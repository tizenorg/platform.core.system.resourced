/*
 * resourced
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * @file proc-main.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <Ecore.h>
#include <Ecore_File.h>
#include <pthread.h>

#include "freezer.h"
#include "notifier.h"
#include "proc-process.h"
#include "proc-main.h"
#include "cgroup.h"
#include "proc-noti.h"
#include "trace.h"
#include "proc-handler.h"
#include "proc-monitor.h"
#include "module.h"
#include "macro.h"
#include "appid-helper.h"
#include "lowmem-handler.h"
#include "procfs.h"
#include "appinfo-list.h"
#include "util.h"

static GHashTable *proc_exclude_list;
static Ecore_File_Monitor *exclude_list_monitor;
static const unsigned int exclude_list_limit = 1024;
static const struct module_ops *freezer;
static GSList *proc_module;  /* proc sub-module list */

#define BASE_UGPATH_PREFIX "/usr/ug/bin"
#define LOG_PREFIX "resourced"
#define TIZEN_SYSTEM_APPID "org.tizen.system"

GSList *proc_app_list;
GSList *proc_program_list;

struct child_pid *new_pid_info(const pid_t pid)
{
	struct child_pid *result = (struct child_pid *)malloc(
			sizeof(struct child_pid));
	if (!result) {
		_E("Malloc of new_pid_info failed\n");
		return NULL;
	}

	result->pid = pid;
	return result;
}

static struct child_pid *find_child_info(pid_list pids, const pid_t pid)
{
	struct child_pid pid_to_find = {
		.pid = pid,
	};
	GSList *found = NULL;

	ret_value_msg_if(!pids, NULL, "Please provide valid pointer.");

	found = g_slist_find_custom((GSList *)pids,
		&pid_to_find, compare_pid);

	if (found)
		return (struct child_pid *)(found->data);
	return NULL;
}

static bool is_ui_app(enum application_type type)
{
	if (type == PROC_TYPE_GUI || type == PROC_TYPE_WIDGET ||
	    type == PROC_TYPE_WATCH)
		return true;
	return false;
}

void proc_add_child_pid(struct proc_app_info *pai, pid_t pid)
{
	struct child_pid pid_to_find = {
		.pid = pid,
	};
	GSList *found = NULL;

	if (pai->childs)
		found = g_slist_find_custom((GSList *)pai->childs,
			&pid_to_find, compare_pid);

	if (found)
		return;

	pai->childs = g_slist_prepend(pai->childs, new_pid_info(pid));
}

void proc_set_process_memory_state(struct proc_app_info *pai,
	int memcg_idx, struct memcg_info *memcg_info, int oom_score_adj)
{
	if (!pai)
		return;

	pai->memory.memcg_idx= memcg_idx;
	pai->memory.memcg_info = memcg_info;
	pai->memory.oom_score_adj = oom_score_adj;
}

/*
 * There can be many processes with same appid at same time.
 * This function returns the most recently used app of all app list.
 */
struct proc_app_info *find_app_info_by_appid(const char *appid)
{
	GSList *iter = NULL;
	struct proc_app_info *pai;

	if (!appid)
		return NULL;

	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		if (equal_name_info(pai->appid, appid))
			return pai;
	}
	return NULL;
}

struct proc_app_info *find_app_info(const pid_t pid)
{
	GSList *iter = NULL;
	struct proc_app_info *pai= NULL;

	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		if ((pai->main_pid == pid) ||
		    (pai->childs && find_child_info(pai->childs, pid)))
			return pai;
	}
	return NULL;
}

struct proc_program_info *find_program_info(const char *pkgname)
{
	GSList *iter = NULL;
	struct proc_program_info *ppi;

	if (!pkgname)
		return NULL;

	gslist_for_each_item(iter, proc_program_list) {
		ppi = (struct proc_program_info *)iter->data;
		if (equal_name_info(ppi->pkgname, pkgname))
			return ppi;
	}
	return NULL;
}

resourced_ret_c proc_set_runtime_exclude_list(const int pid, int type)
{
	struct proc_app_info *pai = NULL;
	struct proc_status ps = {0};

	pai = find_app_info(pid);
	if (!pai)
		return RESOURCED_ERROR_NO_DATA;

	ps.pid = pid;
	ps.pai = pai;
	if (type == PROC_EXCLUDE)
		resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &ps);

	if (pai->runtime_exclude) {
		if (type == PROC_EXCLUDE)
			pai->runtime_exclude++;
		else
			pai->runtime_exclude--;
	} else {
		pai->runtime_exclude = type;
	}
	_D("pid %d set proc exclude list, type = %d, exclude = %d",
		    pid, type, pai->runtime_exclude);

	return RESOURCED_ERROR_NONE;
}

/*
  * find main oom score value from latest launched UI application
  * And set oom score of service app
  */
static void proc_set_default_svc_oomscore
	    (struct proc_program_info *ppi, struct proc_app_info *svc)
{
	struct proc_app_info *pai =
		    (struct proc_app_info *)g_slist_nth_data(ppi->app_list, 0);
	int oom_score_adj = 0, ret ;
	if (pai) {
		if (CHECK_BIT(pai->flags, PROC_VIP_ATTRIBUTE))
			oom_score_adj = OOMADJ_SU;
		else {
			ret = proc_get_oom_score_adj(pai->main_pid, &oom_score_adj);
			if (ret)
				oom_score_adj = 0;
		}
	}
	proc_set_service_oomscore(svc->main_pid, oom_score_adj);
}

struct proc_program_info *proc_add_program_list(const int type,
	    struct proc_app_info *pai, const char *pkgname)
{
	struct proc_program_info *ppi;
	if (!pai || !pkgname)
		return NULL;

	ppi = find_program_info(pkgname);
	if (!ppi) {
		_E("not found ppi : %s", pkgname);
		ppi = calloc(sizeof(struct proc_program_info), 1);
		if (!ppi)
			return NULL;

		if (pai->ai)
			ppi->pkgname = pai->ai->pkgname;
		else {
			ppi->pkgname = strndup(pkgname, strlen(pkgname)+1);
			if (!ppi->pkgname) {
				_E("not enough memory");
				free(ppi);
				return NULL;
			}
		}
		proc_program_list = g_slist_prepend(proc_program_list, ppi);
	}
	if (is_ui_app(type))
		ppi->app_list = g_slist_prepend(ppi->app_list, pai);
	else {
		ppi->svc_list = g_slist_prepend(ppi->svc_list, pai);
		proc_set_default_svc_oomscore(ppi, pai);
	}
	return ppi;
}

struct proc_app_info *proc_add_app_list(const int type, const pid_t pid,
	    const char *appid, const char *pkgname)
{
	struct proc_app_info *pai;

	if (!appid)
		return NULL;

	/*
	 * check lastet item firstly because app list has already created in prelaunch
	 */
	pai = (struct proc_app_info *)g_slist_nth_data(proc_app_list, 0);
	if (!pai || pai->type != PROC_TYPE_READY) {
		_E("not found previous pai : %s", appid);
		pai = proc_create_app_list(appid, pkgname);
		if (!pai) {
			_E("failed to create app list");
			return NULL;
		}
	}

	pai->type = type;
	pai->main_pid = pid;
	pai->program = proc_add_program_list(type, pai, pkgname);
	pai->state = PROC_STATE_FOREGROUND;
	return pai;
}

static void _remove_child_pids(struct proc_app_info *pai, pid_t pid)
{
	GSList *iter, *next;
	struct child_pid *child;

	if (!pai->childs)
		return;

	/*
	 * if pid has a valid value, remove only one child with same pid
	 * otherwise pid is zero, remove all child pids
	 */
	gslist_for_each_safe(pai->childs, iter, next, child) {
		if (pid && pid != child->pid)
			continue;
		pai->childs = g_slist_remove(pai->childs, child);
		free(child);
		if (pid)
			return;
	}
}

int proc_remove_app_list(const pid_t pid)
{
	GSList *iter;
	struct proc_app_info *pai = NULL;
	struct proc_program_info *ppi;
	struct child_pid *found = NULL;

	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		if (!pai->main_pid)
			continue;

		if (pai->main_pid == pid) {
			_remove_child_pids(pai, 0);
			ppi = pai->program;
			if (ppi) {
				if (is_ui_app(pai->type))
					ppi->app_list = g_slist_remove(ppi->app_list, pai);
				else if (pai->type == PROC_TYPE_SERVICE)
					ppi->svc_list = g_slist_remove(ppi->svc_list, pai);
				if (!ppi->app_list && !ppi->svc_list) {
					proc_program_list = g_slist_remove(proc_program_list, ppi);
					resourced_appinfo_put(pai->ai);
					free(ppi);
				}
			}
			proc_app_list = g_slist_remove(proc_app_list, pai);
			free(pai);
			break;
		} else if (pai->childs) {
			found = find_child_info(pai->childs, pid);
			if (!found)
				continue;
			_remove_child_pids(pai, pid);
			break;
		} else
			continue;
	}
	return 0;
}

struct proc_app_info *proc_create_app_list(const char *appid, const char *pkgid)
{
	struct proc_app_info *pai;
	if (!appid)
		return NULL;

	pai = calloc(sizeof(struct proc_app_info), 1);
	if (!pai)
		return NULL;

	pai->ai = resourced_appinfo_get(pai->ai, appid, pkgid);
	if (pai->ai)
		pai->appid = pai->ai->appid;
	else {
		pai->appid = strndup(appid, strlen(appid)+1);
		if (!pai->appid) {
			free(pai);
			_E("not enough memory");
			return NULL;
		}
	}

	pai->proc_exclude = resourced_proc_excluded(appid);
	proc_app_list = g_slist_prepend(proc_app_list, pai);
	return pai;
}

int proc_delete_all_lists(void)
{
	GSList *iter, *next;
	struct proc_app_info *pai = NULL;
	struct proc_program_info *ppi = NULL;

	gslist_for_each_safe(proc_app_list, iter, next, pai) {
		_remove_child_pids(pai, 0);
		ppi = pai->program;
		if (ppi) {
			if (is_ui_app(pai->type))
				ppi->app_list = g_slist_remove(ppi->app_list, pai);
			else if (pai->type == PROC_TYPE_SERVICE)
				ppi->svc_list = g_slist_remove(ppi->svc_list, pai);
		}
		proc_app_list = g_slist_remove(proc_app_list, pai);
		resourced_appinfo_put(pai->ai);
		free(pai);
	}

	gslist_for_each_safe(proc_program_list, iter, next, ppi) {
		proc_program_list = g_slist_remove(proc_program_list, ppi);
		free(ppi);
	}
	return 0;
}

int proc_get_svc_state(struct proc_program_info *ppi)
{
	GSList *iter = NULL;
	int state = PROC_STATE_DEFAULT;

	if (!ppi->app_list)
		return PROC_STATE_DEFAULT;

	gslist_for_each_item(iter, ppi->app_list) {
		struct proc_app_info *pai = (struct proc_app_info *)(iter->data);

		if (pai->lru_state == PROC_FOREGROUND)
			return PROC_STATE_FOREGROUND;

		if (pai->lru_state >= PROC_BACKGROUND)
			state = PROC_STATE_BACKGROUND;
	}
	return state;
}

static void proc_dump_process_list(FILE *fp)
{
	GSList *iter, *iter_child;
	struct proc_app_info *pai = NULL;
	int index = 0, ret, oom_score_adj;

	LOG_DUMP(fp, "[APPLICATION LISTS]\n");
	gslist_for_each_item(iter, proc_app_list) {
		char *typestr;
		unsigned int size;
		unsigned long utime, stime;

		pai = (struct proc_app_info *)iter->data;
		ret = proc_get_oom_score_adj(pai->main_pid, &oom_score_adj);
		if (ret < 0)
			continue;

		if (!pai->ai)
			continue;

		if (is_ui_app(pai->type))
			typestr = "UI APP";
		else if (pai->type == PROC_TYPE_SERVICE)
			typestr = "SVC APP";
		else
			continue;

		LOG_DUMP(fp, "index : %d, type : %s, pkgname : %s, appid : %s\n"
		    "\t lru : %d, proc_exclude : %d, runtime_exclude : %d, flags : %X, "
		    "state : %d\n", index, typestr, pai->ai->pkgname, pai->ai->appid,
		    pai->lru_state, pai->proc_exclude, pai->runtime_exclude,
		    pai->flags, pai->state);

		proc_get_mem_usage(pai->main_pid, NULL, &size);
		proc_get_cpu_time(pai->main_pid, &utime, &stime);
		LOG_DUMP(fp, "\t main pid : %d, oom score : %d, memory rss : %d KB,"
		    "utime : %lu, stime : %lu\n", pai->main_pid, oom_score_adj, size,
		    utime, stime);
		if (pai->childs) {
			struct child_pid *child;
			gslist_for_each_item(iter_child, pai->childs) {
				child = (struct child_pid *)iter_child->data;
				proc_get_mem_usage(child->pid, NULL, &size);
				proc_get_cpu_time(child->pid, &utime, &stime);
				LOG_DUMP(fp, "\t main pid : %d, oom score : %d, "
					"memory rss : %dKB, utime : %lu, stime : %lu\n",
					pai->main_pid, oom_score_adj, size, utime, stime);
			}
		}
		index++;
	}
}

static void proc_free_exclude_key(gpointer data)
{
	if (data)
		free(data);
}

static gboolean find_excluded(gpointer key, gpointer value, gpointer user_data)
{
	if (!user_data || !key)
		return FALSE;

	return (strstr((char *)user_data, (char *)key) ? TRUE : FALSE);
}

int proc_get_id_info(struct proc_status *ps, char **app_name, char **pkg_name)
{
	if (!ps)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	if (!ps->pai || !ps->pai->ai) {
		*app_name = TIZEN_SYSTEM_APPID;
		*pkg_name = TIZEN_SYSTEM_APPID;
	} else {
		*app_name = ps->pai->ai->appid;
		*pkg_name = ps->pai->ai->pkgname;
	}
	return RESOURCED_ERROR_NONE;
}

char *proc_get_appid_from_pid(const pid_t pid)
{
	struct proc_app_info *pai = find_app_info(pid);
	if (!pai)
		return NULL;
	return pai->appid;
}

int resourced_proc_excluded(const char *app_name)
{
	gpointer ret = 0;
	if (proc_exclude_list)
		ret = g_hash_table_find(proc_exclude_list, find_excluded, (gpointer)app_name);
	else
		return RESOURCED_ERROR_NONE;
	return ret ? RESOURCED_ERROR_NONMONITOR : RESOURCED_ERROR_NONE;
}

static void _prepare_appid(char *appid, const int length)
{
	if (!appid || length - 1 <= 0)
		return;
	appid[length - 1] = '\0'; /*remove ending new line*/
}

static void fill_exclude_list_by_path(const char *exclude_file_name,
	GHashTable *list)
{
	char *exclude_app_id = 0;
	int ret;
	unsigned int excluded_count = 0;
	size_t buf_size = 0;
	FILE *exclude_file = NULL;

	if (!list) {
		_D("Please initialize exclude list!");
		return;
	}

	exclude_file = fopen(exclude_file_name, "r");

	if (!exclude_file) {
		_E("Can't open %s.", exclude_file_name);
		return;
	}

	while (excluded_count++ < exclude_list_limit) {
		ret = getline(&exclude_app_id, &buf_size, exclude_file);
		if (ret <= 0)
			break;
		_prepare_appid(exclude_app_id, ret);
		_SD("append %s to proc exclude list", exclude_app_id);

		g_hash_table_insert(list, g_strndup(exclude_app_id, strlen(exclude_app_id)),
			GINT_TO_POINTER(1));
	}

	if (excluded_count >= exclude_list_limit)
		_E("Exclude list is exceed the limit of %u application",
		exclude_list_limit);

	if (exclude_app_id)
		free(exclude_app_id);

	fclose(exclude_file);
}

static void _fill_exclude_list(GHashTable *list)
{
	fill_exclude_list_by_path(EXCLUDE_LIST_FULL_PATH, list);
	fill_exclude_list_by_path(EXCLUDE_LIST_OPT_FULL_PATH, list);
}

static void _exclude_list_change_cb(void *data, Ecore_File_Monitor *em,
	Ecore_File_Event event, const char *path)
{
	_SD("file %s changed, path: %s, event: %d ", EXCLUDE_LIST_OPT_FULL_PATH,
	path, event);

	g_hash_table_remove_all(proc_exclude_list);
	/* reread all */
	_fill_exclude_list(proc_exclude_list);
}

static void _init_exclude_list_noti(void)
{
	if (ecore_file_init() == 0) {
		_E("ecore_file_init() failed");
		return;
	}
	exclude_list_monitor = ecore_file_monitor_add(EXCLUDE_LIST_OPT_FULL_PATH,
		_exclude_list_change_cb,
		NULL);
	if (exclude_list_monitor == NULL)
		_E("Dynamic exclude list not supported. Cannot add notification callback");
}

static void proc_exclude_init(void)
{
	proc_exclude_list = g_hash_table_new_full(
		g_str_hash,
		g_str_equal,
		proc_free_exclude_key,
		NULL);

	if (proc_exclude_list == NULL) {
		_E("Can't initialize exclude_list!");
		return;
	}

	_init_exclude_list_noti();
	_fill_exclude_list(proc_exclude_list);
}

void proc_module_add(const struct proc_module_ops *ops)
{
	proc_module = g_slist_append(proc_module, (gpointer)ops);
}

void proc_module_remove(const struct proc_module_ops *ops)
{
	proc_module = g_slist_remove(proc_module, (gpointer)ops);
}

static void proc_module_init(void *data)
{
	GSList *iter;
	const struct proc_module_ops *module;
	int ret = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, proc_module) {
		module = (struct proc_module_ops *)iter->data;
		_D("Initialize [%s] module\n", module->name);
		if (module->init)
			ret = module->init(data);
		if (ret != RESOURCED_ERROR_NONE)
			_E("Fail to initialize [%s] module\n", module->name);
	}
}

static void proc_module_exit(void *data)
{
	GSList *iter;
	const struct proc_module_ops *module;
	int ret = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, proc_module) {
		module = (struct proc_module_ops *)iter->data;
		_D("Deinitialize [%s] module\n", module->name);
		if (module->exit)
			ret = module->exit(data);
		if (ret != RESOURCED_ERROR_NONE)
			_E("Fail to deinitialize [%s] module\n", module->name);
	}
}

static int resourced_proc_init(void* data)
{
	proc_exclude_init();
	proc_module_init(data);
	return RESOURCED_ERROR_NONE;
}

static int resourced_proc_exit(void* data)
{
	proc_delete_all_lists();
	g_hash_table_destroy(proc_exclude_list);
	ecore_file_monitor_del(exclude_list_monitor);
	proc_module_exit(data);
	return RESOURCED_ERROR_NONE;
}

int proc_get_freezer_status()
{
	int ret = CGROUP_FREEZER_DISABLED;
	struct freezer_status_data f_data;
	if (!freezer) {
		freezer = find_module("freezer");
		if (!freezer)
			return ret;
	}

	f_data.type = GET_STATUS;
	if (freezer->status)
		ret = freezer->status(&f_data);
	return ret;
}

int proc_get_appflag(const pid_t pid)
{
	struct proc_app_info *pai =
		find_app_info(pid);

	if (pai) {
		_D("get apptype = %d", pai->flags);
		return pai->flags;
	} else
		_D("there is no process info for pid = %d", pid);
	return PROC_NONE;
}

void proc_set_group(pid_t onwerpid, pid_t childpid, char *pkgname)
{
	int owner_oom = 0, child_oom = 0, ret;
	int child_type = 0, child_state = 0;
	struct proc_program_info *ppi;
	struct proc_app_info *pai, *owner;
	struct proc_status ps = {0};

	if (onwerpid <= 0 || childpid <=0)
		return;

	ret = proc_get_oom_score_adj(onwerpid, &owner_oom);
	if (ret < 0) {
		_D("owner pid(%d) was already terminated", onwerpid);
		return;
	}

	owner = find_app_info(onwerpid);
	pai = find_app_info(childpid);
	if (!owner)
		return;

	if (pkgname && pai) {
		/*
		 * when child application with appid has owner pai and ppi
		 * check and remove them
		 */
		if (pai->main_pid == childpid) {
			ppi = pai->program;
			if (ppi)
				ppi->app_list = g_slist_remove(ppi->app_list, pai);

			ret = proc_get_oom_score_adj(childpid, &child_oom);
			if(ret < 0) {
				_D("can't get oom score for pid (%d)", childpid);
				child_oom = 0;
			}
			child_type = pai->type;
			child_state = pai->state;
			/*
			 * migrate application categories and activities
			 * from child pai to parent pai
			 */
			if (pai->categories)
				owner->categories += pai->categories;
			if (pai->runtime_exclude)
				owner->runtime_exclude += pai->runtime_exclude;
			proc_app_list = g_slist_remove(proc_app_list, pai);
			free(pai);
		} else {
			_D("main pid(%d) was different from childpid(%d)",
			    pai->main_pid, childpid);
			_remove_child_pids(pai, childpid);
		}
	}
	/*
	 * when some process like webprocess or
	 * UI application that has transparent with owner application
	 * needs to group in owner app
	 * and adds to child lists in the proc app info
	 */
	proc_add_child_pid(owner, childpid);

	/*
	 * When child process was GUI application and it was foreground state
	 * parent application should go to the foreground state also.
	 * Otherwise, child process follows oom and suspend state of parent application
	 */
	if (child_type == PROC_TYPE_GUI &&
	    child_state ==  PROC_STATE_FOREGROUND) {
		owner->lru_state = PROC_FOREGROUND;
		ps.pid = owner->main_pid;
		proc_set_oom_score_adj(owner->main_pid, child_oom);
	} else {
		if (owner_oom <= OOMADJ_BACKGRD_LOCKED) {
			ps.pid = childpid;
			ps.appid = owner->appid;
		}
		proc_set_oom_score_adj(childpid, owner_oom);
	}
	resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &ps);
}

bool proc_check_lru_suspend(int val, int lru)
{
	if (proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
		return false;

	if ((PROC_BACKGROUND + val) == lru)
		return true;
	return false;
}

enum proc_state proc_check_suspend_state(struct proc_app_info *pai)
{
	if (!pai)
		return PROC_STATE_DEFAULT;

	if (pai->type == PROC_TYPE_GUI) {
		/*
		 * check LRU state about UI application
		 * whether it is active state or not
		 */
		if (pai->lru_state < PROC_BACKGROUND)
			return PROC_STATE_DEFAULT;

		/*
		 * if platform has a suspend policy and application has UI,
		 * waits suspend callback or changing LRU.
		 * Otherwise, application goes to suspend state without waiting.
		 */
		if (!(CHECK_BIT(pai->flags, PROC_BGCTRL_PLATFORM)) ||
		    (pai->state == PROC_STATE_SUSPEND_READY))
			return PROC_STATE_SUSPEND;

		pai->state = PROC_STATE_SUSPEND_READY;
		return PROC_STATE_SUSPEND_READY;

	}
	if (pai->type == PROC_TYPE_SERVICE) {
		/*
		 * standalone service goes to suspend state immediately.
		 * if service is connected with UI application,
		 * checks UI state from program list.
		 * if UI has already went to suspend mode,
		 * service goes to suspend state.
		 * Otherwise, service waits until UI app is suspended.
		 */
		struct proc_program_info *ppi = pai->program;
		struct proc_app_info *ui;

		if (!ppi->app_list)
			return PROC_STATE_SUSPEND;

		ui = (struct proc_app_info *)g_slist_nth_data(ppi->app_list, 0);
		if (ui->state == PROC_STATE_SUSPEND)
			return PROC_STATE_SUSPEND;
		pai->state = PROC_STATE_SUSPEND_READY;
		return PROC_STATE_SUSPEND_READY;
	}
	return PROC_STATE_DEFAULT;
}


int resourced_proc_status_change(int status, pid_t pid, char *app_name, char *pkg_name, int apptype)
{
	int ret = 0, oom_score_adj = 0, notitype;
	char pidbuf[MAX_DEC_SIZE(int)];
	struct proc_status ps = {0};
	struct proc_program_info *ppi;

	if (status != PROC_CGROUP_SET_TERMINATED &&
	    status != PROC_CGROUP_SET_NOTI_REQUEST) {
		if (!pid) {
			_E("invalid pid : %d of %s", pid, app_name ? app_name : "noprocess");
			return RESOURCED_ERROR_FAIL;
		}
		ret = proc_get_oom_score_adj(pid, &oom_score_adj);
		if (ret < 0) {
			_E("Empty pid or process not exists. %d", pid);
			return RESOURCED_ERROR_FAIL;
		}
	}

	ps.pid = pid;
	ps.appid = app_name;
	ps.pai = NULL;
	switch (status) {
	case PROC_CGROUP_SET_FOREGRD:
		if (app_name)
			_SD("set foreground: app %s, pid %d", app_name, pid);
		else
			_SD("set foreground: pid %d", pid);

		ps.pai = find_app_info(pid);
		if (apptype == PROC_TYPE_WIDGET || apptype == PROC_TYPE_WATCH) {
			if (!ps.pai)
				proc_add_app_list(apptype, pid, app_name, pkg_name);
			proc_set_oom_score_adj(pid, OOMADJ_FOREGRD_UNLOCKED);
			resourced_notify(RESOURCED_NOTIFIER_WIDGET_FOREGRD, &ps);
			break;
		} else {
			snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
			dbus_proc_handler(PREDEF_FOREGRD, pidbuf);
			ret = proc_set_foregrd(pid, oom_score_adj);
			if (ret != 0)
				return RESOURCED_ERROR_NO_DATA;
			notitype = RESOURCED_NOTIFIER_APP_FOREGRD;
		}
		if (ps.pai) {
			ps.appid = ps.pai->appid;
			resourced_notify(notitype, &ps);
		}

		if (proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			break;

		if (apptype == PROC_TYPE_GUI)
			resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &ps);
		break;
	case PROC_CGROUP_SET_LAUNCH_REQUEST:
		proc_set_oom_score_adj(pid, OOMADJ_INIT);
		if (!app_name) {
			_E("launch request: need app name! pid %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}

		if (pkg_name)
			_SD("launch request: app %s, pkg %s, pid %d", app_name, pkg_name, pid);
		else
			_SD("launch request: app %s, pid %d", app_name, pid);

		ps.pai = proc_add_app_list(apptype, pid, app_name, pkg_name);
		ret = resourced_proc_excluded(app_name);
		if (!ps.pai || ret)
			break;

		if (CHECK_BIT(ps.pai->flags, PROC_VIP_ATTRIBUTE))
			proc_set_oom_score_adj(pid, OOMADJ_SU);

		if (ps.pai->categories)
			proc_set_runtime_exclude_list(pid, PROC_EXCLUDE);
		resourced_notify(RESOURCED_NOTIFIER_APP_LAUNCH, &ps);
		if (proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			break;
		ppi = ps.pai->program;
		if (ppi->svc_list)
			resourced_notify(RESOURCED_NOTIFIER_SERVICE_WAKEUP, &ps);
		break;
	case PROC_CGROUP_SET_SERVICE_REQUEST:
		if (!app_name) {
			_E("service launch request: need app name! pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}
		if (pkg_name)
			_SD("service launch request: app %s, pkg %s, pid %d", app_name, pkg_name, pid);
		else
			_SD("service launch request: app %s, pid %d", app_name, pid);

		ps.pai = proc_add_app_list(PROC_TYPE_SERVICE,
				    pid, app_name, pkg_name);
		if (!ps.pai)
			break;
		if (resourced_proc_excluded(app_name) == RESOURCED_ERROR_NONE)
			resourced_notify(RESOURCED_NOTIFIER_SERVICE_LAUNCH, &ps);
		if (!(CHECK_BIT(ps.pai->flags, PROC_BGCTRL_APP)) ||
		    ps.pai->categories)
			proc_set_runtime_exclude_list(pid, PROC_EXCLUDE);
		break;
	case PROC_CGROUP_SET_RESUME_REQUEST:
		/* init oom_score_value */
		if (!app_name) {
			_E("resume request: need app name! pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}
		_SD("resume request: app %s, pid %d", app_name, pid);

		ps.pai = find_app_info(pid);
		if (!ps.pai && ! resourced_proc_excluded(app_name))
			ps.pai = proc_add_app_list(PROC_TYPE_GUI,
				    pid, app_name, pkg_name);

		if (!ps.pai)
			return RESOURCED_ERROR_NO_DATA;

		ps.pai->lru_state = PROC_ACTIVE;
		if (apptype == PROC_TYPE_GUI && oom_score_adj >= OOMADJ_FAVORITE) {
			resourced_notify(RESOURCED_NOTIFIER_APP_RESUME, &ps);
			proc_set_oom_score_adj(pid, OOMADJ_INIT);
		}
		if (proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			break;
		if (apptype == PROC_TYPE_GUI)
			resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &ps);
		else if (apptype == PROC_TYPE_SERVICE)
			resourced_notify(RESOURCED_NOTIFIER_SERVICE_WAKEUP, &ps);
		break;
	case PROC_CGROUP_SET_TERMINATE_REQUEST:
		if (app_name)
			_SD("terminate request: app %s, pid %d", app_name, pid);
		else
			_SD("terminate request: pid %d", pid);

		ps.pai = find_app_info(pid);
		ps.pid = pid;
		resourced_notify(RESOURCED_NOTIFIER_APP_TERMINATE_START, &ps);
		resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &ps);
		break;
	case PROC_CGROUP_SET_ACTIVE:
		ret = proc_set_active(pid, oom_score_adj);
		if (ret != RESOURCED_ERROR_OK)
			break;

		resourced_notify(RESOURCED_NOTIFIER_APP_ACTIVE, &ps);
		break;
	case PROC_CGROUP_SET_BACKGRD:
		if (app_name)
			_SD("set background: app %s, pid %d", app_name, pid);
		else
			_SD("set background: pid %d", pid);

		if (apptype == PROC_TYPE_WIDGET  || apptype == PROC_TYPE_WATCH) {
			ps.pai = find_app_info(pid);
			if (!ps.pai)
				proc_add_app_list(apptype, pid, app_name, pkg_name);
			proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_PERCEPTIBLE);
			if (apptype == PROC_TYPE_WATCH)
				break;
			resourced_notify(RESOURCED_NOTIFIER_WIDGET_BACKGRD, &ps);
		} else {
			snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
			dbus_proc_handler(PREDEF_BACKGRD, pidbuf);
			ret = proc_set_backgrd(pid, oom_score_adj);
			if (ret != 0)
				break;
			if ((proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			    || resourced_freezer_proc_late_control())
				break;

			ps.pai = find_app_info(pid);
			ps.pid = pid;
			resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &ps);
		}
		break;
	case PROC_CGROUP_SET_INACTIVE:
		ret = proc_set_inactive(pid, oom_score_adj);
		if (ret != RESOURCED_ERROR_OK)
			break;
		resourced_notify(RESOURCED_NOTIFIER_APP_INACTIVE, &ps);
		break;
	case PROC_CGROUP_GET_MEMSWEEP:
		ret = proc_sweep_memory(PROC_SWEEP_EXCLUDE_ACTIVE, pid);
		break;
	case PROC_CGROUP_SET_NOTI_REQUEST:
		if (!app_name || proc_get_freezer_status() == CGROUP_FREEZER_DISABLED)
			break;
		ps.pai = find_app_info_by_appid(app_name);
		if (!ps.pai) {
			_E("set noti request: no entry for %s in app list!", app_name);
			break;
		}
		ps.pid = ps.pai->main_pid;
		resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &ps);
		resourced_notify(RESOURCED_NOTIFIER_APP_ACTIVE, &ps);
		break;
	case PROC_CGROUP_SET_PROC_EXCLUDE_REQUEST:
		proc_set_runtime_exclude_list(pid, PROC_EXCLUDE);
		break;
	case PROC_CGROUP_SET_TERMINATED:
		ps.pai = find_app_info(pid);
		if (ps.pai)
			ps.appid = ps.pai->appid;
		resourced_notify(RESOURCED_NOTIFIER_APP_TERMINATED, &ps);
		proc_remove_app_list(pid);
		break;
	case PROC_CGROUP_SET_SYSTEM_SERVICE:
		if (oom_score_adj < OOMADJ_BACKGRD_PERCEPTIBLE)
			proc_set_oom_score_adj(pid, OOMADJ_BACKGRD_PERCEPTIBLE);
		resourced_notify(RESOURCED_NOTIFIER_SYSTEM_SERVICE, &ps);
		break;
	default:
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
	}
	return ret;
}

int resourced_proc_action(int status, int argnum, char **arg)
{
	pid_t pid;
	char *pidbuf = NULL, *cgroup_name = NULL, *pkg_name = NULL;
	if (argnum < 1) {
		_E("Unsupported number of arguments!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	pidbuf = arg[0];
	pid = (pid_t)atoi(pidbuf);
	if (pid < 0) {
		_E("Invalid pid argument!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	/* Getting appid */
	if (argnum > 1)
		/* It's possible to get appid from arg */
		cgroup_name = arg[1];
	if (argnum == 3)
		pkg_name = arg[2];
	_SD("appid %s, pid %d, status %d\n", cgroup_name, pid, status);
	return resourced_proc_status_change(status, pid, cgroup_name, pkg_name, PROC_TYPE_GUI);
}

int proc_get_state(int type, pid_t pid, char *buf, int len)
{
	int ret = 0;
	switch (type) {
	case PROC_CGROUP_GET_CMDLINE:
		ret = proc_get_raw_cmdline(pid, buf, len);
		break;
	case PROC_CGROUP_GET_PGID_CMDLINE:
		ret = proc_get_raw_cmdline(getpgid(pid), buf, len);
		break;
	case PROC_CGROUP_GET_EXE:
		ret = proc_get_exepath(pid, buf, len);
		break;
	case PROC_CGROUP_GET_STAT:
		ret = proc_get_stat(pid, buf, len);
		break;
	case PROC_CGROUP_GET_STATUS:
		ret = proc_get_status(pid, buf, len);
		break;
	case PROC_CGROUP_GET_OOMSCORE:
		ret = proc_get_oom_score_adj(pid, (int *)buf);
		break;
	default:
		_E("unsupported command %d, pid(%d)", type, pid);
		ret = RESOURCED_ERROR_FAIL;
		break;
	}
	return ret;
}

void resourced_proc_dump(int mode, const char *dirpath)
{
	char buf[MAX_PATH_LENGTH];
	_cleanup_fclose_ FILE *f = NULL;

	if (dirpath) {
		time_t now;
		struct tm cur_tm;

		now = time(NULL);
		if (localtime_r(&now, &cur_tm) == NULL)
			_E("Fail to get localtime");

		snprintf(buf, sizeof(buf), "%s/%s_%.4d%.2d%.2d%.2d%.2d%.2d.log",
		    dirpath, LOG_PREFIX, (1900 + cur_tm.tm_year), 1 + cur_tm.tm_mon,
		    cur_tm.tm_mday, cur_tm.tm_hour, cur_tm.tm_min,
		    cur_tm.tm_sec);
		f = fopen(buf, "w+");
	}
	proc_dump_process_list(f);
	modules_dump((void *)f, mode);
}

static struct module_ops proc_modules_ops = {
	.priority	= MODULE_PRIORITY_EARLY,
	.name		= "PROC",
	.init		= resourced_proc_init,
	.exit		= resourced_proc_exit,
};

MODULE_REGISTER(&proc_modules_ops)

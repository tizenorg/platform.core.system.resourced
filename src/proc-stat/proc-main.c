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

#include "notifier.h"
#include "proc-process.h"
#include "proc-main.h"
#include "cgroup.h"
#include "proc-noti.h"
#include "trace.h"
#include "proc-handler.h"
#include "proc-monitor.h"
#include "proc-usage-stats.h"
#include "module.h"
#include "macro.h"
#include "appid-helper.h"
#include "lowmem-handler.h"

pthread_mutex_t	proc_mutex	= PTHREAD_MUTEX_INITIALIZER;
static GHashTable *proc_exclude_list;
static Ecore_File_Monitor *exclude_list_monitor;
static const unsigned int exclude_list_limit = 1024;
static int proc_notifd;
#define BASE_UGPATH_PREFIX "/usr/ug/bin"
#define LOG_PREFIX "resourced.log"

enum proc_state {
	PROC_STATE_DEFAULT,
	PROC_STATE_FOREGROUND,
	PROC_STATE_BACKGROUND,
};

static char *convert_to_proctype_str(int type)
{
	char *tmp = NULL;
	switch (type) {
	case PROC_TYPE_GUI:
		tmp = "GUI";
		break;
	case PROC_TYPE_SERVICE:
		tmp = "SERVICE";
		break;
	case PROC_TYPE_GROUP:
		tmp = "GROUP";
		break;
	default:
		tmp = "NONE";
		break;
	}
	return tmp;
}

/*
 * @brief pid_info_list is only for pid_info_t
 */
GSList *proc_process_list;

struct pid_info_t *new_pid_info(const pid_t pid, const int type)
{
	struct pid_info_t *result = (struct pid_info_t *)malloc(
			sizeof(struct pid_info_t));
	if (!result) {
		_E("Malloc of new_pid_info failed\n");
		return NULL;
	}

	result->pid = pid;
	result->type = type;
	return result;
}

static gint compare_pid(gconstpointer a, gconstpointer b)
{
	const struct pid_info_t *pida = (struct pid_info_t *)a;
	const struct pid_info_t *pidb = (struct pid_info_t *)b;
	return pida->pid == pidb->pid ? 0 :
		pida->pid > pidb->pid ? 1 : -1;
}

static struct pid_info_t *find_pid_info(pid_info_list pids, const pid_t pid)
{
	struct pid_info_t pid_to_find = {
		.pid = pid,
		/* now it doesn't matter */
		.type = PROC_TYPE_UNKNOWN,
	};
	GSList *found = NULL;

	ret_value_msg_if(!pids, NULL, "Please provide valid pointer.");

	found = g_slist_find_custom((GSList *)pids,
		&pid_to_find, compare_pid);

	if (found)
		return (struct pid_info_t *)(found->data);
	return NULL;
}

void proc_add_pid_list(struct proc_process_info_t *ppi, int pid, enum application_type type)
{
	struct pid_info_t pid_to_find = {
		.pid = pid,
		/* now it doesn't matter */
		.type = PROC_TYPE_UNKNOWN,
	};
	GSList *found = NULL;

	if (ppi->pids)
		found = g_slist_find_custom((GSList *)ppi->pids,
			&pid_to_find, compare_pid);

	if (found)
		return;

	pthread_mutex_lock(&proc_mutex);
	ppi->pids = g_slist_prepend(ppi->pids, new_pid_info(pid, type));
	pthread_mutex_unlock(&proc_mutex);
}

static int equal_process_info(const char *appid_a, const char *appid_b)
{
	return !strcmp(appid_a, appid_b);
}

static resourced_ret_c proc_check_ug(pid_t pid)
{
	char buf[PROC_BUF_MAX];
	char cmdline_buf[PROC_NAME_MAX];
	FILE *fp;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fgets(cmdline_buf, PROC_NAME_MAX-1, fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);
	if (strstr(cmdline_buf, BASE_UGPATH_PREFIX)) {
		_D("pid(%d) is ug process. don't freeze this process", pid);
		return RESOURCED_ERROR_NONFREEZABLE;
	}
	return RESOURCED_ERROR_NONE;
}

void proc_set_process_info_memcg(struct proc_process_info_t *ppi,
	int memcg_idx, struct memcg_info_t *memcg_info)
{
	if (!ppi)
		return;
	ppi->memcg_idx = memcg_idx;
	ppi->memcg_info = memcg_info;
}

struct proc_process_info_t *find_process_info(const char *appid, const pid_t pid, const char *pkgid)
{
	GSList *iter = NULL;
	struct proc_process_info_t *info_t = NULL;

	if (pkgid) {
		gslist_for_each_item(iter, proc_process_list) {
			info_t = (struct proc_process_info_t *)iter->data;
			if (equal_process_info(info_t->pkgname, pkgid))
				return info_t;
		}
		return NULL;
	}

	if (!pid) {
		gslist_for_each_item(iter, proc_process_list) {
			info_t = (struct proc_process_info_t *)iter->data;
			if (equal_process_info(info_t->appid, appid))
				return info_t;
		}
		return NULL;
	}

	gslist_for_each_item(iter, proc_process_list) {
		info_t = (struct proc_process_info_t *)iter->data;
		if (info_t->pids && find_pid_info(info_t->pids, pid))
			return info_t;
	}
	return NULL;
}

resourced_ret_c proc_set_runtime_exclude_list(const int pid, int type)
{
	GSList *iter = NULL;
	struct proc_process_info_t *ppi = NULL;
	struct pid_info_t *found = NULL;

	gslist_for_each_item(iter, proc_process_list) {
		ppi = (struct proc_process_info_t *)iter->data;
		if (!ppi->pids)
			continue;

		found = find_pid_info(ppi->pids, pid);
		if(!found)
			continue;

		if(ppi->runtime_exclude) {
			if (type == PROC_EXCLUDE)
				ppi->runtime_exclude++;
			else
				ppi->runtime_exclude--;
		} else
			ppi->runtime_exclude = type;

		_D("found_pid %d, set proc exclude list, type = %d, exclude = %d",
			    found->pid, type, ppi->runtime_exclude);
		break;
	}
	return RESOURCED_ERROR_NONE;
}

struct proc_process_info_t * proc_add_process_list(const int type, const pid_t pid, const char *appid, const char *pkgid)
{
	struct proc_process_info_t *ppi;
	int owner_oom = 0;

	if (!appid)
		return NULL;

	ppi = find_process_info(appid, pid, pkgid);
	/* do not add if it already in list */
	if (ppi && find_pid_info(ppi->pids, pid))
		return ppi;

	if (!ppi) {
		ppi = malloc(sizeof(struct proc_process_info_t));
		if (!ppi)
			return NULL;

		memset(ppi, 0, sizeof(struct proc_process_info_t));
		strncpy(ppi->appid, appid, MAX_NAME_LENGTH - 1);
		ppi->proc_exclude = resourced_proc_excluded(appid);
		if (pkgid)
			strncpy(ppi->pkgname, pkgid, MAX_NAME_LENGTH - 1);
		else
			extract_pkgname(ppi->appid, ppi->pkgname,
				MAX_NAME_LENGTH);
		pthread_mutex_lock(&proc_mutex);
		proc_process_list = g_slist_prepend(proc_process_list,
			ppi);
		pthread_mutex_unlock(&proc_mutex);
	} else if (type == PROC_TYPE_SERVICE && ppi->main_pid > 0)
		proc_get_oom_score_adj(ppi->main_pid, &owner_oom);

	if (proc_check_ug(pid) == RESOURCED_ERROR_NONFREEZABLE)
		ppi->runtime_exclude = PROC_EXCLUDE;
	if (type == PROC_TYPE_SERVICE)
		proc_set_service_oomscore(pid, owner_oom);

	if (type == PROC_TYPE_GUI) {
		if (ppi->main_pid && pid != ppi->main_pid){
			if (proc_get_oom_score_adj(pid, &owner_oom) < 0) {
				struct pid_info_t *found = NULL;
				found = find_pid_info(ppi->pids, ppi->main_pid);
				if(found) {
					ppi->pids = g_slist_remove(ppi->pids,
						    found);
					free(found);
				}
				ppi->main_pid = pid;
			}
		} else
			ppi->main_pid = pid;
	}
	proc_add_pid_list(ppi, pid, type);
	return ppi;
}

struct proc_process_info_t * proc_create_process_list(const char *appid, const char *pkgid)
{
	struct proc_process_info_t *ppi;

	if (!appid)
		return NULL;

	ppi = find_process_info(appid, 0, pkgid);
	/* do not add if it already in list */
	if (ppi)
		return ppi;

	if (!ppi) {
		ppi = malloc(sizeof(struct proc_process_info_t));
		if (!ppi)
			return NULL;

		memset(ppi, 0, sizeof(struct proc_process_info_t));
		strncpy(ppi->appid, appid, MAX_NAME_LENGTH - 1);
		ppi->proc_exclude = resourced_proc_excluded(appid);
		if (pkgid)
			strncpy(ppi->pkgname, pkgid, MAX_NAME_LENGTH - 1);
		else
			extract_pkgname(ppi->appid, ppi->pkgname,
				MAX_NAME_LENGTH);
		pthread_mutex_lock(&proc_mutex);
		proc_process_list = g_slist_prepend(proc_process_list,
			ppi);
		pthread_mutex_unlock(&proc_mutex);
	}
	return ppi;
}

int proc_remove_process_list(const pid_t pid)
{
	GSList *iter = NULL;
	struct proc_process_info_t *ppi = NULL;
	struct pid_info_t *found = NULL;

	pthread_mutex_lock(&proc_mutex);
	gslist_for_each_item(iter, proc_process_list) {
		ppi = (struct proc_process_info_t *)iter->data;
		if (!ppi->pids)
			continue;

		found = find_pid_info(ppi->pids, pid);
		if(!found)
			continue;

		_D("found_pid %d", found->pid);
		if (ppi->main_pid == pid)
			ppi->main_pid = 0;
		/* Introduce function for removing and cleaning */
		ppi->pids = g_slist_remove(ppi->pids,
			found);
		free(found);
		break;
	}
	pthread_mutex_unlock(&proc_mutex);
	return 0;
}

int proc_delete_process_list(void)
{
	GSList *iter, *next;
	GSList *pid_iter = NULL;
	struct proc_process_info_t *ppi = NULL;

	pthread_mutex_lock(&proc_mutex);
	gslist_for_each_safe(proc_process_list, iter, next, ppi) {
		if (ppi->pids) {
			gslist_for_each_item(pid_iter, ppi->pids) {
				struct pid_info_t *pi = (struct pid_info_t *)(pid_iter->data);
				if (pi) {
					ppi->pids = g_slist_remove(ppi->pids, pi);
					free(pi);
				}
			}
		}
		proc_process_list = g_slist_remove(proc_process_list, ppi);
		free(ppi);
	}
	pthread_mutex_unlock(&proc_mutex);
	return 0;
}

static void proc_dump_process_list(FILE* fp)
{
	GSList *iter = NULL;
	GSList *iter_pid = NULL;
	struct proc_process_info_t *process_info = NULL;
	int index = 0 ;

	LOG_DUMP(fp, "[PROCESS LISTS]\n");
	gslist_for_each_item(iter, proc_process_list) {
		process_info = (struct proc_process_info_t *)iter->data;
		LOG_DUMP(fp, "index : %d, appid : %s, pkgname : %s, main_pid : %d, type : %x\n",
			    index, process_info->appid, process_info->pkgname,
			    process_info->main_pid, process_info->type);
		if (process_info->pids) {
			gslist_for_each_item(iter_pid, process_info->pids) {
				struct pid_info_t *pid_info = (struct pid_info_t *)(iter_pid->data);
				if (pid_info) {
					pid_t pid;
					int oom_score_adj;
					char appname[PROC_NAME_MAX];
					pid = pid_info->pid;
					if (proc_get_oom_score_adj(pid, &oom_score_adj) < 0 ||
						    proc_get_cmdline(pid, appname) < 0) {
						process_info->pids = g_slist_remove(process_info->pids, pid_info);
						free(pid_info);
						continue;
					}
					LOG_DUMP(fp, "\t type : %s, pid : %d, command line : %s, oom_score : %d\n",
					    convert_to_proctype_str(pid_info->type), pid, appname, oom_score_adj);
				}
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
	if(!user_data || !key)
		return FALSE;

	return (strstr((char*)user_data, (char*)key) ? TRUE : FALSE);
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

		g_hash_table_insert(list, g_strdup(exclude_app_id),
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
		_E("Dynamic exclude list is not supported. Can not add "
			"notification callback");
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

int resourced_proc_init(const struct daemon_opts *opts)
{
	int ret;

	proc_notifd = proc_noti_init();

	ret = proc_monitor_init();
	if (ret)
		_E("proc_monitor_init failed : %d", ret);

	ret = proc_usage_stats_init();
	if (ret)
		_E("proc_usage_stats_init failed : %d", ret);

	proc_exclude_init();
	return ret;
}

int resourced_proc_exit(const struct daemon_opts *opts)
{
	proc_delete_process_list();
	if (proc_notifd)
		close(proc_notifd);
	g_hash_table_destroy(proc_exclude_list);
	ecore_file_monitor_del(exclude_list_monitor);
	g_slist_free_full(proc_process_list, free);
	return RESOURCED_ERROR_NONE;
}

void proc_set_apptype(const char *appid, const char *pkgid, int type)
{
	struct proc_process_info_t *ppi =
		proc_create_process_list(appid, pkgid);
	if (ppi)
		ppi->type = type;
}

int proc_get_apptype(const pid_t pid)
{
	struct proc_process_info_t *ppi =
		find_process_info(NULL, pid, NULL);

	if (ppi) {
		_D("get apptype = %d", ppi->type);
		return ppi->type;
	} else
		_D("there is no process info for pid = %d", pid);
	return PROC_NONE;
}

int resourced_proc_status_change(int type, pid_t pid, char* app_name, char* pkg_name)
{
	int ret = 0, oom_score_adj = 0;
	char pidbuf[MAX_DEC_SIZE(int)];
	struct proc_status proc_data = {0};

	if (pid && (proc_get_oom_score_adj(pid, &oom_score_adj) < 0)) {
		proc_remove_process_list(pid);
		_E("Empty pid or process not exists. %d", pid);
		return RESOURCED_ERROR_FAIL;
	}

	if (!pid) {
		_E("invalid pid : %d of %s", pid, app_name ? app_name : "noprocess");
		return RESOURCED_ERROR_FAIL;
	}

	proc_data.pid = pid;
	proc_data.appid = app_name;
	proc_data.ppi = NULL;
	switch (type) {
	case PROC_CGROUP_SET_FOREGRD:
		_SD("set foreground : %d", pid);
		snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
		dbus_proc_handler(PREDEF_FOREGRD, pidbuf);
		ret = proc_set_foregrd(pid, oom_score_adj);
		if (ret != 0)
			return RESOURCED_ERROR_NO_DATA;
		proc_data.ppi = find_process_info(app_name, pid, NULL);
		proc_data.appid = proc_data.ppi->appid;
		resourced_notify(RESOURCED_NOTIFIER_APP_FOREGRD, &proc_data);
		break;
	case PROC_CGROUP_SET_LAUNCH_REQUEST:
		proc_set_oom_score_adj(pid, OOMADJ_INIT);
		if (!app_name) {
			_E("need application name!pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}
		_SD("launch request %s, %d", app_name, pid);
		if (pkg_name)
			_SD("launch request %s with pkgname", pkg_name);
		ret = resourced_proc_excluded(app_name);
		if (!ret)
			proc_data.ppi = proc_add_process_list(PROC_TYPE_GUI, pid, app_name, pkg_name);
		resourced_notify(RESOURCED_NOTIFIER_APP_LAUNCH, &proc_data);
		_E("available memory = %u", get_available());
		break;
	case PROC_CGROUP_SET_SERVICE_REQUEST:
		if (!app_name) {
			_E("need application name!pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}
		_SD("service launch request %s, %d", app_name, pid);
		if (pkg_name)
			_SD("launch request %s with pkgname", pkg_name);
		proc_data.ppi = proc_add_process_list(PROC_TYPE_SERVICE, pid, app_name, pkg_name);
		if (resourced_proc_excluded(app_name) == RESOURCED_ERROR_NONE)
			resourced_notify(RESOURCED_NOTIFIER_SERVICE_LAUNCH, &proc_data);
		break;
	case PROC_CGROUP_SET_RESUME_REQUEST:
		_SD("resume request %d", pid);
		/* init oom_score_value */
		if (!app_name) {
			_E("need application name!pid = %d", pid);
			return RESOURCED_ERROR_NO_DATA;
		}

		proc_data.ppi = proc_add_process_list(PROC_TYPE_GUI, pid, app_name, pkg_name);
		if (oom_score_adj >= OOMADJ_BACKGRD_UNLOCKED) {
			resourced_notify(RESOURCED_NOTIFIER_APP_RESUME, &proc_data);
			proc_set_oom_score_adj(pid, OOMADJ_INIT);
		}
		break;
	case PROC_CGROUP_SET_TERMINATE_REQUEST:
		proc_data.ppi = find_process_info(app_name, pid, NULL);
		resourced_notify(RESOURCED_NOTIFIER_APP_TERMINATE, &proc_data);
		proc_remove_process_list(pid);
		break;
	case PROC_CGROUP_SET_ACTIVE:
		ret = proc_set_active(pid, oom_score_adj);
		if (ret != RESOURCED_ERROR_OK)
			break;
		resourced_notify(RESOURCED_NOTIFIER_APP_ACTIVE, &proc_data);
		proc_set_runtime_exclude_list(pid, PROC_EXCLUDE);
		break;
	case PROC_CGROUP_SET_BACKGRD:
		snprintf(pidbuf, sizeof(pidbuf), "%d", pid);
		dbus_proc_handler(PREDEF_BACKGRD, pidbuf);
		ret = proc_set_backgrd(pid, oom_score_adj);
		if (ret != 0)
			break;
		break;
	case PROC_CGROUP_SET_INACTIVE:
		ret = proc_set_inactive(pid, oom_score_adj);
		if (ret != RESOURCED_ERROR_OK)
			break;
		resourced_notify(RESOURCED_NOTIFIER_APP_INACTIVE, &proc_data);
		break;
	case PROC_CGROUP_GET_MEMSWEEP:
		ret = proc_sweep_memory(PROC_SWEEP_EXCLUDE_ACTIVE, pid);
		break;
	case PROC_CGROUP_SET_NOTI_REQUEST:
		break;
	case PROC_CGROUP_SET_PROC_EXCLUDE_REQUEST:
		proc_set_runtime_exclude_list(pid, PROC_EXCLUDE);
		break;
	default:
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
	}
	return ret;
}

int resourced_proc_action(int type, int argnum, char **arg)
{
	pid_t pid;
	char *pidbuf = NULL, *cgroup_name = NULL, *pkg_name = NULL;
	if (argnum < 1) {
		_E("Unsupported number of arguments!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	pidbuf = arg[0];
	if ((pid = atoi(pidbuf)) < 0) {
		_E("Invalid pid argument!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	/* Getting appid */
	if (argnum > 1)
		/* It's possible to get appid from arg */
		cgroup_name = arg[1];
	if (argnum == 3)
		pkg_name = arg[2];
	_SD("appid %s, pid %d, type %d \n", cgroup_name, pid, type);
	return resourced_proc_status_change(type, pid, cgroup_name, pkg_name);
}

void resourced_proc_dump(int mode, const char *dirpath)
{
	char buf[PROC_BUF_MAX];
	FILE *f = NULL;
	if (dirpath) {
		snprintf(buf, sizeof(buf), "%s/%s", dirpath, LOG_PREFIX);
		f = fopen(buf, "w+");
	}
	proc_dump_process_list(f);
	modules_dump((void*)f, mode);
	if (f)
		fclose(f);
}

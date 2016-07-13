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
 * @file proc-monitor.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <sys/types.h>
#include <unistd.h>
#include <Ecore.h>
#include <E_DBus.h>
#include <sys/mount.h>

#include "proc-main.h"
#include "proc-monitor.h"
#include "resourced.h"
#include "macro.h"
#include "trace.h"
#include "edbus-handler.h"
#include "proc-process.h"
#include "procfs.h"
#include "lowmem-handler.h"
#include "notifier.h"
#include "init.h"
#include "module.h"

#define WATCHDOG_LAUNCHING_PARAM "WatchdogPopupLaunch"
#define WATCHDOG_KEY1			"_SYSPOPUP_CONTENT_"
#define WATCHDOG_KEY2			"_APP_NAME_"
#define WATCHDOG_VALUE_1			"watchdog"

#define TIZEN_DEBUG_MODE_FILE	RD_SYS_ETC"/.debugmode"

#define INIT_PID	1
#define INIT_PROC_VAL	-1

static int proc_watchdog_state;
int current_lcd_state;

static Ecore_Timer *watchdog_check_timer;
#define WATCHDOG_TIMER_INTERVAL		10

static struct proc_watchdog_info {
	pid_t pid;
	int signum;
} proc_watchdog = { -1, -1 };

int proc_debug_enabled(void)
{
	if (access(TIZEN_DEBUG_MODE_FILE, F_OK) == 0)
		return 1;
	else
		return 0;
}

void proc_set_watchdog_state(int state)
{
	proc_watchdog_state = state;
}

static int proc_get_watchdog_state(void)
{
	return proc_watchdog_state;
}

static DBusMessage *edbus_get_meminfo(E_DBus_Object *obj, DBusMessage *msg)
{
	unsigned int mem_total, mem_free, mem_available, cached, used;
	unsigned int swap_total, swap_free, swap;
	DBusMessageIter iter;
	DBusMessage *reply;
	struct meminfo mi;
	int r;
	char error_buf[256];

	reply = dbus_message_new_method_return(msg);

	r = proc_get_meminfo(&mi,
			     MEMINFO_MASK_MEM_TOTAL |
			     MEMINFO_MASK_MEM_FREE |
			     MEMINFO_MASK_MEM_AVAILABLE |
			     MEMINFO_MASK_CACHED |
			     MEMINFO_MASK_SWAP_TOTAL |
			     MEMINFO_MASK_SWAP_FREE);
	if (r < 0) {
		_E("Failed to get meminfo: %s",
				strerror_r(-r, error_buf, sizeof(error_buf)));
		return reply;
	}

	mem_total = mi.value[MEMINFO_ID_MEM_TOTAL];
	mem_free = mi.value[MEMINFO_ID_MEM_FREE];
	mem_available = mi.value[MEMINFO_ID_MEM_AVAILABLE];
	cached = mi.value[MEMINFO_ID_CACHED];
	swap_total = mi.value[MEMINFO_ID_SWAP_TOTAL];
	swap_free = mi.value[MEMINFO_ID_SWAP_FREE];

	used = mem_total - mem_available;
	swap = swap_total - swap_free;

	_D("memory info total = %u, free = %u, cache = %u, used = %u, swap = %u",
		mem_total, mem_free, cached, used, swap);

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &mem_total);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &mem_free);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &cached);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &used);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &swap);

	return reply;
}

static DBusMessage *edbus_reclaim_memory(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusError err;
	DBusMessageIter iter;
	DBusMessage *reply;
	int ret = -1;

	dbus_error_init(&err);
	_D("reclaiming memory!");

	ret = proc_sys_node_trigger(SYS_VM_SHRINK_MEMORY);
	ret = proc_sys_node_trigger(SYS_VM_COMPACT_MEMORY);

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	return reply;
}

static DBusMessage *edbus_pre_poweroff(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int ret = -1;

	_D("pre power off: unmounting cgroup fs");

	proc_sweep_memory(PROC_SWEEP_EXCLUDE_ACTIVE, INIT_PID);
	resourced_notify(RESOURCED_NOTIFIER_POWER_OFF, NULL);
	umount2("/sys/fs/cgroup", MNT_FORCE|MNT_DETACH);

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &ret);
	return reply;
}

static void proc_dbus_active_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret, type;
	char *str;
	pid_t pid;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS, SIGNAL_PROC_ACTIVE);
	if (ret == 0) {
		_D("there is no active signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &str, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	if (!strncmp(str, "active", strlen("active")+1))
		type = PROC_CGROUP_SET_ACTIVE;
	else if (!strncmp(str, "inactive", strlen("inactive")+1))
		type = PROC_CGROUP_SET_INACTIVE;
	else
		return;

	_D("received %s signal for pid %d", str, pid);
	resourced_proc_status_change(type, pid, NULL, NULL, PROC_TYPE_NONE);
}

static DBusMessage *edbus_get_app_cpu(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessageIter iter;
	DBusMessage *reply;
	char *appid;
	unsigned long total, utime, stime;
	struct proc_app_info *pai = NULL;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &appid,
			DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	pai = find_app_info_by_appid(appid);
	if (!pai) {
		_E("There is no appid %s", appid);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	if (proc_get_cpu_time(pai->main_pid, &utime, &stime) != RESOURCED_ERROR_NONE) {
		_E("proc_get_cpu_time = %s (%d)", appid, pai->main_pid);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	_D("cpu usage of %s (%d), utime = %u, stime = %u", appid, pai->main_pid, utime, stime);
	total = utime + stime;
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &total);

	return reply;
}

static DBusMessage *edbus_get_app_memory(E_DBus_Object *obj, DBusMessage *msg)
{
	int ret;
	DBusMessageIter iter;
	DBusMessage *reply;
	char *appid;
	unsigned int rss;
	struct proc_app_info *pai = NULL;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &appid,
		DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	pai = find_app_info_by_appid(appid);
	if (!pai || !pai->main_pid) {
		_E("There is no appid %s", appid);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	if (proc_get_mem_usage(pai->main_pid, NULL, &rss) < 0) {
		_E("lowmem_get_proc_mem_usage failed for appid = %s (%d)",
			appid, pai->main_pid);
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	_D("memory usage of %s (%d), rss = %u", appid, pai->main_pid, rss);
	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &rss);

	return reply;
}

static DBusMessage *edbus_get_memory_list(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessageIter arr;
	DBusMessage *reply;
	GSList *giter;
	char *appid;
	struct proc_app_info *pai;
	unsigned int total = 0, rss;

	reply = dbus_message_new_method_return(msg);
	gslist_for_each_item(giter, proc_app_list) {
		pai = (struct proc_app_info *)giter->data;
		if (!pai->main_pid)
			continue;
		if (proc_get_mem_usage(pai->main_pid, NULL, &rss) < 0)
			continue;
		total += rss;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(su)", &arr);
	gslist_for_each_item(giter, proc_app_list) {
		DBusMessageIter sub;
		pai = (struct proc_app_info *)giter->data;
		if (!pai || !pai->main_pid)
			continue;
		if (proc_get_mem_usage(pai->main_pid, NULL, &rss) < 0)
			continue;

		appid = pai->appid;
		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &appid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &rss);
		dbus_message_iter_close_container(&arr, &sub);
	}
	dbus_message_iter_close_container(&iter, &arr);
	return reply;
}

static DBusMessage *edbus_get_cpu_list(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessageIter arr;
	DBusMessage *reply;
	GSList *giter;
	char *appid;
	struct proc_app_info *pai;
	unsigned long total, utime, stime;

	total = 0;
	reply = dbus_message_new_method_return(msg);
	gslist_for_each_item(giter, proc_app_list) {
		pai = (struct proc_app_info *)giter->data;
		if (!pai->main_pid)
			continue;
		if (proc_get_cpu_time(pai->main_pid, &utime, &stime) != RESOURCED_ERROR_NONE)
			continue;
		total += utime;
		total += stime;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(su)", &arr);
	gslist_for_each_item(giter, proc_app_list) {
		DBusMessageIter sub;
		unsigned long percent;
		pai = (struct proc_app_info *)giter->data;
		if (!pai->main_pid)
			continue;
		if (proc_get_cpu_time(pai->main_pid, &utime, &stime) != RESOURCED_ERROR_NONE)
			continue;
		appid = pai->appid;
		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &appid);
		percent = (!total) ? 0 : ((((utime + stime) * 1000)/total + 5) / 10);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &percent);
		dbus_message_iter_close_container(&arr, &sub);
	}
	dbus_message_iter_close_container(&iter, &arr);
	return reply;
}

static DBusMessage *edbus_get_memory_lists(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessageIter arr;
	DBusMessage *reply;
	GSList *giter;
	char *appid;
	int type, ret;
	struct proc_app_info *pai;
	unsigned int rss;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &type,
			DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(su)", &arr);
	gslist_for_each_item(giter, proc_app_list) {
		DBusMessageIter sub;
		pai = (struct proc_app_info *)giter->data;
		if (!pai || !pai->main_pid)
			continue;
		if (type != PROC_TYPE_MAX && pai->type != type)
			continue;
		if (proc_get_mem_usage(pai->main_pid, NULL, &rss) < 0)
			continue;

		appid = pai->appid;
		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &appid);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &rss);
		dbus_message_iter_close_container(&arr, &sub);
	}
	dbus_message_iter_close_container(&iter, &arr);
	return reply;
}

static DBusMessage *edbus_get_cpu_lists(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessageIter arr;
	DBusMessage *reply;
	GSList *giter;
	int ret, type;
	char *appid;
	struct proc_app_info *pai;
	unsigned long total, utime, stime;

	total = 0;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &type,
			DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		reply = dbus_message_new_method_return(msg);
		return reply;
	}

	reply = dbus_message_new_method_return(msg);
	gslist_for_each_item(giter, proc_app_list) {
		pai = (struct proc_app_info *)giter->data;
		if (!pai->main_pid)
			continue;
		if (type != PROC_TYPE_MAX && pai->type != type)
			continue;
		if (proc_get_cpu_time(pai->main_pid, &utime, &stime) != RESOURCED_ERROR_NONE)
			continue;
		total += utime;
		total += stime;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(su)", &arr);
	gslist_for_each_item(giter, proc_app_list) {
		DBusMessageIter sub;
		unsigned long percent;
		pai = (struct proc_app_info *)giter->data;
		if (!pai->main_pid)
			continue;
		if (type != PROC_TYPE_MAX && pai->type != type)
			continue;
		if (proc_get_cpu_time(pai->main_pid, &utime, &stime) != RESOURCED_ERROR_NONE)
			continue;
		appid = pai->appid;
		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &appid);
		if (total == 0)
			percent = 0;
		else
			percent = (((utime + stime) * 1000)/total + 5) / 10;
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_UINT32, &percent);
		dbus_message_iter_close_container(&arr, &sub);
	}
	dbus_message_iter_close_container(&iter, &arr);
	return reply;
}

static void proc_dbus_exclude_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	char *str;
	pid_t pid;
	struct proc_exclude pe;
	int len;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS, SIGNAL_PROC_EXCLUDE);
	if (ret == 0) {
		_D("there is no active signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &str, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}


	/*
	 * allowed strings: wakeup, exclude, include
	 */
	len = strlen(str);

	_D("%s signal on pid = %d", str, pid);
	if (len == 6 && !strncmp(str, "wa", 2)) {
		struct proc_status ps = {0};

		ps.pai = find_app_info(pid);
		ps.pid = pid;
		resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &ps);
	} else if (len == 7) {
		if (!strncmp(str, "ex", 2)) {
			pe.pid = pid;
			pe.type = PROC_EXCLUDE;
			resourced_notify(RESOURCED_NOTIFIER_CONTROL_EXCLUDE, &pe);
			proc_set_runtime_exclude_list(pe.pid, pe.type);
		} else if (!strncmp(str, "in", 2)) {
			pe.pid = pid;
			pe.type = PROC_INCLUDE;
			resourced_notify(RESOURCED_NOTIFIER_CONTROL_EXCLUDE, &pe);
			proc_set_runtime_exclude_list(pe.pid, pe.type);
		}
	} else
		return;
}

static void proc_dbus_exclude_appid_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	char *str;
	char *appid;
	struct proc_exclude pe;
	int len;
	struct proc_status ps = {0};

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS,
	    SIGNAL_PROC_EXCLUDEAPPID);
	if (ret == 0) {
		_D("there is no active signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &str,
	    DBUS_TYPE_STRING, &appid, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	if (!appid)
		return;

	ps.pai = find_app_info_by_appid(appid);
	if (!ps.pai) {
		_E("no entry of %s in app list", appid);
		return;
	}
	ps.pid = ps.pai->main_pid;

	/*
	 * allowed strings: wakeup, exclude, include
	 */
	len = strlen(str);

	_D("%s signal on app = %s", str, appid);
	if (len == 6 && !strncmp(str, "wa", 2)) {
		resourced_notify(RESOURCED_NOTIFIER_APP_WAKEUP, &ps);
	} else if (len == 7) {
		if (!strncmp(str, "ex", 2)) {
			pe.pid = ps.pid;
			pe.type = PROC_EXCLUDE;
			resourced_notify(RESOURCED_NOTIFIER_CONTROL_EXCLUDE, &pe);
			proc_set_runtime_exclude_list(pe.pid, pe.type);
		} else if (!strncmp(str, "in", 2)) {
			pe.pid = ps.pid;
			pe.type = PROC_INCLUDE;
			resourced_notify(RESOURCED_NOTIFIER_CONTROL_EXCLUDE, &pe);
			proc_set_runtime_exclude_list(pe.pid, pe.type);
		}
	} else
		return;
}


static void proc_dbus_prelaunch_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	char *appid;
	char *pkgid;
	int flags, categories;
	struct proc_status ps;
	struct proc_app_info *pai;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS,
		SIGNAL_PROC_PRELAUNCH);
	if (ret == 0) {
		_D("there is no prelaunch signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err,
		DBUS_TYPE_STRING, &appid,
		DBUS_TYPE_STRING, &pkgid,
		DBUS_TYPE_INT32, &flags,
		DBUS_TYPE_INT32, &categories, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	pai = proc_create_app_list(appid, pkgid);
	if (!pai) {
		_E("prelaunch: failed to create app info for app %s, pkg %s",
				appid, pkgid);
		return;
	}

	_D("prelaunch signal: app %s, pkg %s, flags %d, categories %X\n",
			appid, pkgid, flags, categories);
	pai->flags = flags;
	pai->type = PROC_TYPE_READY;
	pai->categories = categories;
	ps.appid = appid;
	ps.pai = pai;
	resourced_notify(RESOURCED_NOTIFIER_APP_PRELAUNCH, &ps);
	lowmem_proactive_oom_killer(flags, appid);
}

static void proc_dbus_sweep_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS,
		SIGNAL_PROC_SWEEP);

	if (ret == 0) {
		_D("there is no sweep signal");
		return;
	}

	dbus_error_init(&err);
	proc_sweep_memory(PROC_SWEEP_INCLUDE_ACTIVE, INIT_PID);
}

static Eina_Bool check_watchdog_cb(void *data)
{
	int oom_score_adj = 0, ret;
	pid_t pid = proc_watchdog.pid;

	ret = proc_get_oom_score_adj(pid, &oom_score_adj);
	if (!ret) {
		_E("watchdog pid %d not terminated, kill again\n", pid);
		kill(pid, SIGKILL);
	}
	ecore_timer_del(watchdog_check_timer);
	watchdog_check_timer = NULL;
	proc_watchdog.pid = -1;
	proc_watchdog.signum = -1;
	return ECORE_CALLBACK_CANCEL;
}

static void proc_dbus_watchdog_result(void *data, DBusMessage *msg)
{
	DBusError err;
	int type;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS, SIGNAL_PROC_WATCHDOG_RESULT) == 0) {
		_D("there is no watchdog result signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	if (type == 1) {
		if (proc_watchdog.signum == SIGTERM || proc_watchdog.signum == SIGKILL) {
			resourced_proc_status_change(PROC_CGROUP_SET_TERMINATE_REQUEST,
				    proc_watchdog.pid, NULL, NULL, PROC_TYPE_NONE);
			kill(proc_watchdog.pid, SIGABRT);
			if (watchdog_check_timer == NULL) {
				watchdog_check_timer =
					ecore_timer_add(WATCHDOG_TIMER_INTERVAL, check_watchdog_cb, (void *)NULL);
			}
		} else {
			_E("ERROR: Unsupported signal type!");
		}
	}
	proc_watchdog.pid = -1;
	proc_watchdog.signum = -1;
}

static int proc_dbus_show_popup(const char *value)
{
	DBusError err;
	DBusMessage *msg;
	char str_val[32];
	char *pa[4];
	int i, ret, ret_val;

	snprintf(str_val, sizeof(str_val), "%s", value);

	pa[0] = WATCHDOG_KEY1;
	pa[1] = WATCHDOG_VALUE_1;
	pa[2] = WATCHDOG_KEY2;
	pa[3] = str_val;
	i = 0;

	do {
		msg = dbus_method_sync(SYSTEM_POPUP_BUS_NAME, SYSTEM_POPUP_PATH_SYSTEM,
		    SYSTEM_POPUP_IFACE_SYSTEM, WATCHDOG_LAUNCHING_PARAM, "ssss", pa);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return -EBADMSG;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &ret_val, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("no message : [%s:%s]\n", err.name, err.message);
		ret_val = -EBADMSG;
	}

	dbus_message_unref(msg);
	dbus_error_free(&err);

	return ret_val;
}

static void proc_dbus_watchdog_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int pid, command, ret;
	char appname[PROC_NAME_MAX];
	struct proc_status ps;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS, SIGNAL_PROC_WATCHDOG) == 0) {
		_D("there is no watchdog result signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INT32,
		&command, DBUS_TYPE_INVALID);

	if (ret == 0) {
		_D("there is no message");
		return;
	}

	ret = proc_get_cmdline(pid, appname);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("ERROR : invalid pid(%d)", pid);
		return;
	}

	ret = resourced_proc_excluded(appname);
	if (ret == RESOURCED_ERROR_NONMONITOR)
		return;

	if (current_lcd_state == LCD_STATE_OFF) {
		_E("Receive watchdog signal to pid: %d(%s) but don't show ANR popup in LCD off state\n", pid, appname);
		return;
	}

	_E("Receive watchdog signal to app %s, pid %d\n", appname, pid);
	ps.pai = find_app_info(pid);
	ps.pid = pid;
	resourced_notify(RESOURCED_NOTIFIER_APP_ANR, &ps);

	if (watchdog_check_timer) {
		if (proc_watchdog.pid == pid) {
			_E("app %s, pid %d has already received watchdog siganl but not terminated", appname, pid);
			kill(pid, SIGKILL);
			proc_watchdog.pid = -1;
			proc_watchdog.signum = -1;
			return;
		}
	}

	resourced_proc_status_change(PROC_CGROUP_SET_TERMINATE_REQUEST,
		    pid, NULL, NULL, PROC_TYPE_NONE);
	kill(pid, SIGABRT);
	if (watchdog_check_timer == NULL) {
		watchdog_check_timer =
			ecore_timer_add(WATCHDOG_TIMER_INTERVAL,
			    check_watchdog_cb, (void *)NULL);
		proc_watchdog.pid = pid;
		proc_watchdog.signum = command;
	}
}

static void send_dump_signal(char *signal)
{
	pid_t pid = getpid();

	broadcast_edbus_signal(DUMP_SERVICE_OBJECT_PATH,
	    DUMP_SERVICE_INTERFACE_NAME, signal, DBUS_TYPE_INT32, &pid);
}

static void proc_dbus_dump_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_bool_t ret;
	char *path;
	int mode;

	if (dbus_message_is_signal(msg, DUMP_SERVICE_INTERFACE_NAME, SIGNAL_DUMP) == 0) {
		_D("there is no process group signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &mode,
		    DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID);
	if (ret == 0) {
		_D("there is no message");
		return;
	}
	_D("received dump request: path %s", path);
	send_dump_signal(SIGNAL_DUMP_START);
	resourced_proc_dump(mode, path);
	send_dump_signal(SIGNAL_DUMP_FINISH);
}

static void proc_dbus_systemservice_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_bool_t ret;
	pid_t pid;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_PROCESS, SIGNAL_PROC_SYSTEMSERVICE) == 0) {
		_D("there is no process group signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid,
		    DBUS_TYPE_INVALID);
	if (ret == 0) {
		_D("there is no message");
		return;
	}
	resourced_proc_status_change(PROC_CGROUP_SET_SYSTEM_SERVICE, pid,
		    NULL, NULL, PROC_TYPE_NONE);
}

static DBusMessage *edbus_signal_trigger(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	dbus_bool_t ret;
	int pid, command, ret_val;
	char appname[PROC_NAME_MAX];

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INT32,
		&command, DBUS_TYPE_INVALID);

	if (ret == TRUE) {
		ret_val = proc_get_cmdline(pid, appname);
		if (ret_val != RESOURCED_ERROR_NONE) {
			_E("ERROR : invalid pid(%d)", pid);
		} else {
			_E("Receive watchdog signal to pid: %d(%s)\n", pid, appname);
			if (proc_get_watchdog_state() == PROC_WATCHDOG_ENABLE  &&  proc_watchdog.pid == -1) {
				ret_val = resourced_proc_excluded(appname);
				if (ret_val == RESOURCED_ERROR_NONE) {
					ret_val = proc_dbus_show_popup(appname);
					if (ret_val < 0)
						_E("ERROR : request_to_launch_by_dbus()failed : %d", ret_val);
					else {
						proc_watchdog.pid = pid;
						proc_watchdog.signum = command;
					}
				}
			}
		}
	} else {
		_E("ERROR: Wrong message arguments!");
	}

	reply = dbus_message_new_method_return(msg);
	return reply;
}

static void proc_dbus_lcd_on(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);

	if (dbus_message_is_signal(msg, DEVICED_INTERFACE_DISPLAY,
		    SIGNAL_DEVICED_LCDON) == 0) {
		_D("there is no lcd on signal");
		return;
	}
	dbus_error_free(&err);
	current_lcd_state = LCD_STATE_ON;
	resourced_notify(RESOURCED_NOTIFIER_LCD_ON, NULL);
	/* nothing */
}

static void proc_dbus_lcd_off(void *data, DBusMessage *msg)
{
	DBusError err;

	dbus_error_init(&err);
	if (dbus_message_is_signal(msg, DEVICED_INTERFACE_DISPLAY,
		    SIGNAL_DEVICED_LCDOFF) == 0) {
		_D("there is no lcd on signal");
		return;
	}

	dbus_error_free(&err);
	current_lcd_state = LCD_STATE_OFF;
	resourced_notify(RESOURCED_NOTIFIER_LCD_OFF, NULL);
}

static void booting_done_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;

	dbus_error_init(&err);
	if (dbus_message_is_signal(msg, DEVICED_INTERFACE_CORE,
		    SIGNAL_DEVICED_BOOTINGDONE) == 0) {
		_D("there is no lcd on signal");
		return;
	}
	/*
	 * initialize all modules again
	 * If some modules weren't initialized at this time,
	 * it could get a change again for initializing.
	 * Because modules_init checked whether it was already intialized,
	 * it didn't initialize modules twice.
	 */
	_I("launching all modules (booting done)");
	modules_init(NULL);
	resourced_notify(RESOURCED_NOTIFIER_BOOTING_DONE, NULL);
}

static void early_booting_done_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;

	dbus_error_init(&err);
	if (dbus_message_is_signal(msg, DEVICED_INTERFACE_CORE,
		    SIGNAL_DEVICED_EARLY_BOOTING_DONE) == 0) {
		_D("there is no lcd on signal");
		return;
	}

	_I("launching remaining modules (booting done)");
	modules_late_init(NULL);
}

static void low_battery_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;

	dbus_error_init(&err);
	if (dbus_message_is_signal(msg, DEVICED_INTERFACE_BATTERY,
		    SIGNAL_DEVICED_LOW_BATTERY) == 0) {
		_D("there is no low battery signal");
		return;
	}

	resourced_notify(RESOURCED_NOTIFIER_LOW_BATTERY, NULL);
}

static void poweroff_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;

	dbus_error_init(&err);
	if (dbus_message_is_signal(msg, DEVICED_INTERFACE_POWEROFF,
		    SIGNAL_DEVICED_POWEROFF_STATE) == 0) {
		_D("there is no power off signal");
		return;
	}

	_E("quit mainloop at poweroff");
	resourced_quit_mainloop();
}

static void systemtime_changed_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;

	dbus_error_init(&err);
	if (dbus_message_is_signal(msg, DEVICED_INTERFACE_TIME,
		    SIGNAL_DEVICED_SYSTEMTIME_CHANGED) == 0) {
		_D("there is no system time changed signal");
		return;
	}

	resourced_notify(RESOURCED_NOTIFIER_SYSTEMTIME_CHANGED, NULL);
}

static void proc_dbus_aul_launch(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);
	pid_t pid;
	int status, apptype;
	char *appid, *pkgid, *pkgtype;

	if (dbus_message_is_signal(msg, AUL_APPSTATUS_INTERFACE_NAME,
		    SIGNAL_AMD_LAUNCH) == 0) {
		_D("there is no aul launch signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid,
		    DBUS_TYPE_STRING, &appid, DBUS_TYPE_STRING, &pkgid,
		    DBUS_TYPE_STRING, &pkgtype, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);

#ifdef PROC_DEBUG
	_D("aul_launch: app %s, pkgd %s, pid %d, pkgtype %s",
			appid, pkgid, pid, pkgtype);
#endif

	if (!strncmp(pkgtype, "svc", 3)) {
		apptype = PROC_TYPE_SERVICE;
		status = PROC_CGROUP_SET_SERVICE_REQUEST;
	} else if (!strncmp(pkgtype, "ui", 2)) {
		apptype = PROC_TYPE_GUI;
		status = PROC_CGROUP_SET_LAUNCH_REQUEST;
	} else if (!strncmp(pkgtype, "widget", 6)) {
		apptype = PROC_TYPE_WIDGET;
		status = PROC_CGROUP_SET_LAUNCH_REQUEST;
	} else if (!strncmp(pkgtype, "watch", 5)) {
		apptype = PROC_TYPE_WATCH;
		status = PROC_CGROUP_SET_LAUNCH_REQUEST;
	} else
		return;

	resourced_proc_status_change(status, pid, appid, pkgid, apptype);
}

static void proc_dbus_aul_resume(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);
	pid_t pid;
	int status = PROC_CGROUP_SET_RESUME_REQUEST, apptype;
	char *appid, *pkgid, *pkgtype;

	if (dbus_message_is_signal(msg, AUL_APPSTATUS_INTERFACE_NAME,
		    SIGNAL_AMD_RESUME) == 0) {
		_D("there is no aul resume signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid,
		    DBUS_TYPE_STRING, &appid, DBUS_TYPE_STRING, &pkgid,
		    DBUS_TYPE_STRING, &pkgtype, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);

	if (!strncmp(pkgtype, "svc", 3))
		apptype = PROC_TYPE_SERVICE;
	else if (!strncmp(pkgtype, "widget", 6))
		apptype = PROC_TYPE_WIDGET;
	else if (!strncmp(pkgtype, "watch", 5))
		apptype = PROC_TYPE_WATCH;
	else
		apptype = PROC_TYPE_GUI;

	resourced_proc_status_change(status, pid, appid, pkgid, apptype);
}

static void proc_dbus_aul_terminate(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);
	pid_t pid;
	int status = PROC_CGROUP_SET_TERMINATE_REQUEST;
	char *appid, *pkgid, *pkgtype;

	if (dbus_message_is_signal(msg, AUL_APPSTATUS_INTERFACE_NAME,
		    SIGNAL_AMD_TERMINATE) == 0) {
		_D("there is no aul terminate signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid,
		    DBUS_TYPE_STRING, &appid, DBUS_TYPE_STRING, &pkgid,
		    DBUS_TYPE_STRING, &pkgtype, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);

	resourced_proc_status_change(status, pid, appid, pkgid, PROC_TYPE_NONE);
}

static void proc_dbus_aul_changestate(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);
	pid_t pid;
	int status, apptype;
	char *appid, *pkgid, *statstr, *pkgtype;

	if (dbus_message_is_signal(msg, AUL_APPSTATUS_INTERFACE_NAME,
		    SIGNAL_AMD_STATE) == 0) {
		_D("there is no aul changestate signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid,
		    DBUS_TYPE_STRING, &appid, DBUS_TYPE_STRING, &pkgid,
		    DBUS_TYPE_STRING, &statstr, DBUS_TYPE_STRING, &pkgtype,
		    DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);

	if (!strncmp(statstr, "fg", 2))
		status = PROC_CGROUP_SET_FOREGRD;
	else if (!strncmp(statstr, "bg", 2))
		status = PROC_CGROUP_SET_BACKGRD;
	else
		return;

	if (!strncmp(pkgtype, "svc", 3))
		apptype = PROC_TYPE_SERVICE;
	else if (!strncmp(pkgtype, "widget", 6))
		apptype = PROC_TYPE_WIDGET;
	else if (!strncmp(pkgtype, "watch", 5))
		apptype = PROC_TYPE_WATCH;
	else
		apptype = PROC_TYPE_GUI;

	resourced_proc_status_change(status, pid, appid, pkgid, apptype);
}

static void proc_dbus_aul_group(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);
	pid_t ownerpid, childpid;
	char *appid;

	if (dbus_message_is_signal(msg, AUL_APPSTATUS_INTERFACE_NAME,
		    SIGNAL_AMD_GROUP) == 0) {
		_D("there is no aul group signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &ownerpid,
		    DBUS_TYPE_INT32, &childpid, DBUS_TYPE_STRING, &appid,
		    DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);

	_D("received process grouping : owner %d, child %d, previous appid %s",
		    ownerpid, childpid, appid);
	proc_set_group(ownerpid, childpid, appid);
}

static void proc_dbus_aul_terminated(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);
	pid_t pid;
	int status = PROC_CGROUP_SET_TERMINATED;

	if (dbus_message_is_signal(msg, AUL_APPSTATUS_INTERFACE_NAME,
		    SIGNAL_AMD_TERMINATED) == 0) {
		_D("there is no aul terminate signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid,
		    DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);

	resourced_proc_status_change(status, pid, NULL, NULL, PROC_TYPE_NONE);
}

static void proc_dbus_suspend_hint(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);
	pid_t pid;
	struct proc_app_info *pai = NULL;
	struct proc_status ps = {0};
	enum proc_state state;

	if (dbus_message_is_signal(msg, AUL_SUSPEND_INTERFACE_NAME,
		    SIGNAL_AMD_SUSPNED) == 0) {
		_D("there is no aul terminate signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid,
		    DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);

	pai = find_app_info(pid);
	if (!pai)
		return;

	if (pai->appid)
		_D("received suspend hint : app %s, pid %d",
				pai->appid, pid);
	else
		_D("received suspend hint : pid %d", pid);

	state = proc_check_suspend_state(pai);
	if (state == PROC_STATE_SUSPEND) {
		ps.pid = pid;
		ps.pai = pai;
		resourced_notify(RESOURCED_NOTIFIER_APP_SUSPEND,
			    &ps);
	}
}

static const struct edbus_method edbus_methods[] = {
	{ "Signal", "ii", NULL, edbus_signal_trigger },
	{ "GetAppCpu", "s", "u", edbus_get_app_cpu },
	{ "GetCpuList", NULL, "a(su)", edbus_get_cpu_list },
	{ "GetCpuLists", "i", "a(su)", edbus_get_cpu_lists },
	{ "GetAppMemory", "s", "u", edbus_get_app_memory },
	{ "GetMemoryList", NULL, "a(su)", edbus_get_memory_list },
	{ "GetMemoryLists", "i", "a(su)", edbus_get_memory_lists },
	{ "GetMemInfo", NULL, "uuuuu", edbus_get_meminfo },
	{ "ReclaimMemory", NULL, NULL, edbus_reclaim_memory },
	{ "PrePoweroff", NULL, NULL, edbus_pre_poweroff },
	/* Add methods here */
};

static const struct edbus_signal edbus_signals[] = {
	/* RESOURCED DBUS */
	{RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
	    SIGNAL_PROC_WATCHDOG_RESULT, proc_dbus_watchdog_result, NULL},
	{RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
	    SIGNAL_PROC_ACTIVE, proc_dbus_active_signal_handler, NULL},
	{RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
	    SIGNAL_PROC_EXCLUDE, proc_dbus_exclude_signal_handler, NULL},
	{RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
	    SIGNAL_PROC_PRELAUNCH, proc_dbus_prelaunch_signal_handler, NULL},
	{RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
	    SIGNAL_PROC_SWEEP, proc_dbus_sweep_signal_handler, NULL},
	{RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
	    SIGNAL_PROC_WATCHDOG, proc_dbus_watchdog_handler, NULL},
	{RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
	    SIGNAL_PROC_SYSTEMSERVICE, proc_dbus_systemservice_handler, NULL},
	{RESOURCED_PATH_PROCESS, RESOURCED_INTERFACE_PROCESS,
	    SIGNAL_PROC_EXCLUDEAPPID, proc_dbus_exclude_appid_signal_handler, NULL},

	/* DEVICED DBUS */
	{DEVICED_PATH_DISPLAY, DEVICED_INTERFACE_DISPLAY,
	    SIGNAL_DEVICED_LCDON, proc_dbus_lcd_on, NULL},
	{DEVICED_PATH_DISPLAY, DEVICED_INTERFACE_DISPLAY,
	    SIGNAL_DEVICED_LCDOFF, proc_dbus_lcd_off, NULL},
	{DEVICED_PATH_CORE, DEVICED_INTERFACE_CORE,
	    SIGNAL_DEVICED_BOOTINGDONE, booting_done_signal_handler, NULL},
	{DEVICED_PATH_POWEROFF, DEVICED_INTERFACE_POWEROFF,
	    SIGNAL_DEVICED_POWEROFF_STATE, poweroff_signal_handler, NULL},
	{DEVICED_PATH_BATTERY, DEVICED_INTERFACE_BATTERY,
	    SIGNAL_DEVICED_LOW_BATTERY, low_battery_signal_handler, NULL},
	{DUMP_SERVICE_OBJECT_PATH, DUMP_SERVICE_INTERFACE_NAME,
	    SIGNAL_DUMP, proc_dbus_dump_handler, NULL},
	{DEVICED_PATH_CORE, DEVICED_INTERFACE_CORE,
	    SIGNAL_DEVICED_EARLY_BOOTING_DONE,
	    early_booting_done_signal_handler, NULL},
	{DEVICED_PATH_TIME, DEVICED_INTERFACE_TIME,
	    SIGNAL_DEVICED_SYSTEMTIME_CHANGED,
	    systemtime_changed_signal_handler, NULL},

	/* AMD DBUS */
	{AUL_APPSTATUS_OBJECT_PATH, AUL_APPSTATUS_INTERFACE_NAME,
	    SIGNAL_AMD_LAUNCH, proc_dbus_aul_launch, NULL},
	{AUL_APPSTATUS_OBJECT_PATH, AUL_APPSTATUS_INTERFACE_NAME,
	    SIGNAL_AMD_RESUME, proc_dbus_aul_resume, NULL},
	{AUL_APPSTATUS_OBJECT_PATH, AUL_APPSTATUS_INTERFACE_NAME,
	    SIGNAL_AMD_TERMINATE, proc_dbus_aul_terminate, NULL},
	{AUL_APPSTATUS_OBJECT_PATH, AUL_APPSTATUS_INTERFACE_NAME,
	    SIGNAL_AMD_STATE, proc_dbus_aul_changestate, NULL},
	{AUL_APPSTATUS_OBJECT_PATH, AUL_APPSTATUS_INTERFACE_NAME,
	    SIGNAL_AMD_GROUP, proc_dbus_aul_group, NULL},
	{AUL_APPSTATUS_OBJECT_PATH, AUL_APPSTATUS_INTERFACE_NAME,
	    SIGNAL_AMD_TERMINATED, proc_dbus_aul_terminated, NULL},
	{AUL_SUSPEND_OBJECT_PATH, AUL_SUSPEND_INTERFACE_NAME,
	    SIGNAL_AMD_SUSPNED, proc_dbus_suspend_hint, NULL},
};

static int proc_dbus_init(void *data)
{
	edbus_add_signals(edbus_signals, ARRAY_SIZE(edbus_signals));

	/* start watchdog check timer for preveting ANR during booting */
	watchdog_check_timer =
		ecore_timer_add(WATCHDOG_TIMER_INTERVAL, check_watchdog_cb, (void *)NULL);

	return edbus_add_methods(RESOURCED_PATH_PROCESS, edbus_methods,
			  ARRAY_SIZE(edbus_methods));
}

static int proc_dbus_exit(void *data)
{
	if (watchdog_check_timer)
		ecore_timer_del(watchdog_check_timer);
	return RESOURCED_ERROR_NONE;
}

static const struct proc_module_ops proc_dbus_ops = {
	.name		= "PROC_DBUS",
	.init		= proc_dbus_init,
	.exit		= proc_dbus_exit,
};
PROC_MODULE_REGISTER(&proc_dbus_ops)

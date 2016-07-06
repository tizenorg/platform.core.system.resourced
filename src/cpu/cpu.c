/*
 * resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 */

/**
 * @file cpu.c
 *
 * @desc cpu module
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include "notifier.h"
#include "procfs.h"
#include "proc-common.h"
#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "resourced.h"
#include "trace.h"
#include "vconf.h"
#include "cgroup.h"
#include "config-parser.h"
#include "const.h"
#include "file-helper.h"

#define CPU_DEFAULT_CGROUP "/sys/fs/cgroup/cpu"
#define CPU_BACKGROUND_GROUP CPU_DEFAULT_CGROUP"/background"
#define CPU_CPUQUOTA_GROUP CPU_DEFAULT_CGROUP"/quota"
#define CPU_CONTROL_BANDWIDTH	"/cpu.cfs_quota_us"
#define CPU_CONTROL_FULL_BANDWIDTH "/cpu.cfs_period_us"
#define CPU_CONF_FILE     RD_CONFIG_FILE(cpu)
#define CPU_CONF_SECTION	"CONTROL"
#define CPU_CONF_PREDEFINE	"PREDEFINE"
#define CPU_CONF_BOOTING	"BOOTING_PREDEFINE"
#define CPU_CONF_WRT	"WRT_PREDEFINE"
#define CPU_CONF_LAZY	"LAZY_PREDEFINE"
#define CPU_SHARE	"/cpu.shares"
#define MAX_PREDEFINED_TASKS 10
#define CPU_TIMER_INTERVAL	  30
#define CPU_DEFAULT_PRI 0
#define CPU_BACKGROUND_PRI 1
#define CPU_CONTROL_PRI 10
#define CPU_HIGHAPP_PRI -5
#define CPU_QUOTA_PERIOD_USEC 1000

static Ecore_Timer *cpu_predefined_timer = NULL;
static bool bCPUQuota;

static inline int ioprio_set(int which, int who, int ioprio)
{
	return syscall(__NR_ioprio_set, which, who, ioprio);
}

enum {
	IOPRIO_CLASS_NONE,
	IOPRIO_CLASS_RT,
	IOPRIO_CLASS_BE,
	IOPRIO_CLASS_IDLE,
};

enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP,
	IOPRIO_WHO_USER,
};

#define IOPRIO_CLASS_SHIFT	13

enum cpu_control_type {
	SET_NONE,
	SET_DEFAUT,
	SET_BOOTING,
	SET_WRT,
	SET_LAZY,
};

struct controltype {
	int type;
	pid_t pid;
};

struct predefined {
	int num;
	struct controltype control[MAX_PREDEFINED_TASKS];
};

struct predefined def_list = {0};

static int check_predefined(const pid_t pid)
{
	int i = 0;

	for (i = 0; i < def_list.num; i++) {
		if (pid == def_list.control[i].pid)
			return def_list.control[i].type;
	}
	return SET_NONE;
}

static int cpu_move_cgroup(pid_t pid, char *path)
{
	return cgroup_write_node(path, CGROUP_FILE_NAME, pid);
}

static bool cpu_quota_enabled(void)
{
	return bCPUQuota;
}

static void cpu_check_cpuquota(void)
{
	int ret, node = 0;
	char buf[MAX_PATH_LENGTH];

	snprintf(buf, sizeof(buf), "%s%s", CPU_DEFAULT_CGROUP, CPU_CONTROL_BANDWIDTH);
	ret = fread_int(buf, &node);
	if (!ret)
		bCPUQuota = true;
}

static int get_relative_value(const char *cgroup_name,
		const char *file_name, int percent)
{
	unsigned int val;

	if (cgroup_read_node(cgroup_name, file_name, &val) != RESOURCED_ERROR_NONE) {
		_E("Can't read %s%s. value is set to 1000", cgroup_name, file_name);
		val = 1000;
	}

	return val * percent / 100;
}

static int load_cpu_config(struct parse_result *result, void *user_data)
{
	pid_t pid = 0, value;
	if (!result)
		return -EINVAL;

	if (strncmp(result->section, CPU_CONF_SECTION, strlen(CPU_CONF_SECTION)+1))
		return RESOURCED_ERROR_NO_DATA;
	if (!strncmp(result->name, CPU_CONF_PREDEFINE, strlen(CPU_CONF_PREDEFINE)+1)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0) {
			cpu_move_cgroup(pid, CPU_BACKGROUND_GROUP);
			def_list.control[def_list.num].pid = pid;
			def_list.control[def_list.num++].type = SET_DEFAUT;
		} else {
			_E("not found appname = %s", result->value);
		}
	} else if (!strncmp(result->name, CPU_CONF_BOOTING, strlen(CPU_CONF_BOOTING)+1)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0) {
			cpu_move_cgroup(pid, CPU_BACKGROUND_GROUP);
			def_list.control[def_list.num].pid = pid;
			def_list.control[def_list.num++].type = SET_BOOTING;
			setpriority(PRIO_PROCESS, pid, CPU_BACKGROUND_PRI);
		}
	} else if (!strncmp(result->name, CPU_CONF_WRT, strlen(CPU_CONF_WRT)+1)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0) {
			cpu_move_cgroup(pid, CPU_BACKGROUND_GROUP);
			def_list.control[def_list.num].pid = pid;
			def_list.control[def_list.num++].type = SET_WRT;
			setpriority(PRIO_PROCESS, pid, CPU_CONTROL_PRI);
			ioprio_set(IOPRIO_WHO_PROCESS, pid, IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT);
		}
	} else if (!strncmp(result->name, CPU_CONF_LAZY, strlen(CPU_CONF_LAZY)+1)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0) {
			def_list.control[def_list.num].pid = pid;
			def_list.control[def_list.num++].type = SET_LAZY;
		}
	} else if (!strncmp(result->name, "BACKGROUND_CPU_SHARE", strlen("BACKGROUND_CPU_SHARE")+1)) {
		value = atoi(result->value);
		if (value)
			cgroup_write_node(CPU_BACKGROUND_GROUP, CPU_SHARE,
					get_relative_value(CPU_DEFAULT_CGROUP, CPU_SHARE, value));
	} else if (!strncmp(result->name, "QUOTA_CPU_SHARE", strlen("QUOTA_CPU_SHARE")+1)) {
		value = atoi(result->value);
		if (value && cpu_quota_enabled())
			cgroup_write_node(CPU_CPUQUOTA_GROUP, CPU_SHARE,
					get_relative_value(CPU_DEFAULT_CGROUP, CPU_SHARE, value));
	} else if (!strncmp(result->name, "QUOTA_MAX_BANDWIDTH", strlen("QUOTA_MAX_BANDWIDTH")+1)) {
		value = atoi(result->value);
		if (value && cpu_quota_enabled())
			cgroup_write_node(CPU_CPUQUOTA_GROUP, CPU_CONTROL_BANDWIDTH,
					get_relative_value(CPU_CPUQUOTA_GROUP,
						CPU_CONTROL_FULL_BANDWIDTH, value));
	}

	return RESOURCED_ERROR_NONE;
}

static int cpu_service_state(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	struct proc_app_info *pai = ps->pai;

	_D("service launch: pid = %d, appname = %s", ps->pid, ps->appid);
	if (pai && CHECK_BIT(pai->categories, PROC_BG_SYSTEM))
		return RESOURCED_ERROR_NONE;
	else
		cpu_move_cgroup(ps->pid, CPU_BACKGROUND_GROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_widget_state(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	struct proc_app_info *pai = ps->pai;

	_D("widget background: pid = %d, appname = %s", ps->pid, ps->appid);
	if (pai && CHECK_BIT(pai->flags, PROC_DOWNLOADAPP))
		cpu_move_cgroup(ps->pid, CPU_BACKGROUND_GROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_foreground_state(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	int pri;
	_D("app foreground: pid = %d, appname = %s", ps->pid, ps->appid);
	pri = getpriority(PRIO_PROCESS, ps->pid);
	if (pri == -1 || pri > CPU_DEFAULT_PRI)
		setpriority(PRIO_PGRP, ps->pid, CPU_DEFAULT_PRI);
	if (check_predefined(ps->pid) != SET_DEFAUT)
		cpu_move_cgroup(ps->pid, CPU_DEFAULT_CGROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_background_state(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	_D("app background: pid = %d, appname = %s", ps->pid, ps->appid);
	setpriority(PRIO_PGRP, ps->pid, CPU_BACKGROUND_PRI);
	cpu_move_cgroup(ps->pid, CPU_BACKGROUND_GROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_restrict_state(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	_D("app suspend: pid = %d, appname = %s", ps->pid, ps->appid);
	if (CHECK_BIT(ps->pai->categories, PROC_BG_MEDIA))
		return RESOURCED_ERROR_NONE;
	cpu_move_cgroup(ps->pid, CPU_CPUQUOTA_GROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_active_state(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	int oom_score_adj = 0, ret;
	_D("app active : pid = %d, appname = %s", ps->pid, ps->appid);
	ret = proc_get_oom_score_adj(ps->pid, &oom_score_adj);
	if (ret || oom_score_adj < OOMADJ_PREVIOUS_DEFAULT)
		return RESOURCED_ERROR_NONE;
	cpu_move_cgroup(ps->pid, CPU_DEFAULT_CGROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_prelaunch_state(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	struct proc_app_info *pai = ps->pai;
	int i = 0;

	if (!cpu_predefined_timer)
		return RESOURCED_ERROR_NONE;
	if (pai->type & PROC_WEBAPP) {
		for (i = 0; i < def_list.num; i++) {
			if (def_list.control[i].type == SET_WRT) {
				cpu_move_cgroup(def_list.control[i].pid, CPU_DEFAULT_CGROUP);
				setpriority(PRIO_PGRP, def_list.control[i].pid, 0);
				ioprio_set(IOPRIO_WHO_PROCESS, def_list.control[i].pid, IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT);
				return RESOURCED_ERROR_NONE;
			}
		}
	}
	return RESOURCED_ERROR_NONE;
}

static int cpu_system_state(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;

	_D("system service : pid = %d", ps->pid);
	cpu_move_cgroup(ps->pid, CPU_BACKGROUND_GROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_terminatestart_state(void *data)
{
	struct proc_status *ps = (struct proc_status *)data;
	cpu_move_cgroup(ps->pid, CPU_DEFAULT_CGROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_exclude_state(void *data)
{
	struct proc_exclude *pe = (struct proc_exclude *)data;
	if (check_predefined(pe->pid) != SET_DEFAUT)
		return RESOURCED_ERROR_NONE;
	if (pe->type == PROC_INCLUDE)
		cpu_move_cgroup(pe->pid, CPU_BACKGROUND_GROUP);
	else
		cpu_move_cgroup(pe->pid, CPU_DEFAULT_CGROUP);
	return RESOURCED_ERROR_NONE;
}

static Eina_Bool cpu_predefined_cb(void *data)
{
	int i = 0;

	for (i = 0; i < def_list.num; i++) {
		if (def_list.control[i].type == SET_LAZY) {
			cpu_move_cgroup(def_list.control[i].pid, CPU_BACKGROUND_GROUP);
		} else if (def_list.control[i].type == SET_BOOTING) {
			cpu_move_cgroup(def_list.control[i].pid, CPU_DEFAULT_CGROUP);
			setpriority(PRIO_PROCESS, def_list.control[i].pid, 0);
		} else if (def_list.control[i].type == SET_WRT) {
			cpu_move_cgroup(def_list.control[i].pid, CPU_DEFAULT_CGROUP);
			setpriority(PRIO_PROCESS, def_list.control[i].pid, 0);
			ioprio_set(IOPRIO_WHO_PROCESS, def_list.control[i].pid, IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT);
		}
	}
	ecore_timer_del(cpu_predefined_timer);
	cpu_predefined_timer = NULL;
	return ECORE_CALLBACK_CANCEL;

}

static int resourced_cpu_init(void *data)
{
	int ret_code;

	_D("resourced_cpu_init");
	ret_code = make_cgroup_subdir(CPU_DEFAULT_CGROUP, "background", NULL);
	ret_value_msg_if(ret_code < 0, ret_code, "cpu init failed\n");
	cpu_check_cpuquota();
	if (cpu_quota_enabled()) {
		ret_code = make_cgroup_subdir(CPU_DEFAULT_CGROUP, "quota", NULL);
		ret_value_msg_if(ret_code < 0, ret_code, "create service cgroup failed\n");
	}
	config_parse(CPU_CONF_FILE, load_cpu_config, NULL);

	if (def_list.num)
		cpu_predefined_timer =
			ecore_timer_add(CPU_TIMER_INTERVAL, cpu_predefined_cb, NULL);
	register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, cpu_service_state);
	register_notifier(RESOURCED_NOTIFIER_APP_RESUME, cpu_foreground_state);
	register_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, cpu_foreground_state);
	register_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, cpu_background_state);
	register_notifier(RESOURCED_NOTIFIER_APP_PRELAUNCH, cpu_prelaunch_state);
	register_notifier(RESOURCED_NOTIFIER_SYSTEM_SERVICE, cpu_system_state);
	register_notifier(RESOURCED_NOTIFIER_APP_TERMINATE_START, cpu_terminatestart_state);
	register_notifier(RESOURCED_NOTIFIER_CONTROL_EXCLUDE, cpu_exclude_state);
	register_notifier(RESOURCED_NOTIFIER_WIDGET_FOREGRD, cpu_foreground_state);
	register_notifier(RESOURCED_NOTIFIER_WIDGET_BACKGRD, cpu_widget_state);
	register_notifier(RESOURCED_NOTIFIER_APP_ACTIVE, cpu_active_state);
	if (cpu_quota_enabled())
		register_notifier(RESOURCED_NOTIFIER_APP_SUSPEND_READY,
		    cpu_restrict_state);
	return RESOURCED_ERROR_NONE;
}

static int resourced_cpu_finalize(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, cpu_service_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_RESUME, cpu_foreground_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, cpu_foreground_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, cpu_background_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_PRELAUNCH, cpu_prelaunch_state);
	unregister_notifier(RESOURCED_NOTIFIER_SYSTEM_SERVICE, cpu_system_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_TERMINATE_START, cpu_terminatestart_state);
	unregister_notifier(RESOURCED_NOTIFIER_CONTROL_EXCLUDE, cpu_exclude_state);
	unregister_notifier(RESOURCED_NOTIFIER_WIDGET_FOREGRD, cpu_foreground_state);
	unregister_notifier(RESOURCED_NOTIFIER_WIDGET_BACKGRD, cpu_widget_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_ACTIVE, cpu_active_state);
	if (cpu_quota_enabled())
		unregister_notifier(RESOURCED_NOTIFIER_APP_SUSPEND_READY,
		    cpu_restrict_state);
	return RESOURCED_ERROR_NONE;
}

static struct module_ops cpu_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "cpu",
	.init = resourced_cpu_init,
	.exit = resourced_cpu_finalize,
};

MODULE_REGISTER(&cpu_modules_ops)

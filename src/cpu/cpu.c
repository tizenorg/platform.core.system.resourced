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
#include "proc-main.h"
#include "proc-process.h"
#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "resourced.h"
#include "trace.h"
#include "vconf.h"
#include "cgroup.h"
#include "config-parser.h"
#include "const.h"

#define CPU_DEFAULT_CGROUP "/sys/fs/cgroup/cpu"
#define CPU_CONTROL_GROUP "/sys/fs/cgroup/cpu/background"
#define CPU_CONTROL_SERVICE_GROUP "/sys/fs/cgroup/cpu/service"
#define CPU_CONF_FILE                  "/etc/resourced/cpu.conf"
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
#define CPU_HIGHAPP_PRI -10

static Ecore_Timer *cpu_predefined_timer = NULL;

static inline int ioprio_set(int which, int who, int ioprio)
{
	return syscall(__NR_ioprio_set, which, who, ioprio);
}

enum
{
	IOPRIO_CLASS_NONE,
	IOPRIO_CLASS_RT,
	IOPRIO_CLASS_BE,
	IOPRIO_CLASS_IDLE,
};

enum
{
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

static int load_cpu_config(struct parse_result *result, void *user_data)
{
	pid_t pid = 0, value;
	if (!result)
		return -EINVAL;

	if (strcmp(result->section, CPU_CONF_SECTION))
		return RESOURCED_ERROR_NO_DATA;
	if (!strcmp(result->name, CPU_CONF_PREDEFINE)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0) {
			cpu_move_cgroup(pid, CPU_CONTROL_GROUP);
			def_list.control[def_list.num].pid = pid;
			def_list.control[def_list.num++].type = SET_DEFAUT;
		} else {
			_E("not found appname = %s", result->value);
		}
	} else if (!strcmp(result->name, CPU_CONF_BOOTING)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0) {
			cpu_move_cgroup(pid, CPU_CONTROL_GROUP);
			def_list.control[def_list.num].pid = pid;
			def_list.control[def_list.num++].type = SET_BOOTING;
			setpriority(PRIO_PROCESS, pid, CPU_CONTROL_PRI);
		}
	} else if (!strcmp(result->name, CPU_CONF_WRT)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0) {
			cpu_move_cgroup(pid, CPU_CONTROL_GROUP);
			def_list.control[def_list.num].pid = pid;
			def_list.control[def_list.num++].type = SET_WRT;
			setpriority(PRIO_PROCESS, pid, CPU_CONTROL_PRI);
			ioprio_set(IOPRIO_WHO_PROCESS, pid, IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT);
		}
	} else if (!strcmp(result->name, CPU_CONF_LAZY)) {
		pid = find_pid_from_cmdline(result->value);
		if (pid > 0) {
			def_list.control[def_list.num].pid = pid;
			def_list.control[def_list.num++].type = SET_LAZY;
		}
	} else if (!strcmp(result->name, "BACKGROUND_CPU_SHARE")) {
		value = atoi(result->value);
		if (value)
			cgroup_write_node(CPU_CONTROL_GROUP, CPU_SHARE, value);
       } else if (!strcmp(result->name, "SERVICE_CPU_SHARE")) {
		value = atoi(result->value);
		if (value)
			cgroup_write_node(CPU_CONTROL_SERVICE_GROUP, CPU_SHARE, value);
       }
       return RESOURCED_ERROR_NONE;
}

static int cpu_service_launch(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	_D("cpu_service_launch : pid = %d, appname = %s", p_data->pid, p_data->appid);
	cpu_move_cgroup(p_data->pid, CPU_CONTROL_SERVICE_GROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_foreground_state(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	int pri;
	_D("cpu_foreground_state : pid = %d, appname = %s", p_data->pid, p_data->appid);
	pri = getpriority(PRIO_PROCESS, p_data->pid);
	if (pri == -1 || pri > CPU_DEFAULT_PRI)
		setpriority(PRIO_PGRP, p_data->pid, CPU_DEFAULT_PRI);
	if (check_predefined(p_data->pid) != SET_DEFAUT)
		cpu_move_cgroup(p_data->pid, CPU_DEFAULT_CGROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_background_state(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	_D("cpu_background_state : pid = %d, appname = %s", p_data->pid, p_data->appid);
	setpriority(PRIO_PGRP, p_data->pid, CPU_BACKGROUND_PRI);
	cpu_move_cgroup(p_data->pid, CPU_CONTROL_SERVICE_GROUP);
	return RESOURCED_ERROR_NONE;
}

static int cpu_prelaunch_state(void *data)
{
	struct proc_status *p_data = (struct proc_status*)data;
	struct proc_process_info_t *ppi = p_data->ppi;
	int i = 0;
	GSList *iter = NULL;
	if (!cpu_predefined_timer)
		return RESOURCED_ERROR_NONE;
	if (ppi->type & PROC_WEBAPP) {
		for (i = 0; i < def_list.num; i++) {
			if (def_list.control[i].type == SET_WRT) {
				cpu_move_cgroup(def_list.control[i].pid, CPU_DEFAULT_CGROUP);
				setpriority(PRIO_PGRP, def_list.control[i].pid, 0);
				ioprio_set(IOPRIO_WHO_PROCESS, def_list.control[i].pid, IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT);
				return RESOURCED_ERROR_NONE;
			}
		}
	} else {
		gslist_for_each_item(iter, ppi->pids) {
			struct pid_info_t *pi = (struct pid_info_t *)(iter->data);
			if (pi && pi->type == PROC_TYPE_GUI) {
				if (check_predefined(pi->pid) == SET_BOOTING) {
					cpu_move_cgroup(p_data->pid, CPU_DEFAULT_CGROUP);
					setpriority(PRIO_PGRP, p_data->pid, 0);
					return RESOURCED_ERROR_NONE;
				}
			}
		}
	}
	return RESOURCED_ERROR_NONE;
}

static Eina_Bool cpu_predefined_cb(void *data)
{
	int i = 0;

	for (i = 0; i < def_list.num; i++) {
		if (def_list.control[i].type == SET_LAZY) {
			cpu_move_cgroup(def_list.control[i].pid, CPU_CONTROL_GROUP);
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
	ret_code = make_cgroup_subdir(CPU_DEFAULT_CGROUP, "service", NULL);
	ret_value_msg_if(ret_code < 0, ret_code, "create service cgroup failed\n");
	config_parse(CPU_CONF_FILE, load_cpu_config, NULL);

	if (def_list.num)
		cpu_predefined_timer =
			ecore_timer_add(CPU_TIMER_INTERVAL, cpu_predefined_cb, NULL);
	register_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, cpu_service_launch);
	register_notifier(RESOURCED_NOTIFIER_APP_RESUME, cpu_foreground_state);
	register_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, cpu_foreground_state);
	register_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, cpu_background_state);
	register_notifier(RESOURCED_NOTIFIER_APP_PRELAUNCH, cpu_prelaunch_state);
	return RESOURCED_ERROR_NONE;
}

static int resourced_cpu_finalize(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SERVICE_LAUNCH, cpu_service_launch);
	unregister_notifier(RESOURCED_NOTIFIER_APP_RESUME, cpu_foreground_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_FOREGRD, cpu_foreground_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_BACKGRD, cpu_background_state);
	unregister_notifier(RESOURCED_NOTIFIER_APP_PRELAUNCH, cpu_prelaunch_state);
	return RESOURCED_ERROR_NONE;
}

static struct module_ops cpu_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "cpu",
	.init = resourced_cpu_init,
	.exit = resourced_cpu_finalize,
};

MODULE_REGISTER(&cpu_modules_ops)

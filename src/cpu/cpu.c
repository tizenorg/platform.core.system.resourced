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
#include "cpu-common.h"
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

#include <fcntl.h>               /*mkdirat */
#include <sys/stat.h>            /*mkdirat */
#include <stdlib.h>

#define CPU_DEFAULT_CGROUP "/sys/fs/cgroup/cpu"
#define CPU_CONTROL_GROUP "/sys/fs/cgroup/cpu/background"
#define CPU_CONF_FILE                  "/etc/resourced/cpu.conf"
#define CPU_CONF_SECTION	"CONTROL"
#define CPU_CONF_PREDEFINE	"PREDEFINE"
#define CPU_SHARE	"/cpu.shares"

static int make_cpu_cgroup(char* path)
{
	DIR *dir = 0;
	int fd;
	dir = opendir(CPU_DEFAULT_CGROUP);
	if (!dir) {
		_E("cpu cgroup doesn't exit : %d", errno);
		return RESOURCED_ERROR_UNINITIALIZED;
	}
	fd = dirfd(dir);
	if (fd < 0) {
		_E("fail to get fd about cpu cgroup : %d", errno);
		closedir(dir);
		return RESOURCED_ERROR_UNINITIALIZED;
	}
	if (mkdirat(fd, path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH) < 0) {
		_E("fail to get fd about cpu cgroup : %d", errno);
		closedir(dir);
		return RESOURCED_ERROR_UNINITIALIZED;
	}
	closedir(dir);
	return RESOURCED_ERROR_NONE;
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
		if (pid > 0)
			cpu_move_cgroup(pid, CPU_CONTROL_GROUP);
	} else if (!strcmp(result->name, "CPU_SHARE")) {
		value = atoi(result->value);
		if (value)
			cgroup_write_node(CPU_CONTROL_GROUP, CPU_SHARE, value);
       }
       return RESOURCED_ERROR_NONE;
}

static int resourced_cpu_control(void *data)
{
	struct cpu_data_type *c_data;
	int ret = RESOURCED_ERROR_NONE;
	pid_t pid;
	c_data = (struct cpu_data_type *)data;
	if (!c_data)
		return RESOURCED_ERROR_NO_DATA;
	pid = c_data->pid;
	_D("resourced_cpu_control : type = %d, pid = %d", c_data->control_type, pid);
	switch(c_data->control_type) {
	case CPU_SET_LAUNCH:
	case CPU_SET_FOREGROUND:
		ret = cpu_move_cgroup(pid, CPU_DEFAULT_CGROUP);
		break;
	case CPU_SET_BACKGROUND:
		ret = cpu_move_cgroup(pid, CPU_CONTROL_GROUP);
		break;
	}
	return ret;
}

static int resourced_cpu_init(void *data)
{
	int ret_code;

	_D("resourced_cpu_init");
	ret_code = make_cpu_cgroup(CPU_CONTROL_GROUP);
	ret_value_msg_if(ret_code < 0, ret_code, "cpu init failed\n");
	config_parse(CPU_CONF_FILE, load_cpu_config, NULL);
	return RESOURCED_ERROR_NONE;
}

static int resourced_cpu_finalize(void *data)
{
	return RESOURCED_ERROR_NONE;
}

static struct module_ops cpu_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "cpu",
	.init = resourced_cpu_init,
	.exit = resourced_cpu_finalize,
	.control = resourced_cpu_control,
};

MODULE_REGISTER(&cpu_modules_ops)

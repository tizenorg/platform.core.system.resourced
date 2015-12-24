/*
 * resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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

/**
 * @file  cgroup.c
 * @desc  Cgroup related functions
 **/

#include <errno.h>
#include "resourced_tests.h"

/* Checks if the input pid is present in the input cgroup */
int is_pid_in_cgroup(char *cgroup_path, int pid)
{
	int curr_pid;
	FILE *procs_file;
	char buf[STRING_MAX];

	snprintf(buf, sizeof(buf), "%s%s", cgroup_path, "cgroup.procs");
	procs_file = fopen(buf, "r");
	if (!procs_file) {
		_E("IO: Error opening file %s", buf);
		return RESOURCED_ERROR_FAIL;
	}

	curr_pid = -1;
	_D("reading %s file for %d pid", buf, pid);
	while (fgets(buf, sizeof(buf), procs_file) != NULL) {
		if (sscanf(buf, "%d", &curr_pid) != 1) {
			_E("IO: Error reading pid value %s", buf);
			curr_pid = -1;
			break;
		}
		if (curr_pid == pid)
			break;
	}
	fclose(procs_file);

	return (curr_pid == pid) ? RESOURCED_ERROR_NONE : RESOURCED_ERROR_FAIL;
}

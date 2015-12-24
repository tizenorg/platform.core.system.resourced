/*
   Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License
*/

/* @author: Prajwal A N
 * @file: proc-stat.c
 * @desc: Tests for proc-stat APIs in resourced
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <proc_stat.h>

#include "resourced_tests.h"

#define PSTAT_GET_PID_ENTRY_MAX_TESTS 5

int pstat_get_pid_entry(void)
{
	char buf[4*STRING_MAX];
	int i, ret, final_ret;
	int pid;
	char *tests[] = {
		"cmdline",
		"exe",
		"stat",
		"status",
		"oomscore"
	};
	int test_inp[] = {
		PROC_CGROUP_GET_CMDLINE,
		PROC_CGROUP_GET_EXE,
		PROC_CGROUP_GET_STAT,
		PROC_CGROUP_GET_STATUS,
		PROC_CGROUP_GET_OOMSCORE,
	};

	pid = getpid();
	final_ret = RESOURCED_ERROR_NONE;
	for (i = 0; i < PSTAT_GET_PID_ENTRY_MAX_TESTS; ++i) {
		ret = proc_stat_get_pid_entry(test_inp[i], pid, buf, sizeof(buf)-1);
		buf[sizeof(buf)-1] = 0;
		if (ret != RESOURCED_ERROR_NONE) {
			_E("Test %s: failed with %d error", tests[i], ret);
			final_ret = RESOURCED_ERROR_FAIL;
		} else
			_D("Test %s: Passed. buf: %s", tests[i], buf);
	}
	return final_ret;
}

static struct resourced_test_t pstat_tests[] = {
	{ "pstat_get_pid_entry", pstat_get_pid_entry },
	{ "", NULL },
};

int main(int argc, char *argv[])
{
	int i, ret;

	TEST_START_MESSAGE("proc-stat module");

	for (i = 0; pstat_tests[i].test_func; ++i) {
		_D("=======================================");
		_D("Current Test: %s", pstat_tests[i].name);
		ret = (*pstat_tests[i].test_func)();
		if (IS_ERROR(ret))
			_E("Test %s failed!", pstat_tests[i].name);
		else
			_D("Test %s passed!", pstat_tests[i].name);
	}
	return 0;
}

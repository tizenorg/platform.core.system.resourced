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
 * @file: cpu.c
 * @desc: Tests for the CPU module in resourced
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>

#include "resourced_tests.h"
#include "utils.h"

#define CGROUP_FS "/sys/fs/cgroup/"
#define CPU_MAIN_CGROUP CGROUP_FS"cpu/"
#define CPU_BACKGROUND_CGROUP CPU_MAIN_CGROUP"background/"
#define CPU_QUOTA_CGROUP CPU_BACKGROUND_CGROUP"quota/"
#define CPU_DOWNLOAD_CGROUP CPU_BACKGROUND_CGROUP"download/"
#define CPU_QUOTA_US "cpu.cfs_quota_us"

static bool cpu_quota_enabled = false;

int cpu_check_cgroups(void)
{
	char *cgroups[] = {
		CPU_MAIN_CGROUP,
		CPU_BACKGROUND_CGROUP,
		CPU_DOWNLOAD_CGROUP,
		NULL,
	};
	int i;
	char buf[STRING_MAX];

	for (i = 0; cgroups[i]; ++i) {
		snprintf(buf, sizeof(buf), "%s%s", cgroups[i], "cgroup.procs");
		if (access(buf, F_OK)) {
			_E("%s cgroup not created (%d)!", cgroups[i], errno);
			return RESOURCED_ERROR_FAIL;
		}
	}

	cpu_quota_enabled = false;
	if (!access(CPU_MAIN_CGROUP CPU_QUOTA_US, F_OK)) {
		cpu_quota_enabled = true;
		snprintf(buf, sizeof(buf), "%s%s", CPU_QUOTA_CGROUP, "cgroup.procs");
		if (access(buf, F_OK)) {
			_E("%s cgroup not created (%d)!", CPU_QUOTA_CGROUP, errno);
			return RESOURCED_ERROR_FAIL;
		}
	}

	return RESOURCED_ERROR_NONE;
}

int cpu_app_cycle_check(void)
{
	int ret;
	int app_pid;

#define CGROUP_ENTRY_WAIT(time_sec) \
	do { \
		struct timespec req, rem; \
		req.tv_sec = time_sec; \
		req.tv_nsec = 0; \
		nanosleep(&req, &rem); \
	} while(0);

	printf("Checking app cycle. Launch an app and enter its pid:");
	ret = scanf("%d", &app_pid);
	CGROUP_ENTRY_WAIT(3);

	ret = is_pid_in_cgroup(CPU_MAIN_CGROUP, app_pid);
	if (IS_ERROR(ret)) {
		_E("%d not found in main cpu cgroup after launch", app_pid);
		return RESOURCED_ERROR_FAIL;
	}

	printf("Move the app to background\n");
	CGROUP_ENTRY_WAIT(6);

	ret = is_pid_in_cgroup(CPU_BACKGROUND_CGROUP, app_pid);
	if (IS_ERROR(ret)) {
		_E("%d not found in background cpu cgroup after sent to background", app_pid);
		return RESOURCED_ERROR_FAIL;
	}

	if (cpu_quota_enabled) {
		printf("Open another app and send it to background\n");
		CGROUP_ENTRY_WAIT(15);

		ret = is_pid_in_cgroup(CPU_QUOTA_CGROUP, app_pid);
		if (IS_ERROR(ret)) {
			_E("%d not found in quota cpu cgroup after readied for suspend", app_pid);
			return RESOURCED_ERROR_FAIL;
		}
	}

	printf("Resume the first app through task mgr\n");
	CGROUP_ENTRY_WAIT(10);

	ret = is_pid_in_cgroup(CPU_MAIN_CGROUP, app_pid);
	if (IS_ERROR(ret)) {
		_E("%d not found in main cpu cgroup after resuming", app_pid);
		return RESOURCED_ERROR_FAIL;
	}

	printf("Testing complete. Exit the app\n");
	return RESOURCED_ERROR_NONE;
}

static struct resourced_test_t cpu_tests[] = {
	{ "cpu_check_cgroups", cpu_check_cgroups },
	{ "cpu_app_cycle", cpu_app_cycle_check },
	{ "", NULL },
};

int main(int argc, char *argv[])
{
	int i, ret;

	TEST_START_MESSAGE("cpu module");

	for (i = 0; cpu_tests[i].test_func; ++i) {
		_D("=======================================");
		_D("Current Test: %s", cpu_tests[i].name);
		ret = (*cpu_tests[i].test_func)();
		if (IS_ERROR(ret))
			_E("Test %s failed!", cpu_tests[i].name);
		else
			_D("Test %s passed!", cpu_tests[i].name);

		if (!i && IS_ERROR(ret))
			break;
	}
	return 0;
}

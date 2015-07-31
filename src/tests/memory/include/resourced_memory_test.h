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
 * @file  resourced_memory_tests.h
 * @desc  common definitions for memory tests program
 **/

#ifndef __RESOURCED_MEMORY_TEST_H__
#define __RESOURCED_MEMORY_TEST_H__

#include "resourced_tests.h"

/* Memory margins which are used to define lowmem boundaries (in resourced) */
#define RESOURCED_THRESHOLD_MARGIN 10

/* Maximum kills limit in resourced */
#define RESOURCED_MAX_VICTIMS 10

#define MEMCG_ROOT "/sys/fs/cgroup/memory"

/* Memory cgroups as defined in resourced
 * Any addition of deletion to this enum list should
 * be accompanied by appropriate changes to the memcg_*
 * arrays defined below
 */
enum {
	MEMCG_MEMORY,
	MEMCG_PLATFORM,
	MEMCG_FOREGROUND,
	MEMCG_PREVIOUS,
	MEMCG_FAVORITE,
	MEMCG_BACKGROUND,
	MEMCG_SWAP,
	MEMCG_MAX,
};

/* Resourced memory tests available in the resourced_memory_test program
 * Any addition of deletion to this enum list should be accompanied by
 * appropriate changes to the test_name and memcg_* arrays defined below
 */
enum {
	TEST_PROACTIVE_KILLER,
	TEST_OOM_DBUS_TRIGGER,
	TEST_VMPRESSURE_ROOT,
	TEST_VMPRESSURE_ROOT_CB,
	TEST_VMPRESSURE_CGROUP,
	TEST_MAX,
};

/* Name of each test enumerated above (used for input and debug purposes) */
extern char *test_name[TEST_MAX];

/* Limits (associated with the target) present in the memory module of resourced
 * These limits are used to create the needed scenario to activate the appropriate
 * interface of the vmpressure module of resourced
 * Any addition of deletion to this enum list should be accompanied by appropriate
 * changes to the memcg_* arrays defined below
 */
enum {
	LIMIT_TOTAL_MEMORY,
	LIMIT_THRESHOLD_SWAP,
	LIMIT_THRESHOLD_LOW,
	LIMIT_THRESHOLD_MEDIUM,
	LIMIT_THRESHOLD_LEAVE,
	LIMIT_DYNAMIC_THRESHOLD,
	LIMIT_DYNAMIC_THRESH_LEAVE,
	LIMIT_MAX_VICTIMS,
	LIMIT_MAX,
};

/* Target memory configurations supported by resourced
 * Currently the tests package only tests the 750MB configuration (Z1)
 * Any addition of deletion to this enum list should be accompanied by
 * appropriate changes to the vmpressure_* arrays defined in resourced_memory_test.c
 */
enum {
	MEMCONF_768,
	MEMCONF_MAX,
};

/* Name of the memcg subcgroups as defined by resourced */
extern char *memcg_name[MEMCG_MAX];

/* Defines the fraction of memory to be allocated to each
 * cgroup (in a particular test) when creating the base usage
 * scenario of that test
 */
extern double memcg_base_usage_ratio[TEST_MAX][MEMCG_MAX];

/* Defines the number of processes to be started in each
 * cgroup (in a particular test) when creating the base usage
 * scenario of that test. All processes started in a cgroup
 * use the same amount of memory (memory allocated to the cgroup
 * is equally divided among the processes of the cgroup).
 */
extern int memcg_base_process_num[TEST_MAX][MEMCG_MAX];

/* Defines the oom adj score of each process (of the number
 * of processes defined in memcg_base_process_num) started in each
 * cgroup (for a particular test)
 */
extern int memcg_base_process_oom[TEST_MAX][MEMCG_MAX][RESOURCED_MAX_VICTIMS];

/* Process IDs of each process (of the number of processes defined in
 * memcg_base_process_num) started in each cgroup (for a particular test)
 */
extern int pid_list[][RESOURCED_MAX_VICTIMS];

extern int pid_memory_list[][RESOURCED_MAX_VICTIMS];

int get_memconf(int total);
int launch_memory_hogger(int memory, int oom, char *cgroup_path);
void populate_cgroup(int test, int memcg_index, int target);
int check_cgroup_kill_status(int test, int memcg_index, int kill_flag,
				int recovery_target, int *recovered,
				int num_max_victims, int *num_victims);

#endif

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
 * @file  resourced_memory_test.c
 * @desc  test program for memory module of resourced
 **/

#include <time.h>
#include "resourced_memory_test.h"
#include "utils.h"

#define PROACTIVE_SLEEP 15
#define VMPRESSURE_ROOT_SLEEP 5
#define VMPRESSURE_ROOT_CB_SLEEP 32

char *test_name[TEST_MAX] = {
	"proactive",
	"oom_trigger",
	"vmpressure_root",
	"vmpressure_root_cb",
	"vmpressure_cgroup",
};

char *memcg_name[MEMCG_MAX] = {
	"root",
	"platform",
	"foreground",
	"previous",
	"favorite",
	"background",
	"swap"
};

double memcg_base_usage_ratio[TEST_MAX][MEMCG_MAX] = {
	{0.2, 0, 0.2, 0, 0, 0.4, 0.2},		/* Proactive killer */
	{0, 0, 0.2, 0, 0, 0.6, 0.2},		/* OOM dbus trigger */
	{0.05, 0, 0.4, 0.05, 0, 0.4, 0.15},	/* VmPressure on root cgroup with no callback */
	{0.1, 0, 0.25, 0.05, 0.05, 0.4, 0.15},	/* VmPressure on root cgroup with callback */
	{0, 0, 1, 1, 1, 1, 1},			/* VmPressure on other cgroups */
};

int memcg_base_process_num[TEST_MAX][MEMCG_MAX] = {
	{1, 0, 1, 0, 0, 5, 3},			/* Proactive killer */
	{0, 0, 1, 0, 0, 6, 3},			/* OOM dbus trigger */
	{2, 0, 5, 1, 0, 6, 3},			/* VmPressure on root cgroup with no callback */
	{2, 0, 3, 1, 1, 5, 3},			/* VmPressure on root cgroup with callback */
	{1, 0, 1, 0, 0, 5, 3},			/* VmPressure on other cgroups */
};

int memcg_base_process_oom[TEST_MAX][MEMCG_MAX][RESOURCED_MAX_VICTIMS] = {
	/* Proactive killer */
	{
		{-900},
		{},
		{150},
		{},
		{},
		{-900, -900, 300, 300, 350},
		{-900, 350, 350}
	},
	/* OOM dbus trigger */
	{
		{},
		{},
		{150},
		{},
		{},
		{-900, -900, 300, 300, 300, 350},
		{-900, 350, 350}
	},
	/* VmPressure on root cgroup with no callback */
	{
		{-900, 200},
		{},
		{-900, 150, 150, 170, 200},
		{230},
		{},
		{-900, -900, 300, 300, 350, 400},
		{-900, 350, 350}
	},
	/* VmPressure on root cgroup with callback */
	{
		{-900, -900},
		{},
		{-900, -900, 150},
		{150},
		{-900},
		{-900, -900, -900, -900, 350},
		{-900, -900, 350}
	},
	/* VmPressure on different cgroups */
	{
		{-900},
		{},
		{150},
		{},
		{},
		{-900, -900, 300, 300, 350},
		{-900, 350, 350}
	},
};

/* The values of the limit specified in the LIMIT_* enum list
 * for each memory configuration in the MEMCONF_* enum list
 */
static int vmpressure_limits[MEMCONF_MAX][LIMIT_MAX] = {
	{768, 300, 200, 100, 150, 150, 230, 5}
};

/* Different memory margins defined for each memory configuration */
enum {
	MEMORY_MARGIN_LOW,
	MEMORY_MARGIN_MEDIUM,
	MEMORY_MARGIN_HIGH,
	MEMORY_MARGIN_MAX,
};

/* Memory margins to be used for different memory configurations
 * These values of these margins are set according to the values of the limits
 * (in resourced) in the LIMITS_* list. These margins help in managing the
 * internal memory state of the memory module of resourced
 */
static int memory_margin[MEMCONF_MAX][MEMORY_MARGIN_MAX] = {
	{10, 25, 40}
};

int pid_list[MEMCG_MAX][RESOURCED_MAX_VICTIMS];
int pid_memory_list[MEMCG_MAX][RESOURCED_MAX_VICTIMS];

/* Test for proactive oom killer (called by the prelaunch dbus signal handler) */
int proactive_oom_killer(void)
{
	int available, prev_available, target;
	int to_populate, recovered, recovery_target;
	int memconf;
	int pid_bck, pid_swap;
	int num_max_victims, num_victims;
	int memcg_index;
	int ret, ret_val, kill_flag;
	char bckground_path[STRING_MAX];
	char swap_path[STRING_MAX];
	char inp_str[STRING_MAX];
	struct timespec req, rem;

	available = kBtoMB(procfs_get_available());
	memconf = get_memconf(kBtoMB(procfs_get_total()));

	/* Populating memory till dynamic threshold */
	to_populate = available - vmpressure_limits[memconf][LIMIT_DYNAMIC_THRESHOLD];
	to_populate += memory_margin[memconf][MEMORY_MARGIN_MEDIUM];
	if (to_populate < 0) {
		_E("Not able to test proactive oom killer. Not enough memory");
		return ERROR_MEMORY;
	}

	/* Add a process each to the background and the swap cgroups (with sizes in ratio 0.4/0.6 of to_populate) */
	snprintf(bckground_path, sizeof(bckground_path), "%s/%s/cgroup.procs", MEMCG_ROOT, memcg_name[MEMCG_BACKGROUND]);
	snprintf(swap_path, sizeof(swap_path), "%s/%s/cgroup.procs", MEMCG_ROOT, memcg_name[MEMCG_SWAP]);
	pid_bck = launch_memory_hogger((int)(to_populate*0.6), 300, bckground_path);
	pid_swap = launch_memory_hogger((int)(to_populate*0.4), 350, swap_path);
	if (pid_bck < 0 || pid_swap < 0) {
		_E("error in creating processes");
		return ERROR_MEMORY;
	}
	prev_available = available = kBtoMB(procfs_get_available());
	_D("Added %d MB to raise to dynamic threshold (%d MB). current available %d MB",
			to_populate, vmpressure_limits[memconf][LIMIT_DYNAMIC_THRESHOLD], available);

	/* Expecting input after the needed dbus call to prelaunch handler is made
	 * Will sleep for PROACTIVE_SLEEP seconds before checking for results
	 * This is to allow time for proactive killer in resourced to finish its operation
	 */
	printf("Enter input (to continue) after triggering dbus call to prelaunch handler: ");
	ret = scanf("%s", inp_str);
	_D("going to sleep for %d seconds before testing output scenario\n\n\n\n", PROACTIVE_SLEEP);
	req.tv_sec = PROACTIVE_SLEEP;
	req.tv_nsec = 0;
	nanosleep(&req, &rem);

	/* Check if the dynamic threshold has been finally reached */
	available = kBtoMB(procfs_get_available());
	target = vmpressure_limits[memconf][LIMIT_DYNAMIC_THRESH_LEAVE] + memory_margin[memconf][MEMORY_MARGIN_LOW];
	if (available >= target)
		_D("proactive killer reached dynamic threshold leave as expected");
	else
		_E("proactive killer did not reach dynamic threshold leave (%d / %d)",
				available, vmpressure_limits[memconf][LIMIT_DYNAMIC_THRESH_LEAVE]);

	/* Start checking for kills/no-kills accordingly
	 * Keep track of recovered memory and # of kills for each encountered kill
	 * (Note that this calculation is just approximate and not accurate which is why memory margins are used)
	 */
	ret_val = ERROR_NONE;
	recovery_target = vmpressure_limits[memconf][LIMIT_DYNAMIC_THRESH_LEAVE] - prev_available;
	recovery_target += memory_margin[memconf][MEMORY_MARGIN_LOW];
	recovered = 0;
	num_max_victims = vmpressure_limits[memconf][LIMIT_MAX_VICTIMS];
	num_victims = 0;
	_D("current available %d MB, recovery target: %d MB", available, recovery_target);

	/* Starting from swap cgroup proceed till the foreground cgroup checking according to the cgroup */
	for (memcg_index = MEMCG_SWAP; memcg_index >= MEMCG_FOREGROUND; --memcg_index) {
		_D("checking %s cgroup....", memcg_name[memcg_index]);

		/* kill_flag keeps track of if kills are expected in the current cgroup or not
		 * Swap and background cgroups expect kills (nature of proactive killer)
		 * the other cgroups should not have any kills
		 */
		kill_flag = 1;
		switch (memcg_index) {
		case MEMCG_SWAP:
			/* Check if the pid_swap process started above has been killed (expected) */
			if (pid_exists(pid_swap))
				_E("process %d expected to be killed in swap! (%d / %d)",
						pid_swap, recovered, recovery_target);
			else {
				_D("process %d killed as expected in swap (%d / %d)",
						pid_swap, recovered, recovery_target);
				recovered += (int)(to_populate*0.4);
				num_victims++;
			}
			break;
		case MEMCG_BACKGROUND:
			/* Check if the pid_bck process started above has been killed (expected) */
			if (pid_exists(pid_bck)) {
				if (recovered < recovery_target && num_victims < num_max_victims)
					_E("process %d expected to be killed in backgrd! (%d / %d)",
							pid_bck, recovered, recovery_target);
			} else {
				if (recovered >= recovery_target || num_victims >= num_max_victims)
					_E("process %d should not be killed (%d / %d)",
							pid_bck, recovered, recovery_target);
				_D("process %d killed in background cgroup", pid_bck);
				recovered += (int)(to_populate*0.4);
				num_victims++;
			}
			break;
		default:
			/* Disable kill_flag for the remaining cgroups */
			kill_flag = 0;
		}

		ret = check_cgroup_kill_status(TEST_PROACTIVE_KILLER, memcg_index, kill_flag,
						recovery_target, &recovered,
						num_max_victims, &num_victims);
		if (ret != ERROR_NONE)
			ret_val = ret;
	}
	return ret_val;
}

/* Test function for the oom dbus trigger interface of resourced */
int oom_dbus_trigger(void)
{
	int num_max_victims, num_victims;
	int recovered, recovery_target;
	int memcg_index, memconf;
	int ret, ret_val, kill_flag;
	struct timespec req, rem;
	char inp_str[STRING_MAX];

	memconf = get_memconf(kBtoMB(procfs_get_total()));

	/* Wait for input signalling call to oom trigger dbus handler */
	printf("Enter input (to continue) after sending oom trigger dbus signal to resourced: ");
	ret = scanf("%s", inp_str);
	_D("going to sleep for %d seconds before testing output scenario\n\n\n\n", PROACTIVE_SLEEP);
	req.tv_sec = PROACTIVE_SLEEP;
	req.tv_nsec = 0;
	nanosleep(&req, &rem);

	/* There is no target for recovery. All eligible processes in the swap
	 * and background cgroups are expected to be killed irrespective of recovered
	 * memory. Thus recovery_target is set to the total available memory on the target.
	 */
	ret_val = ERROR_NONE;
	recovery_target = vmpressure_limits[memconf][LIMIT_TOTAL_MEMORY];
	recovered = 0;
	num_max_victims = RESOURCED_MAX_VICTIMS;
	num_victims = 0;
	for (memcg_index = MEMCG_MAX-1; memcg_index >= MEMCG_FOREGROUND; --memcg_index) {
		_D("checking %s cgroup", memcg_name[memcg_index]);

		/* kill flag is enabled only for swap and background cgroups */
		switch (memcg_index) {
		case MEMCG_SWAP:
		case MEMCG_BACKGROUND:
			kill_flag = 1;
			break;
		default:
			kill_flag = 0;
			break;
		}

		ret = check_cgroup_kill_status(TEST_OOM_DBUS_TRIGGER, memcg_index, kill_flag,
						recovery_target, &recovered,
						num_max_victims, &num_victims);
		if (ret != ERROR_NONE)
			ret_val = ret;
	}
	return ret_val;
}

/* Test function to test the memory pressure interface of resourced */
int vmpressure_root(int test)
{
	int ret, ret_val;
	struct timespec req, rem;
	int available, prev_available, memconf;
	int recovery_target, recovered;
	int num_max_victims, num_victims, kill_flag;
	int memcg_index;
	char inp_str[STRING_MAX];

	memconf = get_memconf(kBtoMB(procfs_get_total()));

	/* Instructions to trigger the memory pressure eventfd */
	_D("open an app on the target now. this would start the callback for medium pressure");
	_D("ToDo: check why the eventfd on memory pressure is not triggered earlier");

	/* If the test is to check the working at the first call (without callback) */
	if (test == TEST_VMPRESSURE_ROOT) {
		ret_val = ERROR_NONE;

		/* Input as soon as you see oom killer thread related messages on the dlog
		 * of resourced. We wait for VMPRESSURE_ROOT_SLEEP seconds to ensure that the
		 * thread has completed.
		 */
		printf("Enter input (to continue) after oom killer has run once: ");
		ret = scanf("%s", inp_str);
		_D("going to sleep for %d seconds before testing output scenario\n\n\n\n", VMPRESSURE_ROOT_SLEEP);
		req.tv_sec = VMPRESSURE_ROOT_SLEEP;
		req.tv_nsec = 0;
		nanosleep(&req, &rem);

		/* Check if the target (threshold leave) has been reached, and if not
		 * set the recovery target according to the available memory before the killer ran
		 * and the threshold leave for the memory configuration
		 */
		available = kBtoMB(procfs_get_available());
		if (available >= vmpressure_limits[memconf][LIMIT_THRESHOLD_LEAVE])
			_D("threshold leave %dMB reached as expected, available %dMB",
					vmpressure_limits[memconf][LIMIT_THRESHOLD_LEAVE],
					available);
		else
			_E("threshold leave %dMB not reached, available %dMB",
					vmpressure_limits[memconf][LIMIT_THRESHOLD_LEAVE],
					available);

		prev_available = vmpressure_limits[memconf][LIMIT_THRESHOLD_MEDIUM] - memory_margin[memconf][MEMORY_MARGIN_HIGH];
		recovery_target = vmpressure_limits[memconf][LIMIT_THRESHOLD_LEAVE] - prev_available;
		recovery_target += memory_margin[memconf][MEMORY_MARGIN_MEDIUM];
		recovered = 0;
		for (memcg_index = MEMCG_MAX-1; memcg_index >= MEMCG_MEMORY; --memcg_index) {
			_D("checking %s cgroup", memcg_name[memcg_index]);

			/* OOM killer kills from all cgroups, until the recovery target is met
			 * The max victims limit is reset for each cgroup (kills from one cgroup
			 * do not propogate to the count of another cgroup)
			 */
			kill_flag = 1;
			num_victims = 0;
			num_max_victims = vmpressure_limits[memconf][LIMIT_MAX_VICTIMS];
			ret = check_cgroup_kill_status(test, memcg_index, kill_flag,
						recovery_target, &recovered,
						num_max_victims, &num_victims);
			if (ret != ERROR_NONE)
				ret_val = ret;
		}
	} else {
		int i, pid_list_num;
		int oom;

		ret_val = ERROR_NONE;

		/* Input after you see that the oom killer thread has started to run
		 * We let the first run go through and check for reach of the target
		 */
		printf("Enter input (to continue) after the oom killer has started running: ");
		ret = scanf("%s", inp_str);

		available = kBtoMB(procfs_get_available());
		if (available >= vmpressure_limits[memconf][LIMIT_THRESHOLD_LEAVE])
			_E("threshold leave %dMB should not yet be reached, available %dMB",
					vmpressure_limits[memconf][LIMIT_THRESHOLD_LEAVE],
					available);
		else
			_D("threshold leave %dMB not reached as expected, available %dMB",
					vmpressure_limits[memconf][LIMIT_THRESHOLD_LEAVE],
					available);
		recovery_target = vmpressure_limits[memconf][LIMIT_THRESHOLD_LEAVE] - available;
		recovery_target += memory_margin[memconf][MEMORY_MARGIN_MEDIUM];
		recovered = 0;
		for (memcg_index = MEMCG_MAX-1; memcg_index >= MEMCG_MEMORY; --memcg_index) {
			_D("checking %s cgroup", memcg_name[memcg_index]);

			/* OOM killer kills from all cgroups until the recovery target is met
			 * The max # of victims is reset for each cgroup
			 * Due to the oom scores of the processes created in base usage for this test
			 * there should not be major kills and thus the target is not going to be reached.
			 */
			kill_flag = 1;
			num_victims = 0;
			num_max_victims = vmpressure_limits[memconf][LIMIT_MAX_VICTIMS];
			ret = check_cgroup_kill_status(test, memcg_index, kill_flag,
					recovery_target, &recovered,
					num_max_victims, &num_victims);
		}

		/* Since the target has not been reached, we now test the working of the callback.
		 * We change the oom scores of the processes launched in create_base_usage to +ve
		 * values and check if the callback kills these processes until the conditions are met
		 */
		_D("changing oom score adj of processes appropriately");
		for (memcg_index = MEMCG_MAX-1; memcg_index >= MEMCG_MEMORY; --memcg_index) {
			pid_list_num = memcg_base_process_num[test][memcg_index];
			if (!pid_list_num)
				continue;

			/* If the max oom of the cgroup is -ve then continue without changing
			 * (case of important cgroup)
			 */
			oom = memcg_base_process_oom[test][memcg_index][pid_list_num-1];
			if (oom < 0)
				continue;
			/* Else change the oom scores of all processes in the cgroup to the max value */
			for (i = pid_list_num-2; i >= 0; --i) {
				if (memcg_base_process_oom[test][memcg_index][i] > 0)
					continue;
				else {
					ret = procfs_set_oom_score_adj(pid_list[memcg_index][i], oom);
					if (ret == ERROR_NONE)
						memcg_base_process_oom[test][memcg_index][i] = oom;
				}
			}
		}

		/* Wait for some time to get the medium pressure callback to do its work */
		_D("going to sleep for %d seconds before testing output scenario\n\n\n\n", VMPRESSURE_ROOT_CB_SLEEP);
		req.tv_sec = VMPRESSURE_ROOT_CB_SLEEP;
		req.tv_nsec = 0;
		nanosleep(&req, &rem);

		/* Now recheck all the cgroups for proper kills */
		recovered = 0;
		for (memcg_index = MEMCG_MAX-1; memcg_index >= MEMCG_MEMORY; --memcg_index) {
			_D("checking %s cgroup", memcg_name[memcg_index]);

			kill_flag = 1;
			num_victims = 0;
			num_max_victims = vmpressure_limits[memconf][LIMIT_MAX_VICTIMS];
			ret = check_cgroup_kill_status(test, memcg_index, kill_flag,
					recovery_target, &recovered,
					num_max_victims, &num_victims);
			if (ret != ERROR_NONE)
				ret_val = ret;
		}
	}
	return ret_val;
}

/* Creates base usage scenario (i.e. creates processes taking up
 * certain amounts of memory) before the respective test function
 * proceeds to test for the actions in resourced memory module
 * This way helps to create usage on the target and simultaneously keep
 * track of the status of the processes (created in this scenario)
 */
int create_base_usage(int test)
{
	int available, limit;
	int memconf;
	int i, to_populate;
	struct timespec req, rem;

	/* Get memory configuration and current available memory
	 * Base usage creation is dependent on memory configuration
	 */
	memconf = get_memconf(kBtoMB(procfs_get_total()));
	_I("%s: Memory configuration is %d", test_name[test], memconf);

	available = kBtoMB(procfs_get_available());

	/* Find out the memory size to be populated accordingly for the test
	 * and then usage populate_cgroup to create processes and populate the
	 * cgroups. These processes are going to be tracked in the test functions
	 * The return value is dependent on successful creation of the processes
	 */
	switch (test) {
	case TEST_PROACTIVE_KILLER:
		to_populate = available - vmpressure_limits[memconf][LIMIT_THRESHOLD_LOW];
		to_populate += memory_margin[memconf][MEMORY_MARGIN_LOW];
		limit = vmpressure_limits[memconf][LIMIT_THRESHOLD_LOW];

		break;
	case TEST_OOM_DBUS_TRIGGER:
		to_populate = available - vmpressure_limits[memconf][LIMIT_THRESHOLD_MEDIUM];
		to_populate -= memory_margin[memconf][MEMORY_MARGIN_HIGH];
		limit = vmpressure_limits[memconf][LIMIT_THRESHOLD_MEDIUM];

		break;
	case TEST_VMPRESSURE_ROOT:
	case TEST_VMPRESSURE_ROOT_CB:
		to_populate = available - vmpressure_limits[memconf][LIMIT_THRESHOLD_MEDIUM];
		to_populate += memory_margin[memconf][MEMORY_MARGIN_HIGH];
		limit = vmpressure_limits[memconf][LIMIT_THRESHOLD_MEDIUM];

		break;
	default:
		_E("Invalid input");
		return ERROR_INVALID_INPUT;
	}

	if (to_populate < 0) {
		_E("%s: Base usage cannot be created. Not enough memory (%d/%d MB)",
				test_name[test], to_populate, available);
		return ERROR_MEMORY;
	} else
		_D("%s: Available %d MB, Base usage to populate %d MB",
				test_name[test], available, to_populate);

	for (i = 0; i < MEMCG_MAX; ++i)
		populate_cgroup(test, i, to_populate);

	req.tv_sec = 3;
	req.tv_nsec = 0;
	nanosleep(&req, &rem);

	available = kBtoMB(procfs_get_available());

	_I("%s: revised available memory is: %d MB, limit is: %d MB",
			test_name[test], available, limit);

	return ERROR_NONE;
}

/* Runs the needed sequence of tests for the input test
 * Refer to the README in the memory submodule to understand the
 * checks conducted in each test
 */
int run_test(int test)
{
	int  ret;

	/* Create the base usage scenario before proceeding to test for
	 * correct working of memory module in resourced
	 */
	ret = create_base_usage(test);
	if (ret != ERROR_NONE) {
		_E("%s: Not able to create base usage. Error %d", test_name[test], ret);
		return ret;
	}

	/* After base usage scenario was created successfully, test
	 * the working of memory module by calling the appropriate test function
	 */
	switch (test) {
	case TEST_PROACTIVE_KILLER:
		ret = proactive_oom_killer();
		break;
	case TEST_OOM_DBUS_TRIGGER:
		ret = oom_dbus_trigger();
		break;
	case TEST_VMPRESSURE_ROOT:
	case TEST_VMPRESSURE_ROOT_CB:
		ret = vmpressure_root(test);
		break;
	default:
		_E("Invalid input");
		return ERROR_INVALID_INPUT;
	}
	if (ret != ERROR_NONE)
		_E("%s: Error running test", test_name[test]);
	else
		_I("%s: Test successfully completed", test_name[test]);

	return ERROR_NONE;
}

/* Usage function */
void usage(void)
{
	printf("Usage: resourced_memory_test <test>\n");
	printf("\tSupported tests:\n");
	printf("\t\tproactive : tests proactive oom killer (called before launching new apps)\n");
	printf("\t\toom_trigger : tests oom trigger dbus signal handler\n");
	printf("\t\tvmpressure_root : tests oom killer when pressure level builds up\n");
	printf("\t\tvmpressure_root_cb : tests oom killer callback when pressure level builds up\n");
	printf("\t\tvmpressure_cgroup : tests oom killer when pressure level of cgroup builds up\n");
}

/* Test program for memory module of resourced.
 * Usage given in usage() function
 */
int main(int argc, char *argv[])
{
	int i;
	char inp_str[STRING_MAX];

	/* This is done so as to provide an opportunity to start a journalctl
	 * session following only this pid
	 */
	printf("Running as pid %d\n", getpid());
	printf("Enter input after starting journalctl: ");
	i = scanf("%s", inp_str);

	/* Invalid argument */
	if (argc < 2) {
		_E("Usage not correct!");
		usage();
		return 0;
	}

	/* Find out the test mentioned as input and run the test (calling run_test) */
	for (i = 0; i < TEST_MAX; ++i) {
		if (!strncmp(argv[1], test_name[i], strlen(argv[1]))) {
			printf("%s selected. Shifting to journalctl for messages\n", test_name[i]);
			_I("%s selected", test_name[i]);
			run_test(i);
			break;
		}
	}

	/* Invalid argument */
	if (i == TEST_MAX) {
		_E("Usage not correct!");
		usage();
	}

	return 0;
}

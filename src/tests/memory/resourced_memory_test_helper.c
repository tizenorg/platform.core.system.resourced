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
 * @file  resourced_memory_test_helper.c
 * @desc  helper functions for memory test program
 **/

#include "resourced_memory_test.h"
#include "utils.h"

#define DEFAULT_PAGE_SIZE 4
#define DEFAULT_SLEEP_TIME 4000

/* Get the memory configuration (in terms of the MEMCONF_* enum)
 * on the basis of the total memory of the system (given by input
 * arg total_memory).
 * Currently on 750MB configuration is supported (MEMCONF_768)
 */
int get_memconf(int total_memory)
{
	return MEMCONF_768;
}

/* Launches memory hogging processes of size memory, with oom
 * adj score as oom and charged to the cgroup with path cgroup_path
 */
int launch_memory_hogger(int memory, int oom, char *cgroup_path)
{
	pid_t pid;

	pid = fork();

	/* If error return pid immediately */
	if (pid < 0)
		return pid;
	else if (!pid) {
		/* Memory hogger process */
		int ret;
		char *mem_alloc;
		char oom_path[STRING_MAX];
		int page_size = KBtoB(DEFAULT_PAGE_SIZE);
		unsigned long memory_size = MBtoB(memory);
		unsigned long memory_alloted = 0;

		/* Make this process the head of its own process group */
		ret = setpgid(getpid(), 0);
		if (ret)
			_E("failed to separate current process into its own process group");

		/* Writing the oom score to the oom_score_adj file of the process
		 * If this fails, then the process finishes immediately
		 */
		snprintf(oom_path, sizeof(oom_path), "/proc/%d/oom_score_adj", getpid());
		ret = fwrite_int(oom_path, oom);
		if (ret != ERROR_NONE) {
			_E("IO: Error writing oom %d of pid %d", oom, pid);
			return 0;
		}

		/* Allocate memory upto target size in pages
		 * Tinker with these pages so that the memory is actually allocated
		 * Sleep for DEFAULT_SLEEP_TIME seconds (to simulate app use time lifecycle)
		 */
		while (memory_alloted < memory_size) {
			mem_alloc = (char *)malloc(page_size);
			if (!mem_alloc) {
				_E("IO: Process %d not able to allocate memory after %d Bytes (target %d)",
						getpid(), (int)memory_alloted, (int)memory_size);
				break;
			}

			/* Random arithmetic */
			mem_alloc[0] = memory_alloted % 128;
			mem_alloc[page_size-1] = memory_alloted % 123;

			memory_alloted += page_size;
		}
		sleep(DEFAULT_SLEEP_TIME);

		return 0;
	} else {
		/* Resourced memory tests process */
		int ret;

		/* Writing pid to the cgroup. Error returned if this fails. */
		ret = fwrite_int(cgroup_path, (int)pid);
		if (ret != ERROR_NONE) {
			_E("IO: Not able to write %d to %s", pid, cgroup_path);
			return ret;
		}

		return pid;
	}
}

/* Starts processes in the memory cgroup (specified by memcg_index) for
 * the memory test (specified by test) as specified by the memcg_* arrays.
 * The memory to be allocated (specified by target and the memcg_base_usage_ratio
 * array) to the cgroup is equally distributed among all the processes started.
 */
void populate_cgroup(int test, int memcg_index, int target)
{
	int i;
	int proc_num, proc_oom, proc_memory;
	int pid;
	int charged_memory;
	char cgroup_path[STRING_MAX];

	/* proc_num number of processes will be started */
	proc_num = memcg_base_process_num[test][memcg_index];
	if (!proc_num)
		return;

	/* charged_memory MB of memory will be distributed among proc_num processes */
	charged_memory = (int)((double)target * memcg_base_usage_ratio[test][memcg_index]);
	/* ToDo: Make process memory calculation variable */
	proc_memory = charged_memory/proc_num;

	if (!memcg_index)
		snprintf(cgroup_path, sizeof(cgroup_path), "%s/cgroup.procs", MEMCG_ROOT);
	else
		snprintf(cgroup_path, sizeof(cgroup_path), "%s/%s/cgroup.procs", MEMCG_ROOT, memcg_name[memcg_index]);

	/* Launch proc_num processes */
	for (i = 0; i < proc_num; ++i) {
		proc_oom = memcg_base_process_oom[test][memcg_index][i];
		pid = launch_memory_hogger(proc_memory, proc_oom, cgroup_path);

		/* If an error is encountered while launching the processes, log it
		 * But the pid is still stored in the pid_list array (to keep track
		 * of which processes to track in the output scenario)
		 */
		if (pid < 0)
			_E("%s: Failed to launch %d process (cgroup: %s ; oom:%d ; memory:%dMB)",
					test_name[test], i, memcg_name[memcg_index], proc_oom, proc_memory);
		else
			_D("%s: Launched process %d (cgroup: %s ; oom: %d ; memory: %dMB)",
					test_name[test], pid, memcg_name[memcg_index], proc_oom, proc_memory);
		pid_list[memcg_index][i] = pid;
		pid_memory_list[memcg_index][i] = proc_memory;
	}
}

/* Checks for status of kills in the input cgroup (memcg_index), depending on the test,
 * kill flag of the cgroup (kill_flag), target for recovery (recovery_target),
 * amount of recovered memory till now (recovered), # of victims killed (num_victims)
 * against the max # of victims allowed to be killed (num_max_victims)
 */
int check_cgroup_kill_status(int test, int memcg_index, int kill_flag,
				int recovery_target, int *recovered,
				int num_max_victims, int *num_victims)
{
	int i, ret, ret_val;
	int curr_pid, pid_list_num, oom;

	/* For all processes start in create_base_usage for this cgroup
	 * Check if they are killed/not killed and output error/debug messages
	 * according to the condition (code and log msgs are self-explanatory)
	 */
	ret_val = ERROR_NONE;
	pid_list_num = memcg_base_process_num[test][memcg_index];
	for (i = pid_list_num-1; i >= 0; --i) {
		curr_pid = pid_list[memcg_index][i];
		if (curr_pid >= 0) {
			ret = pid_exists(curr_pid);
			oom = memcg_base_process_oom[test][memcg_index][i];
			if (!ret) {
				ret = ERROR_FAIL;
				if (!kill_flag)
					_E("process %d (oom: %d) should not be killed (%d / %d ; killflag)",
							curr_pid, oom, *recovered, recovery_target);
				else if (oom < 0)
					_E("process %d (oom: %d) should not be killed (%d / %d ; oom)",
							curr_pid, oom, *recovered, recovery_target);
				else if (*recovered >= recovery_target)
					_E("process %d (oom: %d) should not be killed (%d / %d ; target met)",
							curr_pid, oom, *recovered, recovery_target);
				else if (*num_victims >= num_max_victims)
					_E("process %d (oom: %d) should not be killed (%d / %d ; max victims)",
							curr_pid, oom, *recovered, recovery_target);
				else {
					_D("process %d (oom: %d) killed as expected (%d / %d)",
							curr_pid, oom, *recovered, recovery_target);
					ret = ERROR_NONE;
				}

				*recovered = *recovered + pid_memory_list[memcg_index][i];
				*num_victims = *num_victims + 1;
			} else {
				ret = ERROR_NONE;
				if (!kill_flag)
					_D("process %d (oom: %d) not killed as expected (%d / %d ; killflag)",
							curr_pid, oom, *recovered, recovery_target);
				else if (oom < 0)
					_D("process %d (oom: %d) not killed as expected (%d / %d ; oom)",
							curr_pid, oom, *recovered, recovery_target);
				else if (*recovered >= recovery_target)
					_D("process %d (oom: %d) not killed as expected (%d / %d ; target met)",
							curr_pid, oom, *recovered, recovery_target);
				else if (*num_victims >= num_max_victims)
					_D("process %d (oom: %d) not killed as expected (%d / %d ; max victims)",
							curr_pid, oom, *recovered, recovery_target);
				else {
					_E("process %d (oom: %d) expected to be killed (%d / %d)",
							curr_pid, oom, *recovered, recovery_target);
					ret = ERROR_FAIL;
				}
			}
			if (ret != ERROR_NONE)
				ret_val = ret;
		}
	}
	return ret_val;
}

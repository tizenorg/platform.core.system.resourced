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
 * @file  utils.c
 * @desc  file IO and proc fs related functions
 **/

#include <errno.h>
#include "utils.h"

#define MEM_AVAILABLE "MemAvailable"
#define MEM_TOTAL "MemTotal"
#define MEM_FREE "MemFree"
#define MEM_CACHED "Cached"

/* File IO abstract function
 * Writes the string (in str) to the file (with path as path)
 */
int fwrite_str(char *path, char *str)
{
	int ret;
	FILE *file;

	file = fopen(path, "w");
	if (!file) {
		_E("IO: Error opening file %s", path);
		return ERROR_IO;
	}

	ret = fputs(str, file);
	fclose(file);

	if (ret < 0)
		return ERROR_IO;
	else
		return ERROR_NONE;
}

/* File IO abstract function
 * Writes the integer (in num) to the file (with path as path)
 * Uses fwrite_str to accomplish the task
 */
int fwrite_int(char *path, int num)
{
	char content_str[STRING_MAX];

	snprintf(content_str, sizeof(content_str), "%d", num);
	return fwrite_str(path, content_str);
}

/* Proc fs util function to get the available (usable) memory in the system
 * Scans the /proc/meminfo file and returns the value of the field MemAvailable
 * The value returned is in kB (1000 bytes)
 */
unsigned int procfs_get_available(void)
{
	char buf[STRING_MAX];
	FILE *fp;
	unsigned int available = 0;
	unsigned int free, cached;

	free = cached = 0;

	fp = fopen("/proc/meminfo", "r");

	if (!fp) {
		_E("IO: Failed to open /proc/meminfo");
		return available;
	}

	while (fgets(buf, STRING_MAX, fp) != NULL) {
		if (!strncmp(buf, MEM_FREE, strlen(MEM_FREE))) {
			if (sscanf(buf, "%*s %d kB", &free) != 1) {
				_E("IO: Failed to get free memory from /proc/meminfo");
				free = 0;
			}
		} else if (!strncmp(buf, MEM_CACHED, strlen(MEM_CACHED))) {
			if (sscanf(buf, "%*s %d kB", &cached) != 1) {
				_E("IO: Failed to get cached memory from /proc/meminfo");
				cached = 0;
			}
		} else if (!strncmp(buf, MEM_AVAILABLE, strlen(MEM_AVAILABLE))) {
			if (sscanf(buf, "%*s %d kB", &available) != 1) {
				_E("IO: Failed to get available memory from /proc/meminfo");
				available = 0;
			}
			break;
		}
	}

	if (!available && (free && cached))
		available = free + cached;

	fclose(fp);

	return available;
}

/* Proc fs util function to get the total memory in the system
 * Scans the /proc/meminfo file and returns the value of the field MemTotal.
 * The value returned is in kB (1000 bytes)
 */
unsigned int procfs_get_total(void)
{
	char buf[STRING_MAX];
	FILE *fp;
	unsigned int total = 0;

	fp = fopen("/proc/meminfo", "r");

	if (!fp) {
		_E("IO: Failed to open /proc/meminfo");
		return total;
	}

	while (fgets(buf, STRING_MAX, fp) != NULL) {
		if (!strncmp(buf, MEM_TOTAL, strlen(MEM_TOTAL))) {
			if (sscanf(buf, "%*s %d kB", &total) != 1) {
				_E("IO: Failed to get total memory from /proc/meminfo");
				total = 0;
			}
			break;
		}
	}
	fclose(fp);

	return total;
}

/* Proc fs util function to set oom score adj (given by oom) of
 * the process (with id pid)
 */
int procfs_set_oom_score_adj(int pid, int oom)
{
	int ret;
	char name[STRING_MAX];

	snprintf(name, sizeof(name), "/proc/%d/oom_score_adj", pid);
	ret = fwrite_int(name, oom);
	if (ret != ERROR_NONE)
		_E("IO: Not able to change oom score of process %d", pid);
	return ret;
}

/* Finds out if the process with input pid is still running.
 * Uses the existence of the respective /proc/<pid>/ directory
 * to find if the process is running.
 */
int pid_exists(int pid)
{
	char name[STRING_MAX];

	/* If the file /proc/pid/cmdline cannot be accessed, the process does not exist */
	snprintf(name, sizeof(name), "/proc/%d/stat", pid);
	if (access(name, F_OK)) {
		return 0;
	} else {
		/* Zombie processes which are not accounted for by the parent processes
		 * still retain their /proc/pid/ directory until the parent processes dies
		 * So we check the process status field of the stat file to see if the process
		 * is either in Z (zombie) or X/x (killed) state
		 * If the process is in either of these states, then it is not running.
		 * Otherwise the process exists
		 */
		FILE *stat_fp;
		int ret;
		char proc_stat;

		stat_fp = fopen(name, "r");
		if (!stat_fp)
			return 0;
		else {
			while (fgets(name, sizeof(name), stat_fp) != NULL) {
				if (sscanf(name, "%*d %*s %c", &proc_stat) != 1)
					ret = 0;
				else if (proc_stat == 'Z' || proc_stat == 'X' || proc_stat == 'x')
					ret = 0;
				else
					ret = 1;
			}
			fclose(stat_fp);
			return ret;
		}
	}
}


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
 * @file procfs.c
 *
 * @desc communicate with procfs in resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "resourced.h"
#include "trace.h"
#include "macro.h"
#include "util.h"
#include "procfs.h"
#include "proc-common.h"
#include "lowmem-common.h"
#include "module.h"

#define PAGE_SIZE_KB 4

static struct sys_node_table sys_node_tables[] = {
	{ SYS_VM_SHRINK_MEMORY, "/proc/sys/vm/shrink_memory", 1, 1 },
	{ SYS_VM_COMPACT_MEMORY, "/proc/sys/vm/compact_memory", 1, 1 },
	{ },
};

int proc_get_cmdline(pid_t pid, char *cmdline)
{
	char buf[PROC_BUF_MAX];
	char cmdline_buf[PROC_NAME_MAX];
	char *filename;
	FILE *fp;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fgets(cmdline_buf, PROC_NAME_MAX-1, fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);

	filename = strrchr(cmdline_buf, '/');
	if (filename == NULL)
		filename = cmdline_buf;
	else
		filename = filename + 1;

	strncpy(cmdline, filename, PROC_NAME_MAX-1);

	return RESOURCED_ERROR_NONE;
}

pid_t find_pid_from_cmdline(char *cmdline)
{
	pid_t pid = -1, foundpid = -1;
	int ret = 0;
	DIR *dp;
	struct dirent dentry;
	struct dirent *result;
	char appname[PROC_NAME_MAX];

	dp = opendir("/proc");
	if (!dp) {
		_E("BACKGRD MANAGE : fail to open /proc");
		return RESOURCED_ERROR_FAIL;
	}
	while (!readdir_r(dp, &dentry, &result) && result != NULL) {
		if (!isdigit(dentry.d_name[0]))
			continue;

		pid = atoi(dentry.d_name);
		if (!pid)
			continue;
		ret = proc_get_cmdline(pid, appname);
		if (ret == RESOURCED_ERROR_NONE) {
			if (!strncmp(cmdline, appname, strlen(appname)+1)) {
				foundpid = pid;
				break;
			}
		}
	}
	closedir(dp);
	return foundpid;
}

int proc_get_oom_score_adj(int pid, int *oom_score_adj)
{
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};
	FILE *fp = NULL;

	if (pid < 0)
		return RESOURCED_ERROR_FAIL;

	snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
	fp = fopen(buf, "r");

	if (fp == NULL) {
		_E("fopen %s failed", buf);
		return RESOURCED_ERROR_FAIL;
	}
	if (fgets(buf, sizeof(buf), fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	(*oom_score_adj) = atoi(buf);
	fclose(fp);
	return RESOURCED_ERROR_NONE;
}

int proc_set_oom_score_adj(int pid, int oom_score_adj)
{
	FILE *fp;
	struct lowmem_data_type lowmem_data;
	static const struct module_ops *lowmem;
	char buf[sizeof(PROC_OOM_SCORE_ADJ_PATH) + MAX_DEC_SIZE(int)] = {0};

	snprintf(buf, sizeof(buf), PROC_OOM_SCORE_ADJ_PATH, pid);
	fp = fopen(buf, "r+");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;
	if (fgets(buf, sizeof(buf), fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fprintf(fp, "%d", oom_score_adj);
	fclose(fp);

	if (!lowmem) {
		lowmem = find_module("lowmem");
		if (!lowmem)
			return RESOURCED_ERROR_FAIL;
	}
	if (lowmem && (oom_score_adj >= OOMADJ_SU)) {
		lowmem_data.control_type = LOWMEM_MOVE_CGROUP;
		lowmem_data.args[0] = (int)pid;
		lowmem_data.args[1] = (int)oom_score_adj;
		lowmem->control(&lowmem_data);
	}

	return RESOURCED_ERROR_NONE;
}

int proc_get_label(pid_t pid, char *label)
{
	char buf[PROC_BUF_MAX];
	FILE *fp;

	snprintf(buf, sizeof(buf), "/proc/%d/attr/current", pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fgets(label, PROC_NAME_MAX-1, fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);
	return RESOURCED_ERROR_NONE;
}

int proc_get_mem_usage(pid_t pid, unsigned int *vmsize, unsigned int *vmrss)
{
	char buf[PROC_BUF_MAX];
	char statm_buf[PROC_NAME_MAX];
	unsigned int size, rss;
	FILE *fp;


	snprintf(buf, sizeof(buf), "/proc/%d/statm", pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fgets(statm_buf, PROC_NAME_MAX-1, fp) == NULL) {
		fclose(fp);
		return RESOURCED_ERROR_FAIL;
	}
	fclose(fp);

	if (sscanf(statm_buf, "%u %u", &size, &rss) < 2)
		return RESOURCED_ERROR_FAIL;

	if (vmsize != NULL)
		*vmsize = size*PAGE_SIZE_KB;
	if (vmrss != NULL)
		*vmrss = rss*PAGE_SIZE_KB;

	return RESOURCED_ERROR_NONE;
}

unsigned int proc_get_mem_available(void)
{
	struct meminfo mi;
	int r;
	char buf[256];

	r = proc_get_meminfo(&mi, MEMINFO_MASK_MEM_AVAILABLE);
	if (r < 0) {
		_E("Failed to get %s: %s",
				meminfo_id_to_string(MEMINFO_ID_MEM_AVAILABLE),
				strerror_r(-r, buf, sizeof(buf)));
		return 0;
	}

	return KBYTE_TO_MBYTE(mi.value[MEMINFO_ID_MEM_AVAILABLE]);
}

unsigned int proc_get_swap_free(void)
{
	struct meminfo mi;
	int r;
	char error_buf[256];

	r = proc_get_meminfo(&mi, MEMINFO_MASK_SWAP_FREE);
	if (r < 0) {
		_E("Failed to get %s: %s",
		   meminfo_id_to_string(MEMINFO_ID_SWAP_FREE),
		   strerror_r(-r, error_buf, sizeof(error_buf)));
		return 0;
	}

	return mi.value[MEMINFO_ID_SWAP_FREE];
}

int proc_get_cpu_time(pid_t pid, unsigned long *utime,
		unsigned long *stime)
{
	char proc_path[sizeof(PROC_STAT_PATH) + MAX_DEC_SIZE(int)];
	_cleanup_fclose_ FILE *fp = NULL;

	assert(utime != NULL);
	assert(stime != NULL);

	snprintf(proc_path, sizeof(proc_path), PROC_STAT_PATH, pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return RESOURCED_ERROR_FAIL;

	if (fscanf(fp, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s") < 0)
		return RESOURCED_ERROR_FAIL;

	if (fscanf(fp, "%lu %lu", utime, stime) < 1)
		return RESOURCED_ERROR_FAIL;

	return RESOURCED_ERROR_NONE;
}

unsigned int proc_get_cpu_number(void)
{
	char buf[PATH_MAX];
	FILE *fp;
	int cpu = 0;

	fp = fopen("/proc/cpuinfo", "r");

	if (!fp) {
		_E("/proc/cpuinfo open failed");
		return RESOURCED_ERROR_FAIL;
	}

	while (fgets(buf, PATH_MAX, fp) != NULL) {
		if (!strncmp(buf, "processor", 9))
			cpu++;
	}

	fclose(fp);
	return cpu;
}

int proc_get_exepath(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];
	int ret = 0;

	snprintf(path, sizeof(path), "/proc/%d/exe", pid);
	ret = readlink(path, buf, len-1);
	if (ret > 0)
		buf[ret] = '\0';
	else
		buf[0] = '\0';
	return RESOURCED_ERROR_NONE;
}

static int proc_get_data(char *path, char *buf, int len)
{
	_cleanup_close_ int fd = -1;
	int ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return RESOURCED_ERROR_FAIL;

	ret = read(fd, buf, len-1);
	if (ret < 0) {
		buf[0] = '\0';
		return RESOURCED_ERROR_FAIL;
	}
	buf[ret] = '\0';
	return RESOURCED_ERROR_NONE;
}

int proc_get_raw_cmdline(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];
	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	return proc_get_data(path, buf, len);
}

int proc_get_stat(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	return proc_get_data(path, buf, len);
}

int proc_get_status(pid_t pid, char *buf, int len)
{
	char path[PROC_BUF_MAX];
	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	return proc_get_data(path, buf, len);
}

int proc_sys_node_trigger(enum sys_node_id sys_node_id)
{
	FILE *fp = NULL;
	char error_buf[256];

	if (sys_node_id >= ARRAY_SIZE(sys_node_tables)) {
		_E("sys_node_id[%d] is out of range.\n", sys_node_id);
		return RESOURCED_ERROR_FAIL;
	}
	if (!sys_node_tables[sys_node_id].valid) {
		_E("sys_node_id[%d] is not valid.\n", sys_node_id);
		return RESOURCED_ERROR_FAIL;
	}

	/* open and check if the path exists, else return fail */
	fp = fopen(sys_node_tables[sys_node_id].path, "w");
	if (fp == NULL) {
		_E("Failed to open: %s: %s\n",
			sys_node_tables[sys_node_id].path,
			strerror_r(errno, error_buf, sizeof(error_buf)));
		sys_node_tables[sys_node_id].valid = 0;
		return RESOURCED_ERROR_FAIL;
	}
	fputc(sys_node_tables[sys_node_id].value, fp);
	fclose(fp);
	return RESOURCED_ERROR_NONE;
}

static const char* const meminfo_string_lookup[MEMINFO_ID_MAX] = {
	[MEMINFO_ID_MEM_TOTAL]	   = "MemTotal",
	[MEMINFO_ID_MEM_FREE]	   = "MemFree",
	[MEMINFO_ID_MEM_AVAILABLE] = "MemAvailable",
	[MEMINFO_ID_BUFFERS]	   = "Buffers",
	[MEMINFO_ID_CACHED]	   = "Cached",
	[MEMINFO_ID_SWAP_CACHED]   = "SwapCached",
	[MEMINFO_ID_ACTIVE]	   = "Active",
	[MEMINFO_ID_INACTIVE]	   = "Inactive",
	[MEMINFO_ID_ACTIVE_ANON]   = "Active(anon)",
	[MEMINFO_ID_INACTIVE_ANON] = "Inactive(anon)",
	[MEMINFO_ID_ACTIVE_FILE]   = "Active(file)",
	[MEMINFO_ID_INACTIVE_FILE] = "Inactive(file)",
	[MEMINFO_ID_UNEVICTABLE]   = "Unevictable",
	[MEMINFO_ID_MLOCKED]	   = "Mlocked",
	[MEMINFO_ID_HIGH_TOTAL]	   = "HighTotal",
	[MEMINFO_ID_HIGH_FREE]	   = "HighFree",
	[MEMINFO_ID_LOW_TOTAL]	   = "LowTotal",
	[MEMINFO_ID_LOW_FREE]	   = "LowFree",
	[MEMINFO_ID_SWAP_TOTAL]	   = "SwapTotal",
	[MEMINFO_ID_SWAP_FREE]	   = "SwapFree",
	[MEMINFO_ID_DIRTY]	   = "Dirty",
	[MEMINFO_ID_WRITEBACK]	   = "Writeback",
	[MEMINFO_ID_ANON_PAGES]	   = "AnonPages",
	[MEMINFO_ID_MAPPED]	   = "Mapped",
	[MEMINFO_ID_SHMEM]	   = "Shmem",
	[MEMINFO_ID_SLAB]	   = "Slab",
	[MEMINFO_ID_SRECLAIMABLE]  = "SReclaimable",
	[MEMINFO_ID_SUNRECLAIM]	   = "SUnreclaim",
	[MEMINFO_ID_KERNEL_STACK]  = "KernelStack",
	[MEMINFO_ID_PAGE_TABLES]   = "PageTables",
	[MEMINFO_ID_NFS_UNSTABLE]  = "NFS_Unstable",
	[MEMINFO_ID_BOUNCE]	   = "Bounce",
	[MEMINFO_ID_WRITEBACK_TMP] = "WritebackTmp",
	[MEMINFO_ID_COMMIT_LIMIT]  = "CommitLimit",
	[MEMINFO_ID_COMMITTED_AS]  = "Committed_AS",
	[MEMINFO_ID_VMALLOC_TOTAL] = "VmallocTotal",
	[MEMINFO_ID_VMALLOC_USED]  = "VmallocUsed",
	[MEMINFO_ID_VMALLOC_CHUNK] = "VmallocChunk",
};

const char *meminfo_id_to_string(enum meminfo_id id)
{
	assert(id >= 0 && id < MEMINFO_ID_MAX);

	return meminfo_string_lookup[id];
}

int proc_get_meminfo(struct meminfo *mi, enum meminfo_mask mask)
{
	_cleanup_fclose_ FILE *f = NULL;
	enum meminfo_mask remain_mask = mask;
	char buf[LINE_MAX];

	assert(mi);

	memset(mi, 0x0, sizeof(struct meminfo));

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return -errno;

	if (remain_mask & MEMINFO_MASK_MEM_AVAILABLE)
		remain_mask |= (MEMINFO_MASK_MEM_FREE |
				MEMINFO_MASK_CACHED);

	while (remain_mask) {
		_cleanup_free_ char *k = NULL;
		unsigned int v = 0;
		enum meminfo_id id;
		size_t l;

		if (!fgets(buf, sizeof(buf), f)) {
			if (ferror(f))
				return -errno;
			break;
		}

		l = strcspn(buf, ":");
		if (!l)
			break;

		k = strndup(buf, l);
		if (!k)
			return -ENOMEM;

		id = meminfo_string_to_id(k);
		if (id < 0 || id >= MEMINFO_ID_MAX)
			continue;

		if (!(remain_mask & (1ULL << id)))
			continue;

		remain_mask &= ~((1ULL << id));

		if (sscanf(buf + l + 1, "%d", &v) != 1)
			break;

		mi->value[id] = v;
	}

	if (remain_mask & MEMINFO_MASK_MEM_AVAILABLE) {
		mi->value[MEMINFO_ID_MEM_AVAILABLE] =
			mi->value[MEMINFO_ID_MEM_FREE]
			+ mi->value[MEMINFO_ID_CACHED];

		remain_mask &= ~MEMINFO_MASK_MEM_AVAILABLE;
	}

	if (remain_mask) {
		enum meminfo_id i;

		for (i = 0; i < MEMINFO_ID_MAX; i++)
			if (remain_mask & (1 << i))
				_E("Failed to get meminfo: '%s'",
				   meminfo_id_to_string(i));
	}

	return 0;
}

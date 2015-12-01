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

#ifndef __PROCFS_H__
#define __PROCFS_H__

#include <resourced.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#define OOMADJ_DISABLE			(-1000)
#define OOMADJ_SERVICE_MIN		(-900)
#define OOMADJ_SU			(0)
#define OOMADJ_INIT			(100)
#define OOMADJ_FOREGRD_LOCKED		(150)
#define OOMADJ_FOREGRD_UNLOCKED		(200)
#define OOMADJ_BACKGRD_PERCEPTIBLE	(230)
#define OOMADJ_BACKGRD_LOCKED		(250)
#define OOMADJ_FAVORITE			(270)
#define OOMADJ_BACKGRD_UNLOCKED		(300)
#define OOMADJ_APP_LIMIT		OOMADJ_INIT
#define OOMADJ_APP_MAX			(990)
#define OOMADJ_APP_INCREASE		(30)

/* OOMADJ_SERVICE_DEFAULT is default value for processes PROC_TYPE_SERVICE */
#define OOMADJ_SERVICE_GAP		(10)
#define OOMADJ_SERVICE_DEFAULT		(OOMADJ_BACKGRD_LOCKED - OOMADJ_SERVICE_GAP)

/*
 * OOMADJ_PREVIOUS_DEFAULT is default value for processes that are
 * moved out from foreground cgroup ( >= OOMADJ_BACKGRD_PERCEPTIBLE)
 * but being in a state before background cgroup ( >= OOMADJ_BACKGRD_UNLOCKED).
 * In the middle it is possible to have process in favorite cgroup (== OOMADJ_FAVORITE).
 */
#define OOMADJ_PREVIOUS_GAP		(10)
#define OOMADJ_PREVIOUS_DEFAULT		(OOMADJ_BACKGRD_LOCKED - OOMADJ_PREVIOUS_GAP)
#define OOMADJ_PREVIOUS_FOREGRD	(OOMADJ_FOREGRD_UNLOCKED - OOMADJ_PREVIOUS_GAP)
#define OOMADJ_PREVIOUS_BACKGRD	(OOMADJ_BACKGRD_UNLOCKED - OOMADJ_PREVIOUS_GAP)


#define PROC_OOM_SCORE_ADJ_PATH "/proc/%d/oom_score_adj"
#define PROC_STAT_PATH "/proc/%d/stat"

enum meminfo_id {
	MEMINFO_ID_INVALID = -1,
	MEMINFO_ID_MEM_TOTAL = 0,
	MEMINFO_ID_MEM_FREE,
	MEMINFO_ID_MEM_AVAILABLE,
	MEMINFO_ID_BUFFERS,
	MEMINFO_ID_CACHED,
	MEMINFO_ID_SWAP_CACHED,
	MEMINFO_ID_ACTIVE,
	MEMINFO_ID_INACTIVE,
	MEMINFO_ID_ACTIVE_ANON,
	MEMINFO_ID_INACTIVE_ANON,
	MEMINFO_ID_ACTIVE_FILE,
	MEMINFO_ID_INACTIVE_FILE,
	MEMINFO_ID_UNEVICTABLE,
	MEMINFO_ID_MLOCKED,
	MEMINFO_ID_HIGH_TOTAL,
	MEMINFO_ID_HIGH_FREE,
	MEMINFO_ID_LOW_TOTAL,
	MEMINFO_ID_LOW_FREE,
	MEMINFO_ID_SWAP_TOTAL,
	MEMINFO_ID_SWAP_FREE,
	MEMINFO_ID_DIRTY,
	MEMINFO_ID_WRITEBACK,
	MEMINFO_ID_ANON_PAGES,
	MEMINFO_ID_MAPPED,
	MEMINFO_ID_SHMEM,
	MEMINFO_ID_SLAB,
	MEMINFO_ID_SRECLAIMABLE,
	MEMINFO_ID_SUNRECLAIM,
	MEMINFO_ID_KERNEL_STACK,
	MEMINFO_ID_PAGE_TABLES,
	MEMINFO_ID_NFS_UNSTABLE,
	MEMINFO_ID_BOUNCE,
	MEMINFO_ID_WRITEBACK_TMP,
	MEMINFO_ID_COMMIT_LIMIT,
	MEMINFO_ID_COMMITTED_AS,
	MEMINFO_ID_VMALLOC_TOTAL,
	MEMINFO_ID_VMALLOC_USED,
	MEMINFO_ID_VMALLOC_CHUNK,
	MEMINFO_ID_MAX,
};

enum meminfo_mask {
	MEMINFO_MASK_MEM_TOTAL		= 1ULL << MEMINFO_ID_MEM_TOTAL,
	MEMINFO_MASK_MEM_FREE		= 1ULL << MEMINFO_ID_MEM_FREE,
	MEMINFO_MASK_MEM_AVAILABLE	= 1ULL << MEMINFO_ID_MEM_AVAILABLE,
	MEMINFO_MASK_BUFFERS		= 1ULL << MEMINFO_ID_BUFFERS,
	MEMINFO_MASK_CACHED		= 1ULL << MEMINFO_ID_CACHED,
	MEMINFO_MASK_SWAP_CACHED	= 1ULL << MEMINFO_ID_SWAP_CACHED,
	MEMINFO_MASK_ACTIVE		= 1ULL << MEMINFO_ID_ACTIVE,
	MEMINFO_MASK_INACTIVE		= 1ULL << MEMINFO_ID_INACTIVE,
	MEMINFO_MASK_ACTIVE_ANON	= 1ULL << MEMINFO_ID_ACTIVE_ANON,
	MEMINFO_MASK_INACTIVE_ANON	= 1ULL << MEMINFO_ID_INACTIVE_ANON,
	MEMINFO_MASK_ACTIVE_FILE	= 1ULL << MEMINFO_ID_ACTIVE_FILE,
	MEMINFO_MASK_INACTIVE_FILE	= 1ULL << MEMINFO_ID_INACTIVE_FILE,
	MEMINFO_MASK_UNEVICTABLE	= 1ULL << MEMINFO_ID_UNEVICTABLE,
	MEMINFO_MASK_MLOCKED		= 1ULL << MEMINFO_ID_MLOCKED,
	MEMINFO_MASK_HIGH_TOTAL		= 1ULL << MEMINFO_ID_HIGH_TOTAL,
	MEMINFO_MASK_HIGH_FREE		= 1ULL << MEMINFO_ID_HIGH_FREE,
	MEMINFO_MASK_LOW_TOTAL		= 1ULL << MEMINFO_ID_LOW_TOTAL,
	MEMINFO_MASK_LOW_FREE		= 1ULL << MEMINFO_ID_LOW_FREE,
	MEMINFO_MASK_SWAP_TOTAL		= 1ULL << MEMINFO_ID_SWAP_TOTAL,
	MEMINFO_MASK_SWAP_FREE		= 1ULL << MEMINFO_ID_SWAP_FREE,
	MEMINFO_MASK_DIRTY		= 1ULL << MEMINFO_ID_DIRTY,
	MEMINFO_MASK_WRITEBACK		= 1ULL << MEMINFO_ID_WRITEBACK,
	MEMINFO_MASK_ANON_PAGES		= 1ULL << MEMINFO_ID_ANON_PAGES,
	MEMINFO_MASK_MAPPED		= 1ULL << MEMINFO_ID_MAPPED,
	MEMINFO_MASK_SHMEM		= 1ULL << MEMINFO_ID_SHMEM,
	MEMINFO_MASK_SLAB		= 1ULL << MEMINFO_ID_SLAB,
	MEMINFO_MASK_SRECLAIMABLE	= 1ULL << MEMINFO_ID_SRECLAIMABLE,
	MEMINFO_MASK_SUNRECLAIM		= 1ULL << MEMINFO_ID_SUNRECLAIM,
	MEMINFO_MASK_KERNEL_STACK	= 1ULL << MEMINFO_ID_KERNEL_STACK,
	MEMINFO_MASK_PAGE_TABLES	= 1ULL << MEMINFO_ID_PAGE_TABLES,
	MEMINFO_MASK_NFS_UNSTABLE	= 1ULL << MEMINFO_ID_NFS_UNSTABLE,
	MEMINFO_MASK_BOUNCE		= 1ULL << MEMINFO_ID_BOUNCE,
	MEMINFO_MASK_WRITEBACK_TMP	= 1ULL << MEMINFO_ID_WRITEBACK_TMP,
	MEMINFO_MASK_COMMIT_LIMIT	= 1ULL << MEMINFO_ID_COMMIT_LIMIT,
	MEMINFO_MASK_COMMITTED_AS	= 1ULL << MEMINFO_ID_COMMITTED_AS,
	MEMINFO_MASK_VMALLOC_TOTAL	= 1ULL << MEMINFO_ID_VMALLOC_TOTAL,
	MEMINFO_MASK_VMALLOC_USED	= 1ULL << MEMINFO_ID_VMALLOC_USED,
	MEMINFO_MASK_VMALLOC_CHUNK	= 1ULL << MEMINFO_ID_VMALLOC_CHUNK,
	MEMINFO_MASK_ALL		= (1ULL << MEMINFO_ID_MAX) - 1,
};

struct meminfo_mapping {
	const char *name;
	enum meminfo_id id;
};
typedef struct meminfo_mapping meminfo_mapping;

const meminfo_mapping *meminfo_mapping_lookup(const char *str, unsigned int len);

static inline enum meminfo_id meminfo_string_to_id(const char *str)
{
	const struct meminfo_mapping *i;

	assert(str);
	i = meminfo_mapping_lookup(str, strlen(str));
	return i ? i->id : MEMINFO_ID_INVALID;
}

const char *meminfo_id_to_string(enum meminfo_id);

struct meminfo {
	unsigned int value[MEMINFO_ID_MAX];
};

/**
 * @desc get info corresponding size(kB) from /proc/meminfo
 * @note given meminfo struct is set all zero before filled
 * @return 0 on success, return negative error code on fail.
 */
int proc_get_meminfo(struct meminfo *mi, enum meminfo_mask mask);

/*
 * This interface is required by proc_sys_node_trigger(...)
 */
enum sys_node_id {
	SYS_VM_SHRINK_MEMORY,
	SYS_VM_COMPACT_MEMORY,
};

/*
 * Here,
 * @path is /proc/sys/vm/{shrink,compact}_memory
 * @value is always 1
 * @valid - indicates whether the node is present in kernel or not
 */
struct sys_node_table {
	enum sys_node_id sys_node_id;
	const char *path;
	int value;
	int valid;
};

/**
 * @desc get command line from /proc/{pid}/cmdline
 * @return negative value if error
 */
int proc_get_cmdline(pid_t pid, char *cmdline);

/**
 * @desc find pid with /proc/{pid}/cmdline
 * it returns first entry when many pids have same cmdline
 * @return negative value if error
 */
pid_t find_pid_from_cmdline(char *cmdline);

/**
 * @desc get oom score adj value from /proc/{pid}/oom_score_adj
 * @return negative value if error or pid doesn't exist
 */
int proc_get_oom_score_adj(int pid, int *oom_score_adj);

/**
 * @desc set oom score adj value to /proc/{pid}/oom_score_adj
 * @return negative value if error or pid doesn't exist
 */
int proc_set_oom_score_adj(int pid, int oom_score_adj);

/**
 * @desc get smack subject label from /proc/{pid}/attr/current
 * this label can indicate package name about child processes
 * @return negative value if error or pid doesn't exist
 */
int proc_get_label(pid_t pid, char *label);

/**
 * @desc get VmSize and VmRSS from /proc/{pid}/statm file.
 * @return negative value if error or pid doesn't exist
 */
int proc_get_mem_usage(pid_t pid, unsigned int *vmsize, unsigned int *vmrss);

/**
 * @desc get MemAvaliable from /proc/meminfo or calcuate it by MemFree+Cached
 * @return 0 if the values can't be read or the avaliable memory value
 */
unsigned int proc_get_mem_available(void);

/**
 * @desc get SwapFree from /proc/meminfo
 * @return 0 if the values can't be read or the free swap memory
 */
unsigned int proc_get_swap_free(void);

/**
 * @desc get number of CPUs from /proc/cpuinfo
 * @return 0 if the number can't be found or number of CPUs
 */
unsigned int proc_get_cpu_number(void);

/**
 * @desc get utime and stime from /proc/{pid}/stat file.
 * @return negative value if error or pid doesn't exist
 */
int proc_get_cpu_time(pid_t pid, unsigned long *utime, unsigned long *stime);

/**
 * @desc get command line from /proc/{pid}/cmdline without any truncation
 * @return negative value if error
 */
int proc_get_raw_cmdline(pid_t pid, char *buf, int len);

/**
 * @desc get symblolic link about /proc/{pid}/exe
 * @return negative value if error
 */
int proc_get_exepath(pid_t pid, char *buf, int len);

/**
 * @desc get stat from /proc/{pid}/stat
 * @return negative value if error
 */
int proc_get_stat(pid_t pid, char *buf, int len);

/**
 * @desc get status from /proc/{pid}/status
 * @return negative value if error
 */
int proc_get_status(pid_t pid, char *buf, int len);

/**
 * @desc invoke shrink_memory or compact_memory vm parameter.
 * @return none
 */
int proc_sys_node_trigger(enum sys_node_id sys_node_id);

#endif /*__PROCFS_H__*/

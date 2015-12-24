/*
 * resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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

/*
 * @file swap.c
 * @desc swap process
 */
#include <trace.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <memory-common.h>

#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "edbus-handler.h"
#include "swap-common.h"
#include "config-parser.h"
#include "lowmem-handler.h"
#include "notifier.h"
#include "procfs.h"
#include "cgroup.h"
#include "const.h"
#include "file-helper.h"
#include "proc-common.h"
#include "util.h"

#define MEMCG_PATH			"/sys/fs/cgroup/memory/"
#define MEMCG_SIZE_LIMIT		"memory.limit_in_bytes"
#define MOVE_CHARGE			"memory.move_charge_at_immigrate"

#define SWAP_ON_EXEC_PATH		"/sbin/swapon"
#define SWAP_OFF_EXEC_PATH		"/sbin/swapoff"
#define SWAP_MKSWAP_EXEC_PATH		"/sbin/mkswap"

#define SWAP_CONF_FILE			"/etc/resourced/swap.conf"
#define SWAP_CONTROL_SECTION		"CONTROL"
#define SWAP_CONF_STREAMS		"MAX_COMP_STREAMS"
#define SWAP_CONF_ALGORITHM		"COMP_ALGORITHM"
#define SWAP_CONF_RATIO			"RATIO"
#define SWAP_HARD_LIMIT			"SWAP_HARD_LIMIT"

#define SWAP_BACKEND			"zram"
#define SWAP_ZRAM_NUM_DEVICE		"1"
#define SWAP_ZRAM_DEVICE		"/dev/zram0"
#define SWAP_ZRAM_SYSFILE		"/sys/block/zram0/"
#define SWAP_ZRAM_DISK_SIZE		SWAP_ZRAM_SYSFILE"disksize"
#define SWAP_ZRAM_MAX_COMP_STREAMS	SWAP_ZRAM_SYSFILE"max_comp_streams"
#define SWAP_ZRAM_COMP_ALGORITHM	SWAP_ZRAM_SYSFILE"comp_algorithm"
#define SWAP_ZRAM_COMPACT		SWAP_ZRAM_SYSFILE"compact"
#define SWAP_ZRAM_MEM_USED_TOTAL	SWAP_ZRAM_SYSFILE"mem_used_total"

#define MBtoB(x)			(x<<20)
#define MBtoPage(x)			(x<<8)
#define BtoMB(x)			((x) >> 20)
#define BtoPAGE(x)			((x) >> 12)

#define SWAP_PRIORITY			20
#define SWAP_SORT_MAX			10
#define MAX_PIDS			3
#define SWAP_RATIO			0.5
#define SWAP_FULLNESS_RATIO		0.8
#define SWAP_HARD_LIMIT_DEFAULT		0.5

enum swap_thread_op {
	SWAP_OP_ACTIVATE,
	SWAP_OP_RECLAIM,
	SWAP_OP_COMPACT,
	SWAP_OP_END,
};

struct swap_task {
	struct proc_app_info *pai;
	int size;
};

struct swap_zram_control {
	int max_comp_streams;
	char comp_algorithm[5];
	float ratio;
	unsigned long swap_size_bytes;
	unsigned long swap_almost_full_bytes;
};

struct swap_safe_queue {
	GQueue *queue;
	pthread_mutex_t lock;
};

struct swap_thread_bundle {
	struct swap_status_msg msg;
	enum swap_thread_op op;
};

static struct swap_zram_control swap_control = {
	.max_comp_streams = -1,
	.comp_algorithm = "lzo",
	.ratio = SWAP_RATIO,
	.swap_size_bytes = 0,
	.swap_almost_full_bytes = 0,
};

static pthread_mutex_t swap_mutex;
static pthread_cond_t swap_cond;
static struct swap_safe_queue swap_thread_queue;
static struct module_ops swap_modules_ops;
static char *swap_thread_op_names[SWAP_OP_END] = {
	"ACTIVATE",
	"RECLAIM",
	"COMPACT",
};
static float swap_hard_limit_fraction = SWAP_HARD_LIMIT_DEFAULT;

static int swap_compact_handler(void *data);

static const char *compact_reason_to_str(enum swap_compact_reason reason)
{
	static const char *reasons_table[] = {"lowmem: low", "lowmem: medium",
			"swap: zram full"};
	if (reason >= SWAP_COMPACT_LOWMEM_LOW && reason < SWAP_COMPACT_RESASON_MAX)
		return reasons_table[reason];
	return "";
}

static void swap_set_state(enum swap_state state)
{
	struct shared_modules_data *modules_data = get_shared_modules_data();

	ret_msg_if(modules_data == NULL,
			 "Invalid shared modules data\n");

	if ((state != SWAP_ON) && (state != SWAP_OFF))
		return;

	modules_data->swap_data.swap_state = state;
}


static pid_t swap_change_state(enum swap_state state)
{
	int status;
	pid_t child_pid;
	pid_t pid = fork();
	char error_buf[256];

	if (pid < 0) {
		_E("failed to fork");
		return RESOURCED_ERROR_FAIL;
	}

	/* child */
	if (pid == 0) {
		if (state == SWAP_ON)
			execl(SWAP_ON_EXEC_PATH, SWAP_ON_EXEC_PATH, "-d",
			    SWAP_ZRAM_DEVICE, (char *)NULL);
		else if (state == SWAP_OFF)
			execl(SWAP_OFF_EXEC_PATH, SWAP_OFF_EXEC_PATH,
			    SWAP_ZRAM_DEVICE, (char *)NULL);
		exit(0);
	}

	/* parent */
	child_pid = waitpid(pid, &status, 0);
	if (child_pid < 0) {
		_E("can't wait for a pid %d %d %s", pid, status,
				strerror_r(errno, error_buf, sizeof(error_buf)));
		return child_pid;
	}

	swap_set_state(state);
	return pid;
}

static unsigned int swap_calculate_hard_limit_in_bytes(unsigned int mem_subcg_usage)
{
	return (unsigned int)((float)mem_subcg_usage * swap_hard_limit_fraction);
}

static int swap_get_disksize_bytes(void)
{
	int ret, disksize = 0;

	ret = fread_int(SWAP_ZRAM_DISK_SIZE, &disksize);
	if (ret == RESOURCED_ERROR_NONE)
		return disksize;

	return ret;
}

static inline void swap_add_bundle(struct swap_thread_bundle *bundle)
{
	pthread_mutex_lock(&swap_thread_queue.lock);
	g_queue_push_tail(swap_thread_queue.queue, bundle);
	pthread_mutex_unlock(&swap_thread_queue.lock);
}

static int swap_move_to_cgroup_by_pid(enum memcg_type type, pid_t pid)
{
	int ret;
	struct memcg *memcg_swap = NULL;
	struct memcg_info *mi;
	struct proc_app_info *pai = find_app_info(pid);
	GSList *iter_child = NULL;

	ret = lowmem_get_memcg(type, &memcg_swap);
	if (ret != RESOURCED_ERROR_NONE)
		return RESOURCED_ERROR_FAIL;

	mi = memcg_swap->info;
	if (!pai)
		return place_pid_to_cgroup_by_fullpath(mi->name, pid);

	ret = place_pid_to_cgroup_by_fullpath(mi->name, pai->main_pid);
	gslist_for_each_item(iter_child, pai->childs) {
		struct child_pid *child;

		child = (struct child_pid *)(iter_child->data);
		ret= place_pid_to_cgroup_by_fullpath(mi->name, child->pid);
	}
	pai->memory.memcg_idx = MEMCG_SWAP;
	pai->memory.memcg_info = mi;
	return ret;
}

static int swap_move_to_cgroup(struct memcg_info *info, GArray *candidates)
{
	int index;
	struct swap_task tsk;
	struct proc_app_info *pai = NULL;
	GSList *iter_child = NULL;

	if (!candidates)
		return RESOURCED_ERROR_NO_DATA;

	for (index = 0; index < candidates->len; index++) {
		tsk = g_array_index(candidates, struct swap_task, index);
		pai = tsk.pai;
		place_pid_to_cgroup_by_fullpath(info->name, pai->main_pid);
		gslist_for_each_item(iter_child, pai->childs) {
			struct child_pid *child;

			child = (struct child_pid *)(iter_child->data);
			place_pid_to_cgroup_by_fullpath(info->name, child->pid);
		}
		pai->memory.memcg_idx = MEMCG_SWAP;
		pai->memory.memcg_info = info;
	}
	return RESOURCED_ERROR_NONE;
}

static int swap_sort_by_oom(const struct swap_task *ta,
    const struct swap_task *tb)
{
	/* sort by oom score adj */
	assert(ta != NULL);
	assert(tb != NULL);

	return ((int)(tb->pai->memory.oom_score_adj) -
		(int)(ta->pai->memory.oom_score_adj));
}

static int swap_sort_by_vmrss(const struct swap_task *ta,
    const struct swap_task *tb)
{
	/* sort by task memory usage */
	assert(ta != NULL);
	assert(tb != NULL);

	return ((int)(tb->size) - (int)(ta->size));
}

static int swap_prepare_victims(GArray *candidates)
{
	GSList *iter = NULL;
	struct proc_app_info *pai = NULL;
	struct swap_task victim;

	/*
	 * serch victims from proc_app_list
	 * It was better than searching backround cgroup
	 * because proc_app_list had already known current state and child processes
	 */
	gslist_for_each_item(iter, proc_app_list) {
		pai = (struct proc_app_info *)iter->data;
		if (pai->memory.memcg_idx != MEMCG_BACKGROUND)
			continue;
		if (pai->lru_state <= PROC_BACKGROUND)
			continue;

		memset(&victim, 0, sizeof(struct swap_task));
		victim.pai = pai;
		g_array_append_val(candidates, victim);
	}
	return candidates->len;
}

static int swap_reduce_victims(GArray *candidates, int max)
{
	int index;
	struct swap_task tsk;
	struct proc_app_info *pai = NULL;
	unsigned int vmrss = 0;

	if (!candidates)
		return RESOURCED_ERROR_NO_DATA;

	for (index = 0; index < candidates->len; index++) {
		tsk = g_array_index(candidates, struct swap_task, index);
		pai = tsk.pai;

		/* Measuring VmRSS is OK as it's anonymous + swapcache */
		if (proc_get_mem_usage(pai->main_pid, NULL, &vmrss) < 0)
			continue;

		tsk.size += vmrss;

		if (pai->childs) {
			GSList *iter_child = NULL;

			gslist_for_each_item(iter_child, pai->childs) {
				struct child_pid *child;

				child = (struct child_pid *)(iter_child->data);
				if (proc_get_mem_usage(child->pid, NULL, &vmrss) < 0)
					continue;
				tsk.size += vmrss;
			}
		}
	}
	/* sort by oom_score_adj value, older are better candidates */
	g_array_sort(candidates, (GCompareFunc)swap_sort_by_oom);

	/* sort by memory usage, swapping bigger will free more memory */
	g_array_sort(candidates, (GCompareFunc)swap_sort_by_vmrss);

	/* limit the number of potential candidates, after sort by oom */
	g_array_remove_range(candidates, max, candidates->len - max);

	return RESOURCED_ERROR_NONE;
}

static int swap_reclaim_memcg(struct swap_status_msg msg)
{
	int ret;
	unsigned long swap_usage;
	unsigned int usage, memcg_limit;

	/* Test for restarted resourced, where zram already activated */
	if (swap_control.swap_size_bytes == 0) {
		swap_control.swap_size_bytes = swap_get_disksize_bytes();
		swap_control.swap_almost_full_bytes = swap_control.swap_size_bytes * SWAP_FULLNESS_RATIO;
		swap_change_state(SWAP_ON);
	}
	swap_usage = swap_control.swap_size_bytes - KBYTE_TO_BYTE(proc_get_swap_free());
	if (swap_usage > swap_control.swap_almost_full_bytes) {
		_D("reclaim omit, almost full swap partition full: %d curr: %d",
			swap_control.swap_almost_full_bytes, swap_usage);
		/* Compact swap when we already have full swap partition */
		swap_compact_handler((void *)SWAP_COMPACT_SWAP_FULL);
		return RESOURCED_ERROR_NONE;
	}

	ret = memcg_get_usage(msg.info, &usage);
	if (ret != RESOURCED_ERROR_NONE)
		usage = 0;

	memcg_limit = swap_calculate_hard_limit_in_bytes(usage);
	_D("Swap request: %s cgroup usage is %lu, hard limit set to %lu (hard limit fraction %f)",
			msg.info->name, usage, memcg_limit, swap_hard_limit_fraction);
	ret = cgroup_write_node(msg.info->name, MEMCG_SIZE_LIMIT, memcg_limit);
	if (ret != RESOURCED_ERROR_NONE)
		_E("Not able to set hard limit of %s memory cgroup", msg.info->name);

	return ret;
}

static int swap_compact_zram(void)
{
	int ret;
	unsigned int total;
	static unsigned int last_total;

	ret = fread_uint(SWAP_ZRAM_MEM_USED_TOTAL, &total);
	if (ret < 0) {
		_E("fail to read %s", SWAP_ZRAM_MEM_USED_TOTAL);
		return ret;
	}

	/*
	 * Until zram size not increased of at least 1 MB from last compaction
	 * then it not makes any sense to compact it again.
	 */
	if ((total - last_total) < MBtoB(1))
		return RESOURCED_ERROR_NO_DATA;

	last_total = total;
	ret = fwrite_int(SWAP_ZRAM_COMPACT, 1);
	if (ret < 0) {
		_E("fail to write %s", SWAP_ZRAM_COMPACT);
		return ret;
	}

	ret = fread_uint(SWAP_ZRAM_MEM_USED_TOTAL, &total);
	if (ret < 0) {
		_E("fail to read %s", SWAP_ZRAM_MEM_USED_TOTAL);
		return ret;
	}

	return RESOURCED_ERROR_NONE;
}

static int swap_move_background_to_swap(struct swap_status_msg *msg)
{
	int max_victims, selected;
	int ret = RESOURCED_ERROR_NONE;
	GArray *candidates = NULL, *pids_array = NULL;
	struct memcg *memcg_swap = NULL;

	pids_array = g_array_new(false, false, sizeof(pid_t));
	if (!pids_array) {
		_E("failed to allocate memory");
		ret = RESOURCED_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Get procs to check for swap candidates */
	memcg_get_pids(msg->info, pids_array);
	if (pids_array->len == 0) {
		ret = RESOURCED_ERROR_NO_DATA;
		goto out;
	}
	/*
	 * background cgroup finds victims and moves them to swap group
	 */
	ret = lowmem_get_memcg(MEMCG_SWAP, &memcg_swap);
	if (ret != RESOURCED_ERROR_NONE)
		return RESOURCED_ERROR_FAIL;

	candidates = g_array_new(false, false, sizeof(struct swap_task));
	if (!candidates) {
		_E("failed to allocate memory");
		ret = RESOURCED_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	/*
	 * Let's consider 50% of background apps to be swappable. Using ZRAM
	 * swap makes the operation on swap cheaper. Only anonymous memory
	 * is swaped so the results are limited by size of allocations.
	 */
	max_victims = pids_array->len >> 1;
	/* It makes no sense if we will have no candidates */
	if (max_victims == 0) {
		ret = RESOURCED_ERROR_NO_DATA;
		goto out;
	}
	if (max_victims > SWAP_SORT_MAX)
		max_victims = SWAP_SORT_MAX;

	selected = swap_prepare_victims(candidates);
	if (selected == 0) {
		ret = RESOURCED_ERROR_NO_DATA;
		_D("no victims from proc_app_list (pids: %d)", max_victims);
		goto out;
	} else if (selected > max_victims)
		swap_reduce_victims(candidates, max_victims);

	/*
	 * change swap info from background cgroup to swap group
	 * for using same structure to move and swap it
	 */
	msg->info = memcg_swap->info;
	msg->type = MEMCG_SWAP;
	swap_move_to_cgroup(msg->info, candidates);
out:
	if (candidates)
		g_array_free(candidates, TRUE);
	if (pids_array)
		g_array_free(pids_array, TRUE);
	return ret;

}

static int swap_size(void)
{
	int size; /* size in bytes */
	unsigned long ktotalram = lowmem_get_ktotalram(); /* size in kilobytes */

	if (ktotalram >= 900000) /* >= 878 MB */
		size = 268435456; /* 256 MB */
	else if (ktotalram < 200000) /* < 195 MB */
		size = 16777216; /* 16 MB */
	else
		size = ktotalram * swap_control.ratio * 1024;

	_D("swapfile size = %d", size);

	return size;
}

static int swap_mkswap(void)
{
	pid_t pid = fork();

	if (pid < 0) {
		_E("fork for mkswap failed");
		return pid;
	} else if (pid == 0) {
		_D("mkswap starts");
		execl(SWAP_MKSWAP_EXEC_PATH, SWAP_MKSWAP_EXEC_PATH,
			SWAP_ZRAM_DEVICE, (char *)NULL);
		exit(0);
	} else {
		wait(0);
		_D("mkswap ends");
	}

	return pid;
}

static int swap_zram_activate(void)
{
	int ret;
	unsigned int swap_size_bytes;

	ret = fwrite_int(SWAP_ZRAM_MAX_COMP_STREAMS, swap_control.max_comp_streams);
	if (ret < 0) {
		_E("fail to write max_comp_streams");
		return ret;
	}

	ret = fwrite_str(SWAP_ZRAM_COMP_ALGORITHM, swap_control.comp_algorithm);
	if (ret < 0) {
		_E("fail to write comp_algrithm");
		return ret;
	}

	swap_control.swap_size_bytes = swap_size();
	swap_control.swap_almost_full_bytes = swap_control.swap_size_bytes * SWAP_FULLNESS_RATIO;
	ret = fwrite_uint(SWAP_ZRAM_DISK_SIZE, swap_control.swap_size_bytes);
	if (ret < 0) {
		_E("fail to write disk_size");
		return ret;
	}

	ret = fread_uint(SWAP_ZRAM_DISK_SIZE, &swap_size_bytes);
	if (ret < 0) {
		_E("fail to read zram disk_size");
		return ret;
	}

	/* Check if zram was sucessfully initialized (zcomp rollback case) */
	if (swap_size_bytes < swap_control.swap_size_bytes) {
		_E("swap size (%d) less than expected swap size (%d)",
				swap_size_bytes, swap_control.swap_size_bytes);
		return RESOURCED_ERROR_OOM;
	}

	ret = swap_mkswap();
	if (ret < 0) {
		_E("swap mkswap failed, fork error = %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}

static void swap_activate_in_module(void)
{
	int disksize;

	if (swap_get_state() == SWAP_ON)
		return;
	
	disksize = swap_get_disksize_bytes();
	if (disksize <= 0) {
		if (swap_zram_activate() < 0) {
			_E("swap cannot be activated");
			return;
		}
	}
	swap_change_state(SWAP_ON);
	_D("swap activated");
}

static void *swap_thread_main(void * data)
{
	int is_empty;
	struct swap_thread_bundle *bundle;

	setpriority(PRIO_PROCESS, 0, SWAP_PRIORITY);

	while (1) {
		pthread_mutex_lock(&swap_mutex);
		/* THREAD: WAIT FOR START */
		pthread_mutex_lock(&swap_thread_queue.lock);
		is_empty = g_queue_is_empty(swap_thread_queue.queue);
		pthread_mutex_unlock(&swap_thread_queue.lock);
		if (is_empty) {
			/* The queue is empty, wait for thread signal */
			pthread_cond_wait(&swap_cond, &swap_mutex);
		}

		/* We're in swap thread, now it's time to dispatch bundles */
		pthread_mutex_lock(&swap_thread_queue.lock);
		bundle = g_queue_pop_head(swap_thread_queue.queue);
		pthread_mutex_unlock(&swap_thread_queue.lock);

		if (!bundle)
			goto unlock_out;

		switch (bundle->op) {
		/* Swap activation operttion: mkswap, swapon etc. */
		case SWAP_OP_ACTIVATE:
			swap_activate_in_module();
			break;
		/* Swap reclaim opertation: move to swap, force_reclaim */
		case SWAP_OP_RECLAIM:
			swap_reclaim_memcg(bundle->msg);
			break;
		/* Swap compact operation of zsmalloc. */
		case SWAP_OP_COMPACT:
			swap_compact_zram();
			break;
		case SWAP_OP_END:
		default:
			_D("wrong swap thread operation selected");
		}

		free(bundle);
unlock_out:
		pthread_mutex_unlock(&swap_mutex);
	}
	return NULL;
}

static int swap_start_handler(void *data)
{
	int ret;
	struct swap_thread_bundle *bundle;

	if (!data)
		return RESOURCED_ERROR_NO_DATA;

	bundle = malloc(sizeof(struct swap_thread_bundle));
	if (!bundle)
		return RESOURCED_ERROR_OUT_OF_MEMORY;

	bundle->op = SWAP_OP_RECLAIM;
	memcpy(&(bundle->msg), data, sizeof(struct swap_status_msg));

	if (bundle->msg.type == MEMCG_BACKGROUND) {
		ret = swap_move_background_to_swap(&(bundle->msg));
		/* add bundle only if some processes were moved into swap memcg */
		if (ret) {
			free(bundle);
			return RESOURCED_ERROR_NO_DATA;
		}
	}
	swap_add_bundle(bundle);

	/* Try to signal swap thread, that there is some work to do */
	ret = pthread_mutex_trylock(&swap_mutex);
	if (ret == 0) {
		pthread_cond_signal(&swap_cond);
		pthread_mutex_unlock(&swap_mutex);
		_I("send signal to swap thread");
		return RESOURCED_ERROR_NONE;
	}

	if (ret && ret == EBUSY) {
		_D("swap thread already active");
	} else {
		_E("pthread_mutex_trylock fail : %d, errno : %d", ret, errno);
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}

static int swap_simple_bundle_sender(enum swap_thread_op operation)
{
	int ret;
	struct swap_thread_bundle *bundle;

	bundle = malloc(sizeof(struct swap_thread_bundle));
	if (!bundle)
		return RESOURCED_ERROR_OUT_OF_MEMORY;

	bundle->op = operation;
	swap_add_bundle(bundle);

	if (operation >= 0 && operation < SWAP_OP_END)
		_D("added %s operation to swap queue",
				swap_thread_op_names[operation]);

	/* Try to signal swap thread, that there is some work to do */
	ret = pthread_mutex_trylock(&swap_mutex);
	if (ret == 0) {
		pthread_cond_signal(&swap_cond);
		pthread_mutex_unlock(&swap_mutex);
		_I("send signal to swap thread");
		return RESOURCED_ERROR_NONE;
	}

	if (ret && ret == EBUSY) {
		_D("swap thread already active");
	} else {
		_E("pthread_mutex_trylock fail : %d, errno : %d", ret, errno);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

static int swap_activate_handler(void *data)
{
	return swap_simple_bundle_sender(SWAP_OP_ACTIVATE);
}

static int swap_compact_handler(void *data)
{
	_I("compaction request. Reason: %s",
			compact_reason_to_str((enum swap_compact_reason)data));
	return swap_simple_bundle_sender(SWAP_OP_COMPACT);
}

/* This function is callback function for the notifier RESOURCED_NOTIFIER_SWAP_UNSET_LIMIT.
 * This notifier is notified from normal_act function of vmpressure module whenever the
 * memory state changes to normal.
 * This function resets the hard limit of the swap subcgroup to -1 (unlimited) */
static int swap_cgroup_reset_limit(void *data)
{
	int ret, limit;
	struct swap_status_msg *msg = data;

	limit = -1;
	ret = cgroup_write_node(msg->info->name, MEMCG_SIZE_LIMIT, limit);
	if (ret != RESOURCED_ERROR_NONE)
		_E("Failed to change hard limit of %s cgroup to -1", msg->info->name);
	else
		_D("changed hard limit of %s cgroup to -1", msg->info->name);

	return ret;
}

static void swap_start_pid_edbus_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	pid_t pid;
	struct memcg *memcg_swap;
	struct swap_status_msg ss_msg;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_SWAP, SIGNAL_NAME_SWAP_START_PID);
	if (ret == 0) {
		_D("there is no swap type signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &pid, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	ret = lowmem_get_memcg(MEMCG_SWAP, &memcg_swap);
	if (ret != RESOURCED_ERROR_NONE)
		return;
	swap_move_to_cgroup_by_pid(MEMCG_SWAP, pid);
	ss_msg.pid = pid;
	ss_msg.type = MEMCG_SWAP;
	ss_msg.info = memcg_swap->info;
	swap_start_handler(&ss_msg);
	_I("swap cgroup entered : pid : %d", (int)pid);
}

static void swap_type_edbus_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	enum swap_state state;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_SWAP, SIGNAL_NAME_SWAP_TYPE) == 0) {
		_D("there is no swap state signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &state, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	if (swap_get_state() != state)
		swap_change_state(state);
}

static DBusMessage *edbus_getswaptype(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	enum swap_state state;

	state = swap_get_state();

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &state);

	return reply;
}

static struct edbus_method edbus_methods[] = {
	{ "GetSwapType",   NULL,   "i", edbus_getswaptype },
	/* Add methods here */
};

static const struct edbus_signal edbus_signals[] = {
	/* RESOURCED DBUS */
	{RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
	    SIGNAL_NAME_SWAP_TYPE, swap_type_edbus_signal_handler, NULL},
	{RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
	    SIGNAL_NAME_SWAP_START_PID, swap_start_pid_edbus_signal_handler, NULL},
};

static void swap_dbus_init(void)
{
	resourced_ret_c ret;

	edbus_add_signals(edbus_signals, ARRAY_SIZE(edbus_signals));

	ret = edbus_add_methods(RESOURCED_PATH_SWAP, edbus_methods,
			  ARRAY_SIZE(edbus_methods));

	ret_msg_if(ret != RESOURCED_ERROR_NONE,
		"DBus method registration for %s is failed",
			RESOURCED_PATH_SWAP);
}

static int load_swap_config(struct parse_result *result, void *user_data)
{
	int limit_value;

	if (!result)
		return -EINVAL;

	if (strncmp(result->section, SWAP_CONTROL_SECTION, strlen(SWAP_CONTROL_SECTION)+1))
		return RESOURCED_ERROR_NO_DATA;

	if (!strncmp(result->name, SWAP_CONF_STREAMS, strlen(SWAP_CONF_STREAMS)+1)) {
		int value = atoi(result->value);
		if (value > 0) {
			swap_control.max_comp_streams = value;
			_D("max_comp_streams of swap_control is %d",
				swap_control.max_comp_streams);
		}
	} else if (!strncmp(result->name, SWAP_CONF_ALGORITHM, strlen(SWAP_CONF_ALGORITHM)+1)) {
		if (!strncmp(result->value, "lzo", 4) ||
		    !strncmp(result->value, "lz4", 4)) {
			strncpy(swap_control.comp_algorithm, result->value,
				strlen(result->value) + 1);
			_D("comp_algorithm of swap_control is %s",
				result->value);
		}
	} else if (!strncmp(result->name, SWAP_CONF_RATIO, strlen(SWAP_CONF_RATIO)+1)) {
		float ratio = atof(result->value);
		swap_control.ratio = ratio;
		_D("swap disk size ratio is %.2f", swap_control.ratio);
	} else if (!strncmp(result->name, SWAP_HARD_LIMIT, strlen(SWAP_HARD_LIMIT)+1)) {
		limit_value = (int)strtoul(result->value, NULL, 0);
		if (limit_value < 0 || limit_value > 100)
			_E("Invalid %s value in %s file, setting %f as default percent value",
						SWAP_HARD_LIMIT, SWAP_CONF_FILE,
						SWAP_HARD_LIMIT_DEFAULT);
		else {
			swap_hard_limit_fraction = (float)limit_value/100;
			_D("hard limit fraction for swap module is %f", swap_hard_limit_fraction);
		}
	}

	if (swap_control.max_comp_streams < 0) {
		int cpu = proc_get_cpu_number();
		if (cpu > 0) {
			if (cpu > 4)
				/*
				 * On big.LITLLE we can have 8 cores visible
				 * but there can be used 4. Let's limit it to 4
				 * if there is no specified value in .conf file.
				 */
				cpu = 4;
			swap_control.max_comp_streams = cpu;
		} else
			swap_control.max_comp_streams = 1;
	}

	return RESOURCED_ERROR_NONE;
}

static int swap_thread_create(void)
{
	int ret = 0;
	pthread_t pth;

	pthread_mutex_init(&swap_mutex, NULL);
	pthread_cond_init(&swap_cond, NULL);
	pthread_mutex_init(&(swap_thread_queue.lock), NULL);
	swap_thread_queue.queue = g_queue_new();

	if (!swap_thread_queue.queue) {
		_E("fail to allocate swap thread queue");
		return RESOURCED_ERROR_FAIL;
	}

	ret = pthread_create(&pth, NULL, &swap_thread_main, (void *)NULL);
	if (ret) {
		_E("pthread creation for swap_thread failed\n");
		return ret;
	} else {
		pthread_detach(pth);
	}

	return RESOURCED_ERROR_NONE;
}

static int swap_init(void)
{
	int ret;

	config_parse(SWAP_CONF_FILE, load_swap_config, NULL);
	ret = swap_thread_create();
	if (ret) {
		_E("swap thread create failed");
		return ret;
	}
	swap_dbus_init();

	return ret;
}

static int swap_check_node(void)
{
	FILE *fp;

	fp = fopen(SWAP_ZRAM_DEVICE, "w");
	if (fp == NULL) {
		_E("%s open failed", SWAP_ZRAM_DEVICE);
		return RESOURCED_ERROR_NO_DATA;
	}
	fclose(fp);

	return RESOURCED_ERROR_NONE;
}

static int resourced_swap_check_runtime_support(void *data)
{
	return swap_check_node();
}

/*
 * Quote from: kernel Documentation/cgroups/memory.txt
 *
 * Each bit in move_charge_at_immigrate has its own meaning about what type of
 * charges should be moved. But in any case, it must be noted that an account of
 * a page or a swap can be moved only when it is charged to the task's current
 * (old) memory cgroup.
 *
 *  bit | what type of charges would be moved ?
 * -----+------------------------------------------------------------------------
 *   0  | A charge of an anonymous page (or swap of it) used by the target task.
 *      | You must enable Swap Extension (see 2.4) to enable move of swap charges.
 * -----+------------------------------------------------------------------------
 *   1  | A charge of file pages (normal file, tmpfs file (e.g. ipc shared memory)
 *      | and swaps of tmpfs file) mmapped by the target task. Unlike the case of
 *      | anonymous pages, file pages (and swaps) in the range mmapped by the task
 *      | will be moved even if the task hasn't done page fault, i.e. they might
 *      | not be the task's "RSS", but other task's "RSS" that maps the same file.
 *      | And mapcount of the page is ignored (the page can be moved even if
 *      | page_mapcount(page) > 1). You must enable Swap Extension (see 2.4) to
 *      | enable move of swap charges.
 * quote end.
 *
 * In our case it's better to set only the bit number 0 to charge only
 * anon pages. Therefore file pages etc. will be managed directly by
 * kernel reclaim mechanisms.
 * That will help focus us only on swapping the memory that we actually
 * can swap - anonymous pages.
 * This will prevent from flushing file pages from memory - causing
 * slowdown when re-launching applications.
 */
static void resourced_swap_change_memcg_settings(enum memcg_type type)
{
	int ret;
	struct memcg *memcg_swap = NULL;

	ret = lowmem_get_memcg(type, &memcg_swap);
	if (ret != RESOURCED_ERROR_NONE)
		return;

	cgroup_write_node(memcg_swap->info->name, MOVE_CHARGE, 1);
}

static int resourced_swap_init(void *data)
{
	int ret;

	make_cgroup_subdir(MEMCG_PATH, "swap", NULL);
	resourced_swap_change_memcg_settings(MEMCG_SWAP);
	resourced_swap_change_memcg_settings(MEMCG_FAVORITE);
	resourced_swap_change_memcg_settings(MEMCG_PLATFORM);
	swap_set_state(SWAP_OFF);

	ret = swap_init();
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	register_notifier(RESOURCED_NOTIFIER_SWAP_START, swap_start_handler);
	register_notifier(RESOURCED_NOTIFIER_SWAP_ACTIVATE, swap_activate_handler);
	register_notifier(RESOURCED_NOTIFIER_BOOTING_DONE, swap_activate_handler);
	register_notifier(RESOURCED_NOTIFIER_SWAP_COMPACT, swap_compact_handler);
	register_notifier(RESOURCED_NOTIFIER_SWAP_UNSET_LIMIT, swap_cgroup_reset_limit);

	return ret;
}

static int resourced_swap_finalize(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_START, swap_start_handler);
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_ACTIVATE, swap_activate_handler);
	unregister_notifier(RESOURCED_NOTIFIER_BOOTING_DONE, swap_activate_handler);
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_COMPACT, swap_compact_handler);
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_UNSET_LIMIT, swap_cgroup_reset_limit);

	g_queue_free(swap_thread_queue.queue);

	return RESOURCED_ERROR_NONE;
}

static struct module_ops swap_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "swap",
	.init = resourced_swap_init,
	.exit = resourced_swap_finalize,
	.check_runtime_support = resourced_swap_check_runtime_support,
};

MODULE_REGISTER(&swap_modules_ops)

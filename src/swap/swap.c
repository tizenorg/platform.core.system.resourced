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

#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "edbus-handler.h"
#include "swap-common.h"
#include "notifier.h"
#include "proc-process.h"
#include "proc-main.h"
#include "config-parser.h"

#include <resourced.h>
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

#define MAX_SWAP_VICTIMS		16

#define MEMCG_PATH			"/sys/fs/cgroup/memory"

#define BACKCG_PATH			MEMCG_PATH"/background"
#define BACKCG_PROCS		BACKCG_PATH"/cgroup.procs"

#define SWAPCG_PATH			MEMCG_PATH"/swap"
#define SWAPCG_PROCS			SWAPCG_PATH"/cgroup.procs"
#define SWAPCG_USAGE			SWAPCG_PATH"/memory.usage_in_bytes"
#define SWAPCG_LIMIT			SWAPCG_PATH"/memory.limit_in_bytes"

#define SWAP_ON_EXEC_PATH		"/sbin/swapon"
#define SWAP_OFF_EXEC_PATH		"/sbin/swapoff"

#define SIGNAL_NAME_SWAP_TYPE		"SwapType"
#define SIGNAL_NAME_SWAP_START_PID	"SwapStartPid"

#define SWAPFILE_NAME			"/dev/zram0"

#define SWAP_CONF_FILE			"/etc/resourced/swap.conf"
#define SWAP_CONTROL			"SWAP_CONTROL"
#define SWAP_HARD_LIMIT			"SWAP_HARD_LIMIT"
#define SWAP_HARD_LIMIT_DEFAULT		0.5

#define SWAP_PATH_MAX			100

#define MBtoB(x)			(x<<20)
#define MBtoPage(x)			(x<<8)

#define BtoMB(x)			((x) >> 20)
#define BtoPAGE(x)			((x) >> 12)

#define SWAP_TIMER_INTERVAL		0.5
#define SWAP_PRIORITY			20

#define SWAP_SORT_MAX			10
#define SWAP_COUNT_MAX				5

struct task_info {
	pid_t pid;
	pid_t pgid;
	int oom_score_adj;
	int size;
	int cgroup_cnt;
};

static int swapon;
static float hard_limit_fraction = SWAP_HARD_LIMIT_DEFAULT;
static pthread_mutex_t swap_mutex;
static pthread_cond_t swap_cond;
static Ecore_Timer *swap_timer = NULL;

static const struct module_ops swap_modules_ops;
static const struct module_ops *swap_ops;

static int swap_get_swap_type(void)
{
	struct shared_modules_data *modules_data = get_shared_modules_data();

	ret_value_msg_if(modules_data == NULL, RESOURCED_ERROR_FAIL,
			 "Invalid shared modules data\n");
	return modules_data->swap_data.swaptype;
}

static void swap_set_swap_type(int type)
{
	struct shared_modules_data *modules_data = get_shared_modules_data();

	ret_msg_if(modules_data == NULL,
			 "Invalid shared modules data\n");
	modules_data->swap_data.swaptype = type;
}

static unsigned long swap_calculate_hard_limit(unsigned long swap_cg_usage)
{
	return (unsigned long)(swap_cg_usage * hard_limit_fraction);
}

static int load_swap_config(struct parse_result *result, void *user_data)
{
	int limit_value;

	if (!result) {
		_E("Invalid parameter: result is NULL");
		return -EINVAL;
	}

	if (!strncmp(result->section, SWAP_CONTROL, strlen(SWAP_CONTROL))) {
		if (!strncmp(result->name, SWAP_HARD_LIMIT, strlen(SWAP_CONTROL))) {
			limit_value = (int)strtoul(result->value, NULL, 0);
			if (limit_value < 0 || limit_value > 100) {
				_E("Invalid %s value in %s file, setting %f as default percent value",
						SWAP_HARD_LIMIT, SWAP_CONF_FILE, SWAP_HARD_LIMIT_DEFAULT);
				return RESOURCED_ERROR_NONE;
			}

			hard_limit_fraction = (float)limit_value/100;
		}
	}
	_D("hard limit fraction for swap module is %f", hard_limit_fraction);
	return RESOURCED_ERROR_NONE;
}

static int swap_move_to_swap_cgroup(pid_t pid)
{
	int size;
	FILE *f;
	char buf[SWAP_PATH_MAX] = {0,};

	f = fopen(SWAPCG_PROCS, "w");
	if (!f) {
		_E("Fail to %s file open", SWAPCG_PROCS);
		return RESOURCED_ERROR_FAIL;
	}

	_D("Moving task %d to swap cgroup", pid);
	size = sprintf(buf, "%d", pid);
	if (fwrite(buf, size, 1, f) != 1)
		_E("fwrite cgroup tasks to swap cgroup failed : %d\n", pid);
	fclose(f);

	return RESOURCED_ERROR_NONE;
}

/*
  * check current mem usage total, and caculate to move swap cgroup
  */
static int swap_victims(GArray *victim_candidates)
{
	int i, ret, loop_max;
	int total_usage = 0;
	int swap_size = 0;
	struct sysinfo si;
	char appname[PROC_NAME_MAX];

	if (!sysinfo(&si))
		total_usage = si.totalram - si.freeram;

	if (!total_usage) {
		_E("sysinfo failed");
		return RESOURCED_ERROR_FAIL;
	}

	swap_size = total_usage >> 3;

	if (victim_candidates->len < SWAP_COUNT_MAX)
		loop_max = victim_candidates->len;
	else
		loop_max = SWAP_COUNT_MAX;

	_D("Received %d victims to be moved to swap cgroup. Moving %d tasks", victim_candidates->len, loop_max);
	for (i=0; i<loop_max; i++) {
		struct task_info tsk;

		tsk = g_array_index(victim_candidates, struct task_info, i);

		if (i == 0) {
			ret = proc_get_cmdline(tsk.pid, appname);
			if (ret == RESOURCED_ERROR_FAIL)
				continue;
			/* To DO : kill highest 1 process */
			kill(tsk.pid, SIGKILL);
			_E("we killed %d (%s)", tsk.pid, appname);
		}

		swap_move_to_swap_cgroup(tsk.pid);
		swap_size -= tsk.size;

		if (swap_size < 0)
			return RESOURCED_ERROR_NONE;
	}

	return RESOURCED_ERROR_NONE;
}

/*
  * sorting by mem usage and LRU
  */
static int swap_sort_LRU(const struct task_info *ta, const struct task_info *tb)
{
	/* sort by LRU */
	assert(ta != NULL);
	assert(tb != NULL);

	return ((int)(tb->cgroup_cnt) - (int)(ta->cgroup_cnt));
}

static int swap_sort_usage(const struct task_info *ta, const struct task_info *tb)
{
	/*
	* sort by task size
	*/
	assert(ta != NULL);
	assert(tb != NULL);

	return ((int)(tb->size) - (int)(ta->size));
}

static bool get_mem_usage_by_pid(pid_t pid, unsigned int *rss)
{
	FILE *fp;
	char proc_path[SWAP_PATH_MAX];

	sprintf(proc_path, "/proc/%d/statm", pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return false;

	if (fscanf(fp, "%*s %d", rss) < 1) {
		fclose(fp);
		return false;
	}

	fclose(fp);

	/* convert page to Kb */
	*rss *= 4;
	return true;
}


/*
  * check background mem usage.
  */
static int swap_check_cgroup_victims(void)
{
	FILE *f = NULL;
	int i = 0;
	int cnt = 0;
	int ret;
	char buf[SWAP_PATH_MAX] = {0, };
	GArray *victim_candidates = NULL;

	victim_candidates = g_array_new(false, false, sizeof(struct task_info));

	/* if g_array_new fails, return the current number of victims */
	if (victim_candidates == NULL) {
		_E("victim_candidates failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	if (f == NULL) {
		f = fopen(BACKCG_PROCS, "r");
		if (f == NULL) {
			_E("%s open failed", BACKCG_PROCS);
			return RESOURCED_ERROR_FAIL;
		}
	}

	while (fgets(buf, 32, f) != NULL) {
		struct task_info new_victim;
		pid_t tpid = 0;
		int toom = 0;
		unsigned int tsize = 0;

		tpid = atoi(buf);

		if (proc_get_oom_score_adj(tpid, &toom) < 0) {
			_D("pid(%d) was already terminated", tpid);
			continue;
		}

		if (!get_mem_usage_by_pid(tpid, &tsize)) {
			_D("pid(%d) size is not available\n", tpid);
			continue;
		}

		for (i = 0; i < victim_candidates->len; i++) {
			struct task_info *tsk = &g_array_index(victim_candidates,
							struct task_info, i);
			if (getpgid(tpid) == tsk->pgid) {
				tsk->size += tsize;
				if (tsk->oom_score_adj <= 0 && toom > 0) {
					tsk->pid = tpid;
					tsk->oom_score_adj = toom;
					tsk->cgroup_cnt = cnt;
				}
				break;
			}
		}

		if (i == victim_candidates->len) {
			new_victim.pid = tpid;
			new_victim.pgid = getpgid(tpid);
			new_victim.oom_score_adj = toom;
			new_victim.size = tsize;
			new_victim.cgroup_cnt = cnt;

			g_array_append_val(victim_candidates, new_victim);
		}

		cnt++;
	}

	if (victim_candidates->len == 0) {
		_E("victim_candidates->len = %d", victim_candidates->len);
		g_array_free(victim_candidates, true);
		fclose(f);
		return RESOURCED_ERROR_NO_DATA;
	}

	/* sort by mem usage */
	g_array_sort(victim_candidates, (GCompareFunc)swap_sort_usage);

	if (victim_candidates->len > SWAP_SORT_MAX)
		g_array_remove_range(victim_candidates, SWAP_SORT_MAX, victim_candidates->len - SWAP_SORT_MAX);

	/* sort by LRU */
	g_array_sort(victim_candidates, (GCompareFunc)swap_sort_LRU);

	ret = swap_victims(victim_candidates);
	if (ret) {
		_E("swap_victims error");
		g_array_free(victim_candidates, true);
		fclose(f);
		return RESOURCED_ERROR_FAIL;
	}

	g_array_free(victim_candidates, true);

	fclose(f);
	return RESOURCED_ERROR_NONE;
}

static int swap_thread_do(FILE *procs, FILE *usage_in_bytes, FILE *limit_in_bytes)
{
	char buf[SWAP_PATH_MAX] = {0,};
	int size;
	int ret;
	unsigned long usage;
	unsigned long swap_cg_limit;

	ret = swap_check_cgroup_victims();

	if (ret < 0) {
		_E("swap_check_cgroup_victims error");
		return RESOURCED_ERROR_FAIL;
	}

	/* cacluate reclaim size by usage and swap cgroup count */
	if (fgets(buf, 32, usage_in_bytes) == NULL)
		return RESOURCED_ERROR_FAIL;

	usage = (unsigned long)atol(buf);

	swap_cg_limit = swap_calculate_hard_limit(usage);
	_D("swap cgroup usage is %lu, hard limit set to %lu (hard limit fraction %f)",
			usage, swap_cg_limit, hard_limit_fraction);

	/* set reclaim size */
	size = sprintf(buf, "%lu", swap_cg_limit);
	if (fwrite(buf, 1, size, limit_in_bytes) != size)
		_E("fwrite %s\n", buf);

	return RESOURCED_ERROR_NONE;
}

static void *swap_thread_main(void * data)
{
	FILE *procs;
	FILE *usage_in_bytes;
	FILE *limit_in_bytes;

	setpriority(PRIO_PROCESS, 0, SWAP_PRIORITY);

	procs = fopen(SWAPCG_PROCS, "r");
	if (procs == NULL) {
		_E("%s open failed", SWAPCG_PROCS);
		return NULL;
	}

	usage_in_bytes = fopen(SWAPCG_USAGE, "r");
	if (usage_in_bytes == NULL) {
		_E("%s open failed", SWAPCG_USAGE);
		fclose(procs);
		return NULL;
	}

	limit_in_bytes = fopen(SWAPCG_LIMIT, "w");
	if (limit_in_bytes == NULL) {
		_E("%s open failed", SWAPCG_LIMIT);
		fclose(procs);
		fclose(usage_in_bytes);
		return NULL;
	}

	while (1) {
		pthread_mutex_lock(&swap_mutex);
		pthread_cond_wait(&swap_cond, &swap_mutex);

		/*
		 * when signalled by main thread, it starts
		 * swap_thread_do().
		 */
		_I("swap thread conditional signal received");

		fseek(procs, 0, SEEK_SET);
		fseek(usage_in_bytes, 0, SEEK_SET);
		fseek(limit_in_bytes, 0, SEEK_SET);

		_D("swap_thread_do start");
		swap_thread_do(procs, usage_in_bytes, limit_in_bytes);
		_D("swap_thread_do end");
		pthread_mutex_unlock(&swap_mutex);
	}

	if (procs)
		fclose(procs);
	if (usage_in_bytes)
		fclose(usage_in_bytes);
	if (limit_in_bytes)
		fclose(limit_in_bytes);

	return NULL;
}

static pid_t swap_on(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl(SWAP_ON_EXEC_PATH, SWAP_ON_EXEC_PATH, "-d", SWAPFILE_NAME, (char *)NULL);
		exit(0);
	}
	swapon = 1;
	return pid;
}

static pid_t swap_off(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		execl(SWAP_OFF_EXEC_PATH, SWAP_OFF_EXEC_PATH, SWAPFILE_NAME, (char *)NULL);
		exit(0);
	}
	swapon = 0;
	return pid;
}

static Eina_Bool swap_send_signal(void *data)
{
	int ret;

	_D("swap timer callback function start");

	if(!swapon)
		swap_on();

	/* signal to swap_start to start swap */
	ret = pthread_mutex_trylock(&swap_mutex);

	if (ret)
		_E("pthread_mutex_trylock fail : %d, errno : %d", ret, errno);
	else {
		pthread_cond_signal(&swap_cond);
		_I("send signal to swap thread");
		pthread_mutex_unlock(&swap_mutex);
	}

	_D("swap timer delete");

	ecore_timer_del(swap_timer);
	swap_timer = NULL;

	return ECORE_CALLBACK_CANCEL;
}

static int swap_start(void *data)
{
	if (swap_timer == NULL) {
		_D("swap timer start");
		swap_timer =
			ecore_timer_add(SWAP_TIMER_INTERVAL, swap_send_signal, (void *)NULL);
	}

	return RESOURCED_ERROR_NONE;
}

static int swap_thread_create(void)
{
	int ret = RESOURCED_ERROR_NONE;
	pthread_t pth;

	pthread_mutex_init(&swap_mutex, NULL);
	pthread_cond_init(&swap_cond, NULL);

	ret = pthread_create(&pth, NULL, &swap_thread_main, (void*)NULL);
	if (ret) {
		_E("pthread creation for swap_thread failed\n");
		return ret;
	} else {
		pthread_detach(pth);
	}

	return ret;
}

int swap_check_swap_pid(int pid)
{
	char buf[SWAP_PATH_MAX] = {0,};
	int swappid;
	int ret = 0;
	FILE *f;

	f = fopen(SWAPCG_PROCS, "r");
	if (!f) {
		_E("%s open failed", SWAPCG_PROCS);
		return RESOURCED_ERROR_FAIL;
	}

	while (fgets(buf, SWAP_PATH_MAX, f) != NULL) {
		swappid = atoi(buf);
		if (swappid == pid) {
			ret = swappid;
			break;
		}
	}
	fclose(f);
	return ret;
}

static void swap_start_pid_edbus_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	pid_t pid;

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

	_I("swap cgroup entered : pid : %d", (int)pid);
	swap_move_to_swap_cgroup(pid);

	swap_start(NULL);
}

static void swap_type_edbus_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int type;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_SWAP, SIGNAL_NAME_SWAP_TYPE) == 0) {
		_D("there is no swap type signal");
		return;
	}

	dbus_error_init(&err);

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}

	switch (type) {
	case 0:
		if (swap_get_swap_type() != SWAP_OFF) {
			if (swapon)
				swap_off();
			swap_set_swap_type(type);
		}
		break;
	case 1:
		if (swap_get_swap_type() != SWAP_ON) {
			if (!swapon)
				swap_on();
			swap_set_swap_type(type);
		}
		break;
	default:
		_D("It is not valid swap type : %d", type);
		break;
	}
}

static DBusMessage *edbus_getswaptype(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int state;

	state = swap_get_swap_type();

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &state);

	return reply;
}

static struct edbus_method edbus_methods[] = {
	{ "GetSwapType",   NULL,   "i", edbus_getswaptype },
	/* Add methods here */
};

static void swap_dbus_init(void)
{
	resourced_ret_c ret;

	register_edbus_signal_handler(RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
			SIGNAL_NAME_SWAP_TYPE,
		    (void *)swap_type_edbus_signal_handler, NULL);
	register_edbus_signal_handler(RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
			SIGNAL_NAME_SWAP_START_PID,
		    (void *)swap_start_pid_edbus_signal_handler, NULL);

	ret = edbus_add_methods(RESOURCED_PATH_SWAP, edbus_methods,
			  ARRAY_SIZE(edbus_methods));

	ret_msg_if(ret != RESOURCED_ERROR_NONE,
		"DBus method registration for %s is failed",
			RESOURCED_PATH_SWAP);
}

static int swap_init(void)
{
	int ret;

	ret = swap_thread_create();
	if (ret) {
		_E("swap thread create failed");
		return ret;
	}

	_I("swap_init : %d", swap_get_swap_type());

	swap_dbus_init();

	return ret;
}

static int swap_check_node(void)
{
	FILE *procs;
	FILE *usage_in_bytes;
	FILE *limit_in_bytes;

	procs = fopen(SWAPCG_PROCS, "r");
	if (procs == NULL) {
		_E("%s open failed", SWAPCG_PROCS);
		return RESOURCED_ERROR_NO_DATA;
	}

	fclose(procs);

	usage_in_bytes = fopen(SWAPCG_USAGE, "r");
	if (usage_in_bytes == NULL) {
		_E("%s open failed", SWAPCG_USAGE);
		return RESOURCED_ERROR_NO_DATA;
	}

	fclose(usage_in_bytes);

	limit_in_bytes = fopen(SWAPCG_LIMIT, "w");
	if (limit_in_bytes == NULL) {
		_E("%s open failed", SWAPCG_LIMIT);
		return RESOURCED_ERROR_NO_DATA;
	}

	fclose(limit_in_bytes);

	return RESOURCED_ERROR_NONE;
}

static int resourced_swap_check_runtime_support(void *data)
{
	return swap_check_node();
}

static int resourced_swap_init(void *data)
{
	struct modules_arg *marg = (struct modules_arg *)data;
	struct daemon_opts *dopt = marg->opts;
	int ret;

	ret = config_parse(SWAP_CONF_FILE, load_swap_config, NULL);

	if (ret < 0)
		return ret;

	swap_ops = &swap_modules_ops;

	if (dopt->enable_swap)
		swap_set_swap_type(dopt->enable_swap);

	register_notifier(RESOURCED_NOTIFIER_SWAP_START, swap_start);

	return swap_init();
}

static int resourced_swap_finalize(void *data)
{
	unregister_notifier(RESOURCED_NOTIFIER_SWAP_START, swap_start);

	return RESOURCED_ERROR_NONE;
}

static const struct module_ops swap_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "swap",
	.init = resourced_swap_init,
	.exit = resourced_swap_finalize,
	.check_runtime_support = resourced_swap_check_runtime_support,
};

MODULE_REGISTER(&swap_modules_ops)

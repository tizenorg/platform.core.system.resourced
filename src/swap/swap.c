/*
 * resourced
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 */

#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "edbus-handler.h"
#include "swap-common.h"

#include <resourced.h>
#include <trace.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

enum {
	FLASH_OUT_OFF,
	FLASH_OUT_ON,
};

#define SWAP_PATH_MAX				100
#define MAX_SWAP_VICTIMS			16

#define MEMCG_PATH				"/sys/fs/cgroup/memory"
#define SWAP_ON_EXEC_PATH		"/sbin/swapon"
#define SWAP_OFF_EXEC_PATH		"/sbin/swapoff"

#define SWAP_FLASH_COUNT_PATH			"/sys/kernel/debug/zswap/written_back_pages"

#define SIGNAL_NAME_SWAP_TYPE			"SwapType"
#define SIGNAL_NAME_SWAP_FLASH			"SwapFlash"
#define SIGNAL_NAME_SWAP_START_PID		"SwapStartPid"

#define SWAPFILE_NAME		"/opt/usr/swapfile"

#define BtoPAGE(x)		((x) >> 12)

static int swapon;
static int swap_flashout;
static int last_swap_count;
static pthread_mutex_t swap_mutex;
static pthread_cond_t swap_cond;

pid_t swap_victims[MAX_SWAP_VICTIMS];

static void swap_set_candidate_pid(int *pid_array, int count)
{
	int i;

	memset(swap_victims, 0, sizeof(int)*MAX_SWAP_VICTIMS);

	for (i = 0; i < count; i++)
		swap_victims[i] = pid_array[i];
}

static pid_t swap_get_candidate_pid(void)
{
	int i;
	pid_t pid = 0;

	for (i = 0; i < MAX_SWAP_VICTIMS; i++)
		if(swap_victims[i]) {
			pid = swap_victims[i];
			swap_victims[i] = 0;
			break;
		}
	return pid;
}

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

	ret_value_msg_if(modules_data == NULL, ,
			 "Invalid shared modules data\n");
	modules_data->swap_data.swaptype = type;
}

static int swap_check_swap_pid(int pid)
{
	char buf[SWAP_PATH_MAX] = {0,};
	int swappid;
	int ret = 0;
	FILE *f;

	sprintf(buf, "%s/swap/cgroup.procs", MEMCG_PATH);

	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed", buf);
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

static int swap_check_swap_cgroup(void)
{
	char buf[SWAP_PATH_MAX] = {0,};
	int ret = SWAP_FALSE;
	FILE *f;

	sprintf(buf, "%s/swap/cgroup.procs", MEMCG_PATH);

	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed", buf);
		return RESOURCED_ERROR_FAIL;
	}
	while (fgets(buf, SWAP_PATH_MAX, f) != NULL) {
		ret = SWAP_TRUE;
		break;
	}
	fclose(f);
	return ret;
}

static int swap_thread_do(void)
{
	FILE *f;
	char buf[SWAP_PATH_MAX] = {0,};
	int size;
	unsigned long usage, nr_to_reclaim;

	/* reclaim 25% of swap cgroup usage */
	sprintf(buf, "%s/swap/memory.usage_in_bytes", MEMCG_PATH);
	f = fopen(buf, "r");
	if (!f) {
		_E("%s open failed, %d", buf, f);
		return RESOURCED_ERROR_FAIL;
	}

	if (fgets(buf, 32, f) == NULL) {
		_E("fgets failed\n");
		fclose(f);
		return RESOURCED_ERROR_FAIL;
	}
	usage = (unsigned long)atol(buf);
	fclose(f);

	nr_to_reclaim = BtoPAGE(usage) >> 2;
	sprintf(buf, "%s/swap/memory.force_reclaim", MEMCG_PATH);
	f = fopen(buf, "w");
	if (!f) {
		_E("%s open failed, %d", buf, f);
		return RESOURCED_ERROR_FAIL;
	}

	size = sprintf(buf, "%lu", nr_to_reclaim);
	if (fwrite(buf, 1, size, f) != size)
		_E("fwrite %s\n", buf);
	fclose(f);

	return RESOURCED_ERROR_NONE;
}

static void *swap_thread_main(void * data)
{
	while (1) {
		/*
		 * when signalled by main thread, it starts
		 * swap_thread_do().
		 */
		pthread_mutex_lock(&swap_mutex);
		pthread_cond_wait(&swap_cond, &swap_mutex);
		_I("swap thread conditional signal received");
		swap_thread_do();
		pthread_mutex_unlock(&swap_mutex);
	}

	return NULL;
}

static void swap_start(void)
{
	/* signal to swap_start to start swap */
	pthread_mutex_lock(&swap_mutex);
	pthread_cond_signal(&swap_cond);
	_I("send signal to swap thread");
	pthread_mutex_unlock(&swap_mutex);
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

static int get_swap_status(void)
{
	return swapon;
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

static int swap_set_flashswap(unsigned int on)
{
	swap_flashout = (on ? FLASH_OUT_ON : FLASH_OUT_OFF);

	return RESOURCED_ERROR_NONE;
}

static int swap_set_flashswap_on(void)
{
	return swap_set_flashswap(1);
}

static int swap_set_flashswap_off(void)
{
	return swap_set_flashswap(0);
}

static void restart_swap(void)
{
	int status;
	pid_t pid;
	pid_t ret;

	if (!swapon) {
		swap_on();
		swap_set_flashswap_on();
		return;
	}

	pid = fork();
	if (pid == -1) {
		_E("fork() error");
		return;
	} else if (pid == 0) {
		pid = swap_off();
		ret = waitpid(pid, &status, 0);
		if (ret == -1) {
			_E("Error waiting for swap_off child process (PID: %d, status: %d)", (int)pid, status);
		}
		swap_on();
		swap_set_flashswap_on();
		exit(0);
	}
	swapon = 1;
}

static int swap_get_flashswap(void)
{
	return swap_flashout;
}

static void swap_move_swap_cgroup(pid_t pid)
{
	int size;
	FILE *f;
	char buf[SWAP_PATH_MAX] = {0,};
	sprintf(buf, "%s/swap/cgroup.procs", MEMCG_PATH);
	f = fopen(buf, "w");
	if (!f) {
		_E("Fail to %s file open", buf);
		return;
	}
	size = sprintf(buf, "%d", (int)pid);
	if (fwrite(buf, size, 1, f) != 1)
		_E("fwrite cgroup tasks to swap cgroup failed : %d\n", (int)pid);
	fclose(f);
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
	swap_move_swap_cgroup(pid);

	if (get_swap_status() == SWAP_OFF)
			restart_swap();
	swap_start();
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
			swap_set_flashswap_off();
			if (swapon)
				swap_off();
			swap_set_swap_type(type);
		}
		break;
	case 1:
		if (swap_get_swap_type() != SWAP_ON) {
			restart_swap();
			swap_set_swap_type(type);
		}
		break;
	default:
		_D("It is not valid swap type : %d", type);
		break;
	}
}

static void swap_flash_edbus_signal_handler(void *data, DBusMessage *msg)
{
	DBusError err;
	int type;

	if (dbus_message_is_signal(msg, RESOURCED_INTERFACE_SWAP, SIGNAL_NAME_SWAP_FLASH) == 0) {
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
		if (swap_get_flashswap() == FLASH_OUT_ON)
			swap_set_flashswap_off();
		break;
	case 1:
		if (swap_get_flashswap() == FLASH_OUT_OFF)
			swap_set_flashswap_on();
		break;
	default:
		_D("It is not valid swap flash : %d", type);
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

static DBusMessage *edbus_getflashout_state(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int state;

	state = swap_get_flashswap();

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &state);

	return reply;
}

static struct edbus_method edbus_methods[] = {
	{ "GetFlashoutState",   NULL,   "i", edbus_getflashout_state },
	{ "GetSwapType",   NULL,   "i", edbus_getswaptype },
	/* Add methods here */
};

static void swap_dbus_init(void)
{
	resourced_ret_c ret;

	register_edbus_signal_handler(RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
			SIGNAL_NAME_SWAP_TYPE,
		    (void *)swap_type_edbus_signal_handler);
	register_edbus_signal_handler(RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
			SIGNAL_NAME_SWAP_FLASH,
		    (void *)swap_flash_edbus_signal_handler);
	register_edbus_signal_handler(RESOURCED_PATH_SWAP, RESOURCED_INTERFACE_SWAP,
			SIGNAL_NAME_SWAP_START_PID,
		    (void *)swap_start_pid_edbus_signal_handler);

	ret = edbus_add_methods(RESOURCED_PATH_SWAP, edbus_methods,
			  ARRAY_SIZE(edbus_methods));

	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ,
		"DBus method registration for %s is failed",
			RESOURCED_PATH_SWAP);
}

static int swap_get_swapout_count(int *count)
{
	char buf[SWAP_PATH_MAX] = {0,};
	FILE *f;
	size_t len;

	f = fopen(SWAP_FLASH_COUNT_PATH, "r");

	if (!f) {
		_E("%s open failed", SWAP_FLASH_COUNT_PATH);
		return RESOURCED_ERROR_FAIL;
	}

	len = fread(buf, 1, SWAP_PATH_MAX, f);

	if (len <= 0) {
		_E("fread %s fail\n", SWAP_FLASH_COUNT_PATH);
		fclose(f);
		return RESOURCED_ERROR_FAIL;
	}

	*count = atoi(buf);

	fclose(f);

	return RESOURCED_ERROR_NONE;
}

static int swap_get_last_swapcount(void)
{
	return last_swap_count;
}

static void swap_set_last_swapcount(int count)
{
	last_swap_count = count;
}

static void swap_check_swapout_count(void)
{
	struct shared_modules_data *modules_data = get_shared_modules_data();
	int swap_flash_count;

	ret_value_msg_if(modules_data == NULL, ,
			 "Invalid shared modules data\n");
	if (modules_data->swap_data.swaptype == SWAP_OFF)
		return;

	/* check flashswap count */
	if (swap_get_swapout_count(&swap_flash_count) < 0)
		return;

	if ((swap_flash_count - swap_get_last_swapcount()) >
			MBtoPage(512)) {
		swap_set_last_swapcount(swap_flash_count);
		swap_set_flashswap_off();
		if (swapon)
			swap_off();
	}

	return;
}

static int swap_init(void)
{
	int ret = RESOURCED_ERROR_NONE;

	ret = swap_thread_create();
	if (ret) {
		_E("swap thread create failed\n");
		return ret;
	}

	_I("swap_init : %d", swap_get_swap_type());

	swap_dbus_init();

	return ret;
}

static int swap_intialized;

static int resourced_swap_control(void *data)
{
	int ret = RESOURCED_ERROR_NONE;
	struct swap_data_type *s_data;

	if (!swap_intialized)
		return RESOURCED_ERROR_NONE;

	s_data = (struct swap_data_type *)data;
	switch(s_data->data_type.control_type) {
	case SWAP_START:
		swap_start();
		break;
	case SWAP_RESTART:
		restart_swap();
		break;
	case SWAP_MOVE_CGROUP:
		if (s_data->args)
			swap_move_swap_cgroup((pid_t)s_data->args[0]);
		break;
	}
	return ret;
}

static int resourced_swap_status(void *data)
{
	int ret = RESOURCED_ERROR_NONE;
	struct swap_data_type *s_data;

	if (!swap_intialized)
		return RESOURCED_ERROR_NONE;

	s_data = (struct swap_data_type *)data;
	switch(s_data->data_type.status_type) {
	case SWAP_GET_TYPE:
		ret = swap_get_swap_type();
		break;
	case SWAP_GET_CANDIDATE_PID:
		ret = swap_get_candidate_pid();
		break;
	case SWAP_SET_CANDIDATE_PID:
		if (s_data->args)
			swap_set_candidate_pid((int*)s_data->args[0], (int)s_data->args[1]);
		break;
	case SWAP_GET_STATUS:
		ret = get_swap_status();
		break;
	case SWAP_CHECK_PID:
		if (s_data->args)
			ret = swap_check_swap_pid((int)s_data->args[0]);
		else
			ret = RESOURCED_ERROR_FAIL;
		break;
	case SWAP_CHECK_CGROUP:
		ret = swap_check_swap_cgroup();
		break;
	case SWAP_CHECK_SWAPOUT_COUNT:
		swap_check_swapout_count();
		break;
	}
	return ret;
}

static int resourced_swap_init(void *data)
{
	struct modules_arg *marg = (struct modules_arg *)data;
	struct daemon_opts *dopt = marg->opts;

	swap_intialized = 1;

	if (dopt->enable_swap)
		swap_set_swap_type(dopt->enable_swap);

	return swap_init();
}

static int resourced_swap_finalize(void *data)
{
	return RESOURCED_ERROR_NONE;
}

static struct module_ops swap_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "swap",
	.init = resourced_swap_init,
	.exit = resourced_swap_finalize,
	.control = resourced_swap_control,
	.status = resourced_swap_status,
};

MODULE_REGISTER(&swap_modules_ops)

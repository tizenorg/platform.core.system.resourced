/*
 * resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 */

/**
 * @file counter-process.c
 *
 * @desc Counter process entity
 */

#include "app-stat.h"
#include "classid-helper.h"
#include "config.h"
#include "const.h"
#include "counter.h"
#include "datausage-restriction.h"
#include "edbus-handler.h"
#include "generic-netlink.h"
#include "macro.h"
#include "module-data.h"
#include "notification.h"
#include "resourced.h"
#include "roaming.h"
#include "storage.h"
#include "tethering.h"
#include "trace.h"
#include "transmission.h"
#include "iptables_helper.h"

#include <Ecore.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>

static void _store_and_free_result(struct counter_arg *arg);

static bool check_net_blocked(sig_atomic_t state)
{
	static int net_blocked; /* counter for run only one time after blocking
		to store gap value */
	if (state & RESOURCED_NET_BLOCKED_STATE &&
		net_blocked)
		return true;

	/* set net_blocked flag */
	if (!net_blocked &&
			state & RESOURCED_NET_BLOCKED_STATE)
		++net_blocked;
	/* reset net_blocked flag */
	if (net_blocked &&
		!(state & RESOURCED_NET_BLOCKED_STATE))
		--net_blocked;
	_D("net_blocked %d, state %d", net_blocked, state);
	return false;
}

static resourced_ret_c _process_simply_network_counter( struct counter_arg *carg)
{
	resourced_ret_c ret;

	ret = prepare_application_stat(carg->in_tree,
			carg->out_tree, carg->result,
			carg->opts);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to prepare application statistics!");
		return ret;
	}

	_store_and_free_result( carg);

	g_tree_ref( carg->out_tree);
	free_traffic_stat_tree( carg->out_tree);
	g_tree_ref( carg->in_tree);
	free_traffic_stat_tree( carg->in_tree);

	return ret;
}

static resourced_ret_c get_iptables_counters( struct counter_arg *carg)
{
	int res;

	res = GetCgroupCounters( carg);
	if (res < 0)
		return res;
	res = ZeroCounters();
	if (res < 0)
		return res;

	return _process_simply_network_counter( carg);
}

static Eina_Bool _counter_func_cb(void *user_data)
{
	struct counter_arg *carg = (struct counter_arg *)user_data;
	int ret;

	if (check_net_blocked(carg->opts->state)) {
		ecore_timer_freeze(carg->ecore_timer);
		return ECORE_CALLBACK_RENEW;
	}

	if (!(carg->opts->state & RESOURCED_FORCIBLY_QUIT_STATE)) {
		/* Here we just sent command,
		 * answer we receiving in another callback, send_command uses
		 * return value the same as sendto
		 */
		ret = get_iptables_counters(carg);
		if (ret < 0) {
			ETRACE_ERRNO_MSG("Failed to send command to get "
					 "incomming traffic");
			return ECORE_CALLBACK_RENEW;
		}

		carg->new_traffic = 0;
		return ECORE_CALLBACK_RENEW;
	}

	close(carg->sock);
	return ECORE_CALLBACK_CANCEL;
}

static bool need_flush_immediatelly(sig_atomic_t state)
{
	return state & RESOURCED_FORCIBLY_FLUSH_STATE ||
		state & RESOURCED_FORCIBLY_QUIT_STATE;
}

static void _store_and_free_result(struct counter_arg *arg)
{
	if (store_result(arg->result, need_flush_immediatelly(arg->opts->state)
			 ? 0 : arg->opts->flush_period)) {
		/*We still plan to use result outside, just
		remove and free elements */
		g_tree_ref(arg->result->tree);
		free_app_stat_tree(arg->result);
	}
}

struct nl_family_params {
	struct genl *ans;
	struct counter_arg *carg;
};

typedef struct {
	struct nl_family_params params;
	void (*process)(struct nl_family_params *params);
} nl_family_serialization_command;

static inline char *_get_public_appid(const uint32_t classid)
{
	char *appid;

	/* following value for ALL is suitable for using in statistics
	   what's why it's not in get_app_id_by_classid */
	if (classid == RESOURCED_ALL_APP_CLASSID)
		return RESOURCED_ALL_APP;

	appid = get_app_id_by_classid(classid, true);
	return !appid ? UNKNOWN_APP : appid;
}

int resourced_init_counter_func(struct counter_arg *carg)
{
	int error = 0;

	if (!carg) {
		_E("Please provide valid argument for counting routine.");
		error = RESOURCED_ERROR_INVALID_PARAMETER;
		return error;
	}

	carg->result = create_app_stat_tree();
	carg->in_tree = create_traffic_stat_tree();
	carg->out_tree = create_traffic_stat_tree();

	init_iftype(); /*Initialize iftypes table once, update it by event*/

	if (error != RESOURCED_ERROR_NONE)
		_E("DBus method registration for %s is failed",
			RESOURCED_PATH_NETWORK);

	_counter_func_cb(carg);

	carg->ecore_timer = ecore_timer_add(carg->opts->update_period,
						_counter_func_cb, carg);

	ret_value_msg_if(carg->ecore_timer == 0, RESOURCED_ERROR_FAIL,
			 "carg_timer is null, can't work! update period: %d",
			 carg->opts->update_period);

	return error;
}

void resourced_finalize_counter_func(struct counter_arg *carg)
{
	ret_value_msg_if(!carg, , "Invalid counter argument\n");
	free_traffic_stat_tree(carg->out_tree);
	free_traffic_stat_tree(carg->in_tree);
	free_app_stat_tree(carg->result);
	ecore_main_fd_handler_del(carg->ecore_fd_handler);
	ecore_timer_del(carg->ecore_timer);
}

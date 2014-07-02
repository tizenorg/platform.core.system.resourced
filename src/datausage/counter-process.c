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
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
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

#if 0
    WALK_TREE( carg->result->tree, print_appstat);
#endif

	_store_and_free_result( carg);

	g_tree_ref( carg->out_tree);
	free_traffic_stat_tree( carg->out_tree);
	g_tree_ref( carg->in_tree);
	free_traffic_stat_tree( carg->in_tree);

	return ret;
}

int GetCgroupCounters( struct counter_arg *carg);
int ZeroCounters();


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

static dbus_bool_t deserialize_restriction(
	DBusMessage *msg, char **appid, resourced_net_restrictions *rest,
	enum traffic_restriction_type *rst_type)
{
	DBusError err;
	dbus_error_init(&err);

	int ret = dbus_message_get_args(
		msg, &err,
		DBUS_TYPE_STRING, appid,
		DBUS_TYPE_INT32, rst_type,
		DBUS_TYPE_INT32, &(rest->rs_type),
		DBUS_TYPE_INT32, &(rest->iftype),
		DBUS_TYPE_INT32, &(rest->send_limit),
		DBUS_TYPE_INT32, &(rest->rcv_limit),
		DBUS_TYPE_INT32, &(rest->snd_warning_limit),
		DBUS_TYPE_INT32, &(rest->rcv_warning_limit),
		DBUS_TYPE_INT32, &(rest->roaming),
		DBUS_TYPE_INVALID);

	if (ret == FALSE) {
		_E("Can't deserialize net_restriction! [%s:%s]\n",
		err.name, err.message);
	}

	dbus_error_free(&err);

	return ret;
}

static DBusMessage *edbus_process_restriction(E_DBus_Object *obj,
					      DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int ret;
	resourced_ret_c dbus_ret = RESOURCED_ERROR_NONE;
	char *appid = NULL;
	resourced_net_restrictions rest;
	enum traffic_restriction_type rst_type;

	ret = dbus_message_is_method_call(
	    msg, RESOURCED_INTERFACE_NETWORK,
	    RESOURCED_NETWORK_PROCESS_RESTRICTION);

	if (ret == FALSE)
		return dbus_message_new_error(msg, DBUS_ERROR_UNKNOWN_METHOD,
					      "Method is not supported");

	ret = deserialize_restriction(msg, &appid, &rest, &rst_type);

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	if (ret == FALSE) {
		dbus_ret = RESOURCED_ERROR_FAIL;
		goto out;
	}

#if 0
    dbus_ret = process_restriction_local(appid, NONE_QUOTA_ID, &rest,
					     rst_type);
#endif
out:
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &dbus_ret);

	return reply;
}


static DBusMessage *edbus_update_counters(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	struct shared_modules_data *m_data = get_shared_modules_data();

	if (dbus_message_is_method_call(msg, RESOURCED_INTERFACE_NETWORK,
					RESOURCED_NETWORK_UPDATE) == 0)
		return dbus_message_new_error(msg, DBUS_ERROR_UNKNOWN_METHOD,
					      "Method is not supported");

	if (m_data != NULL && m_data->carg != NULL) {
		if (!(m_data->carg->opts->state & RESOURCED_FORCIBLY_QUIT_STATE))
			m_data->carg->opts->state |=
				RESOURCED_FORCIBLY_FLUSH_STATE;

		/* postpone periodic update on one minute */
		reschedule_count_timer(m_data->carg, COUNTER_UPDATE_PERIOD);
		_counter_func_cb(m_data->carg);
	}

	reply = dbus_message_new_method_return(msg);
	return reply;
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
		if (arg->opts->state & RESOURCED_FORCIBLY_FLUSH_STATE) {
			arg->opts->state &= ~RESOURCED_FORCIBLY_FLUSH_STATE;
			if (broadcast_edbus_signal(
				    RESOURCED_PATH_NETWORK,
				    RESOURCED_INTERFACE_NETWORK,
				    RESOURCED_NETWORK_UPDATE_FINISH,
				    DBUS_TYPE_INVALID, NULL))
				_E("Failed to send DBUS message\n");
		}
	}
}

inline void netlink_release(struct genl *ans)
{
	free(ans);
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

static const struct edbus_method edbus_methods[] = {
	{ RESOURCED_NETWORK_UPDATE, NULL, NULL, edbus_update_counters },
	{ RESOURCED_NETWORK_PROCESS_RESTRICTION, NULL, NULL,
	  edbus_process_restriction },
};

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


	error = edbus_add_methods(RESOURCED_PATH_NETWORK, edbus_methods,
			  ARRAY_SIZE(edbus_methods));

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

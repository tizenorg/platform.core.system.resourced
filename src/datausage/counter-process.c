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
#include "datausage-quota.h"
#include "datausage-quota-processing.h"
#include "datausage-restriction.h"
#include "edbus-handler.h"
#include "generic-netlink.h"
#include "macro.h"
#include "module-data.h"
#include "notification.h"
#include "resourced.h"
#include "roaming.h"
#include "specific-trace.h"
#include "storage.h"
#include "tethering.h"
#include "trace.h"
#include "transmission.h"

#include <Ecore.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>

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
		ret = send_command(carg->sock, carg->pid, carg->family_id_stat,
			TRAF_STAT_C_GET_CONN_IN);
		if (ret < 0) {
			ETRACE_ERRNO_MSG("Failed to send command to get "
					 "incomming traffic");
			return ECORE_CALLBACK_RENEW;
		}

		ret = send_command(carg->sock, carg->pid, carg->family_id_stat,
			TRAF_STAT_C_GET_PID_OUT);
		if (ret < 0) {
			ETRACE_ERRNO_MSG("Failed to send command to get "
					 "outgoing traffic");
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

	dbus_ret = process_restriction_local(appid, NONE_QUOTA_ID, &rest,
					     rst_type);
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

static void _process_restriction(struct nl_family_params *cmd)
{
	struct traffic_restriction restriction = {0,};
	uint8_t notification_type = RESTRICTION_NOTI_C_UNSPEC;
	char *app_id = NULL;
	resourced_iface_type iftype;
	resourced_restriction_info rst_info = {0,};
	resourced_ret_c ret;

	_D("Restriction notification");

	if (process_netlink_restriction_msg(cmd->ans, &restriction,
	    &notification_type) !=
	    RESOURCED_ERROR_NONE) {
		_E("Failed to process netlink restriction.");
		return;
	}

	app_id = _get_public_appid(restriction.sk_classid);
	iftype = get_iftype(restriction.ifindex);

	ret = get_restriction_info(app_id, iftype, &rst_info);
	ret_value_msg_if(ret != RESOURCED_ERROR_NONE,,
		"Failed to get restriction info!");

	if (notification_type == RESTRICTION_NOTI_C_ACTIVE) {
		if (rst_info.quota_id != NONE_QUOTA_ID)
			send_restriction_notification(app_id);
		update_restriction_db(app_id, iftype, 0, 0,
				      RESOURCED_RESTRICTION_ACTIVATED,
		rst_info.quota_id, rst_info.roaming);
	} else if (notification_type == RESTRICTION_NOTI_C_WARNING) {
		/* nested if due error message correctness */
		if (rst_info.quota_id != NONE_QUOTA_ID)
			send_restriction_warn_notification(app_id);
	} else
		_E("Unkown restriction notification type");
}

static void _process_network_counter(struct nl_family_params *params)
{
	resourced_ret_c ret;
	netlink_serialization_command *netlink =
		netlink_create_command(params->ans, params->carg);

	if (!netlink) {
		_E("Can not create command");
		return;
	}

	netlink->deserialize_answer(&(netlink->params));

	/* process only filled in/out or tethering traffic */
	if ((!g_tree_nnodes(params->carg->in_tree) ||
	     !g_tree_nnodes(params->carg->out_tree)) &&
	    !add_tethering_traffic_info(params->carg->result) &&
	    params->carg->opts->state & RESOURCED_FORCIBLY_QUIT_STATE)
		return;

	ret = prepare_application_stat(params->carg->in_tree,
			params->carg->out_tree, params->carg->result,
		params->carg->opts);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to prepare application statistics!");
		return;
	}
	ret = process_quota(params->carg->result, params->carg->opts);
	if (ret != 0) {
		_E("Failed to process quota!");
		return;
	}

	WALK_TREE(params->carg->result->tree, print_appstat);

	_store_and_free_result(params->carg);

	g_tree_ref(params->carg->out_tree);
	free_traffic_stat_tree(params->carg->out_tree);
	g_tree_ref(params->carg->in_tree);
	free_traffic_stat_tree(params->carg->in_tree);
}


static nl_family_serialization_command *_create_family_command(struct genl *ans,
	struct counter_arg *carg)
{
	int family;
	static nl_family_serialization_command command;

	if (!ans || !carg) {
		_E("Please provide valid pointer!");
		return NULL;
	}

	if (!command.params.carg)
		command.params.carg = carg;

	command.params.ans = ans;

	family = netlink_get_family(ans);

	if (family == carg->family_id_restriction)
		command.process = _process_restriction;
	else if (family == carg->family_id_stat)
		command.process = _process_network_counter;
	else {
		_E("General netlink family %d unsupported,\
		    restriction_id %d, stat_id %d", family,
			carg->family_id_restriction, carg->family_id_stat);
		return NULL;
	}

	return &command;
}

static Eina_Bool _answer_func_cb(void *user_data, Ecore_Fd_Handler *fd_handler)
{
	struct counter_arg *carg = (struct counter_arg *)user_data;
	struct genl *ans = NULL;
	nl_family_serialization_command *netlink_handler = NULL;

	ans = netlink_read(carg->sock);
	if (ans == NULL)
		goto out;

	netlink_handler = _create_family_command(ans, carg);

	if (!netlink_handler)
		goto out;

	netlink_handler->process(&(netlink_handler->params));

	netlink_release(ans);

out:
	return ECORE_CALLBACK_RENEW;
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

	carg->sock = create_netlink(NETLINK_GENERIC, 0);

	ret_value_msg_if(carg->sock < 0, RESOURCED_ERROR_FAIL,
		"Failed to create and bind netlink socket.");

	carg->family_id_stat = get_family_id(carg->sock,
		carg->pid, "TRAF_STAT");
	if (carg->family_id_stat == 0) {
		_E("Failed to get family id for TRAF_STAT.");
		error = RESOURCED_ERROR_FAIL;
		goto release_sock;
	}

	carg->family_id_restriction = get_family_id(carg->sock,
		carg->pid, "REST_NOTI");

	if (carg->family_id_restriction ==  0) {
		_E("Failed to get family id for REST_NOTI.");
		error = RESOURCED_ERROR_FAIL;
		goto release_sock;
	}
	/*thereafter we'll be able to receive message from server */
	send_start(carg->sock, carg->pid, carg->family_id_stat);

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

	carg->ecore_fd_handler = ecore_main_fd_handler_add(
		carg->sock, ECORE_FD_READ, _answer_func_cb, carg, NULL, NULL);
	_D("ecore_carg_handler = %p", carg->ecore_fd_handler);

	return error;

release_sock:
	close(carg->sock);
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

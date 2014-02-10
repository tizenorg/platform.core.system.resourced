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
 * @file restriction-handler.c
 *
 * @desc Callback for working reset restrictions
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <data_usage.h>
#include <stdlib.h>
#include <net/if.h>

#include "iface.h"
#include "macro.h"
#include "trace.h"
#include "restriction-helper.h"
#include "datausage-restriction.h"
#include "restriction-handler.h"

struct restriction_context {
	int ifindex;
	list_restrictions_info *restrictions;
};

static gpointer _create_reset_restriction(
	const resourced_restriction_info *info, const int ifindex)
{
	resourced_iface_type iftype;
	resourced_restriction_info *res_data;

	iftype = get_iftype(ifindex);
	if (info->iftype != iftype)
		return NULL;

	res_data = (resourced_restriction_info *)
		malloc(sizeof(resourced_restriction_info));
	if (!res_data) {
		_E("Malloc of resourced_restriction_info failed\n");
		return NULL;
	}
	res_data->app_id = strdup(info->app_id);
	res_data->iftype = iftype;
	res_data->rcv_limit = info->rcv_limit;
	res_data->send_limit = info->send_limit;
	res_data->rst_state = info->rst_state;
	res_data->quota_id = info->quota_id;
	res_data->roaming = info->roaming;
	return res_data;
}

static resourced_cb_ret _restriction_iter(
	const resourced_restriction_info *info, void *user_data)
{
	struct restriction_context *context =
		(struct restriction_context *)(user_data);

	if (!context) {
		_E("Please provide valid pointer!");
		return RESOURCED_CONTINUE;
	}

	_SI("we have restriction for appid %s and check it for ifindex %d\n",
	   info->app_id, context->ifindex);
	gpointer data = _create_reset_restriction(info, context->ifindex);
	if (data)
		context->restrictions = g_list_prepend(context->restrictions,
			data);
	return RESOURCED_CONTINUE;
}

static void _reset_restrictions_iter(gpointer data, gpointer user_data)
{
	resourced_restriction_info *arg = (resourced_restriction_info *)data;
	resourced_net_restrictions rst = {0};
	int error_code = RESOURCED_ERROR_NONE;
	enum traffic_restriction_type rst_type;

	ret_value_msg_if(!arg, , "Please provide valid pointer!");

	rst.iftype = arg->iftype;
	rst.send_limit = arg->send_limit;
	rst.rcv_limit = arg->rcv_limit;
	rst.roaming = arg->roaming;
	rst_type = convert_to_restriction_type(arg->rst_state);
	error_code = process_restriction_local(arg->app_id, arg->quota_id, &rst,
					       rst_type);

	ret_value_msg_if(error_code != RESOURCED_ERROR_NONE, ,
			 "restriction type %d failed, error %d\n", rst_type,
			 error_code);
	return;
}

static void _apply_reset_restrictions(const list_restrictions_info *restrictions)
{
	if (!restrictions) {
		_D("No restrictions!");
		return;
	}
	g_list_foreach((GList *)restrictions, _reset_restrictions_iter, NULL);
}

static void _free_restriction_iter(gpointer data)
{
	resourced_restriction_info *arg = (resourced_restriction_info *)data;
	if (!arg) {
		_D("No restrictions!");
		return;
	}
	free((char *)arg->app_id);
	return;
}

static void _free_reset_restrictions(list_restrictions_info *restrictions)
{
	if (!restrictions) {
		_E("Plese provide valid pointer!");
		return;
	}
	g_list_free_full(restrictions, _free_restriction_iter);
}

static void _handle_on_iface_up(const int ifindex)
{
	/* Create local list of restriction for thread safety */
	struct restriction_context context = {
		.restrictions = 0,
		.ifindex = ifindex,
	};

	init_iftype();
	restrictions_foreach(_restriction_iter, &context);
	if (!context.restrictions) {
		_D("No restrictions!");
		return;
	}
	_apply_reset_restrictions(context.restrictions);
	_free_reset_restrictions(context.restrictions);
}

static resourced_cb_ret roaming_restrictions_iter(
	const resourced_restriction_info *info, void *user_data)
{
	_reset_restrictions_iter((gpointer)info, (gpointer)user_data);
	return RESOURCED_CONTINUE;
}

static void handle_roaming_change(void)
{
	restrictions_foreach(roaming_restrictions_iter, NULL);
}

roaming_cb get_roaming_restriction_cb(void)
{
	return handle_roaming_change;
}

iface_callback *create_restriction_callback(void)
{
	iface_callback *ret_arg = (iface_callback *)
		malloc(sizeof(iface_callback));

	if (!ret_arg) {
		_E("Malloc of iface_callback failed\n");
		return NULL;
	}
	ret_arg->handle_iface_up = _handle_on_iface_up;
	ret_arg->handle_iface_down = NULL;

	return ret_arg;
}

void reactivate_restrictions(void)
{
	int i;
	struct if_nameindex *ids = if_nameindex();

	ret_value_msg_if(ids == NULL, ,
			 "Failed to initialize iftype table! errno: %d, %s",
			 errno, strerror(errno));

	for (i = 0; ids[i].if_index != 0; ++i)
		_handle_on_iface_up(ids[i].if_index);

	if_freenameindex(ids);
}

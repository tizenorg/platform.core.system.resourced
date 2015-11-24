 /*
 * resourced
 *
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file network-dummy.c
 *
 * @desc Dummy definitions of the data_usage library
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>

#include "macro.h"
#include "data_usage.h"
#include "resourced.h"

API resourced_ret_c set_resourced_options(const resourced_options *options)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c get_resourced_options(resourced_options *options)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c set_net_restriction(const char *app_id,
		const resourced_net_restrictions *restriction)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c restrictions_foreach(resourced_restriction_cb restriction_cb, void *user_data)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c remove_restriction(const char *app_id)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c exclude_restriction(const char *app_id)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c exclude_restriction_by_iftype(const char *app_id,
		const resourced_iface_type iftype)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c set_net_exclusion(const char *app_id,
		const resourced_net_restrictions *rst)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c register_net_activity_cb(net_activity_cb activity_cb)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c resourced_update_statistics(void)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c data_usage_foreach(const data_usage_selection_rule *rule,
		data_usage_info_cb info_cb, void *user_data)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c data_usage_details_foreach(const char *app_id, data_usage_selection_rule *rule,
		data_usage_info_cb info_cb, void *user_data)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c reset_data_usage(const data_usage_reset_rule *rule)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c remove_datausage_quota(const struct datausage_quota_reset_rule *rule)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c remove_datausage_quota_by_iftype(const char *app_id,
		const resourced_iface_type iftype)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c set_datausage_quota(const char *app_id,
		const data_usage_quota *quota)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c get_restriction_state(const char *pkg_id, resourced_iface_type iftype,
		resourced_restriction_state *state)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c remove_restriction_by_iftype(const char *app_id,
		const resourced_iface_type iftype)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c remove_restriction_full(const char *app_id,
		const resourced_net_restrictions *restriction)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c resourced_remove_restriction(const char *app_id, char *imsi)
{
	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c resourced_remove_restriction_by_iftype(const char *app_id,
		const resourced_iface_type iftype, char *imsi)
{
	return RESOURCED_ERROR_NONE;
}

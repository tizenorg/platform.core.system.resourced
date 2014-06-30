/*
 * resourced
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file stub-datausage-API-min.c
 * @desc Implement datausage API stubs
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "const.h"
#include "data_usage.h"
#include "trace.h"
#include "resourced.h"

static resourced_ret_c no_datausage(void)
{
	_E("Datausage is not fully supported\n");
	return RESOURCED_ERROR_NOTIMPL;
}

API resourced_ret_c reset_data_usage(const data_usage_reset_rule *rule)
{
	return no_datausage();
}

API resourced_ret_c remove_datausage_quota(
	const struct datausage_quota_reset_rule *rule)
{
	return no_datausage();
}

API resourced_ret_c remove_datausage_quota_by_iftype(
	const char *app_id, const resourced_iface_type iftype)
{
	return no_datausage();
}

API resourced_ret_c set_datausage_quota(const char *app_id,
					const data_usage_quota *quota)
{
	return no_datausage();
}

API resourced_ret_c resourced_update_statistics(void)
{
	return no_datausage();
}

API resourced_ret_c register_net_activity_cb(net_activity_cb activity_cb)
{
	return no_datausage();
}

API resourced_ret_c data_usage_foreach(const data_usage_selection_rule *rule,
				       data_usage_info_cb info_cb,
				       void *user_data)
{
	return no_datausage();
}

API resourced_ret_c data_usage_details_foreach(
	const char *app_id, data_usage_selection_rule *rule,
	data_usage_info_cb info_cb, void *user_data)
{
	return no_datausage();
}

API resourced_ret_c set_net_restriction(const char *app_id,
					const resourced_net_restrictions *rst)
{
	return no_datausage();
}

API resourced_ret_c restrictions_foreach(
	resourced_restriction_cb restriction_cb, void *user_data)
{
	return no_datausage();
}

API resourced_ret_c remove_restriction(const char *app_id)
{
	return remove_restriction_by_iftype(app_id, RESOURCED_IFACE_ALL);
}

API resourced_ret_c remove_restriction_by_iftype(
	const char *app_id, const resourced_iface_type iftype)
{
	return no_datausage();
}

API resourced_ret_c exclude_restriction(const char *app_id)
{
	return exclude_restriction_by_iftype(app_id, RESOURCED_IFACE_ALL);
}

API resourced_ret_c exclude_restriction_by_iftype(
	const char *app_id, const resourced_iface_type iftype)
{
	return no_datausage();
}


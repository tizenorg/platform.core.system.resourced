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
 */

/*
 *  @file: datausage-vconf-callbacks.c
 *
 *  @desc Add datausage callback functions to vconf
 *
 */

#include "const.h"
#include "counter.h"
#include "daemon-options.h"
#include "datausage-vconf-callbacks.h"
#include "datausage-quota-processing.h"
#include "datausage-quota.h"
#include "iface.h"
#include "macro.h"
#include "resourced.h"
#include "settings.h"
#include "tethering.h"
#include "trace.h"

#include <stdlib.h>
#include <vconf.h>

static void _fill_quota_arg(char *quota_value,
			    char **app_id, resourced_iface_type *iftype,
			    time_t *start_time, int *time_period,
			    resourced_roaming_type *roaming)
{
	char *value = strtok(quota_value, COMMA_DELIMETER);
	if (!value)
		goto handle_error;

	*app_id = strdup(value);

	value = strtok(NULL, COMMA_DELIMETER);
	if (!value)
		goto handle_error;

	*iftype = atoi(value);

	value = strtok(NULL, COMMA_DELIMETER);
	if (!value)
		goto handle_error;
	*roaming = (resourced_roaming_type)atoi(value);


	value = strtok(NULL, COMMA_DELIMETER);
	if (!value)
		goto handle_error;

	*start_time = atol(value);

	value = strtok(NULL, COMMA_DELIMETER);
	if (!value)
		goto handle_error;

	*time_period = atoi(value);

	return;
handle_error:
	_D("Can not parse quota_delete argument! %s", quota_value);
}

static void wifi_change_cb(keynode_t *key, void *data)
{
	int val = vconf_keynode_get_bool(key);
	_SD("key = %s, value = %d(int)\n",
	    vconf_keynode_get_name(key), val);
	set_wifi_allowance(val ?
			   RESOURCED_OPTION_ENABLE : RESOURCED_OPTION_DISABLE);
}

static void datacall_change_cb(keynode_t *key, void *data)
{
	int val = vconf_keynode_get_bool(key);

	_SD("key = %s, value = %d(int)\n",
	    vconf_keynode_get_name(key), val);
	set_datacall_allowance(val ? RESOURCED_OPTION_ENABLE :
			       RESOURCED_OPTION_DISABLE);
}

static void datacall_logging_change_cb(keynode_t *key, void *data)
{
	struct daemon_opts *options = (struct daemon_opts *)data;
	int val = vconf_keynode_get_bool(key);

	if (!options) {
		_E("Please provide valid argument!");
		return;
	}
	_SD("key = %s, value = %d(int)\n",
	    vconf_keynode_get_name(key), val);
	options->datacall_logging = val ? RESOURCED_OPTION_ENABLE :
		RESOURCED_OPTION_DISABLE;
}

static void datausage_timer_change_cb(keynode_t *key, void *data)
{
	struct daemon_opts *options = (struct daemon_opts *)data;
	int val = vconf_keynode_get_int(key);

	if (!options) {
		_E("Please provide valid argument!");
		return;
	}
	_SD("key = %s, value = %d(int)\n",
	    vconf_keynode_get_name(key), val);

	options->update_period = val;
}

static void datausage_new_limit_cb(keynode_t *key, void *data)
{
	struct counter_arg *carg = (struct counter_arg *)data;
	char *app_id = UNKNOWN_APP;
	resourced_iface_type iftype = RESOURCED_IFACE_UNKNOWN;
	time_t start_time = 0;
	int time_period = 0;
	resourced_roaming_type roaming = RESOURCED_ROAMING_UNKNOWN;

	_SD("Datausage quota changed");
	_fill_quota_arg(vconf_keynode_get_str(key),
			&app_id, &iftype, &start_time, &time_period,
			&roaming);
	update_quota_state(app_id, iftype, start_time, time_period, roaming);

	ret_value_msg_if(!carg || !carg->opts, ,
			 "Please provide valid argument!");
	carg->opts->is_update_quota = 1;
	reschedule_count_timer(carg, 0);
}

static void datausage_delete_limit_cb(keynode_t *key, UNUSED void *data)
{
	char *app_id = UNKNOWN_APP;
	resourced_iface_type iftype = RESOURCED_IFACE_UNKNOWN;
	time_t start_time = 0;
	int time_period = 0;
	resourced_roaming_type roaming = RESOURCED_ROAMING_UNKNOWN;

	/* TODO workaround we stil not using another IPC */
	_fill_quota_arg(vconf_keynode_get_str(key),
			&app_id, &iftype, &start_time, &time_period,
			&roaming);

	update_quota_state(app_id, iftype, start_time, time_period, roaming);
}

void resourced_add_vconf_datausage_cb(struct counter_arg *carg)
{
	_D("Add vconf datausage callbacks\n");
	ret_value_msg_if(!carg || !carg->opts, ,
			 "Please provide valid argument!");
	vconf_notify_key_changed(RESOURCED_WIFI_STATISTICS_PATH, wifi_change_cb,
				 NULL);
	vconf_notify_key_changed(RESOURCED_DATACALL_PATH, datacall_change_cb,
				 NULL);
	vconf_notify_key_changed(RESOURCED_DATAUSAGE_TIMER_PATH,
				 datausage_timer_change_cb, (void *)carg->opts);
	vconf_notify_key_changed(RESOURCED_DATACALL_LOGGING_PATH,
				 datacall_logging_change_cb,
				 (void *)carg->opts);
	vconf_notify_key_changed(RESOURCED_NEW_LIMIT_PATH,
				 datausage_new_limit_cb, (void *)carg);
	vconf_notify_key_changed(RESOURCED_DELETE_LIMIT_PATH,
				 datausage_delete_limit_cb, NULL);
	vconf_notify_key_changed(VCONFKEY_MOBILE_HOTSPOT_MODE,
				 tethering_state_change_cb, NULL);
}

void resourced_remove_vconf_datausage_cb(void)
{
	_D("Remove vconf datausage callbacks\n");
	vconf_ignore_key_changed(RESOURCED_WIFI_STATISTICS_PATH,
				 wifi_change_cb);
	vconf_ignore_key_changed(RESOURCED_DATACALL_PATH, datacall_change_cb);
	vconf_ignore_key_changed(RESOURCED_DATAUSAGE_TIMER_PATH,
				 datausage_timer_change_cb);
	vconf_ignore_key_changed(RESOURCED_DATACALL_LOGGING_PATH,
				 datacall_logging_change_cb);
	vconf_ignore_key_changed(RESOURCED_NEW_LIMIT_PATH,
				 datausage_new_limit_cb);
	vconf_ignore_key_changed(RESOURCED_DELETE_LIMIT_PATH,
				 datausage_delete_limit_cb);
	vconf_ignore_key_changed(VCONFKEY_MOBILE_HOTSPOT_MODE,
				 tethering_state_change_cb);
}

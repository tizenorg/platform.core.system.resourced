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
 * @file tethering.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "app-stat.h"
#include "cgroup.h"
#include "const.h"
#include "resourced.h"
#include "roaming.h"
#include "tethering.h"
#include "trace.h"

#include <sys/types.h>
#include <glib.h>
#include <stdbool.h>
#include <vconf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <network/network-cm-intf.h>

static bool register_client;
static bool tethering_init;
static char active_net_if_name[MAX_IFACE_NAME_LENGTH];
static resourced_iface_type active_net_if_type;
static int mobileap_state = VCONFKEY_MOBILE_HOTSPOT_MODE_NONE;
static long total_snd_bytes;
static long total_rcv_bytes;

enum tethering_ret_c {
	TETHERING_ERROR_OK,		/*<< successfull */
	TETHERING_ERROR_OFF,		/*<< tethering is off */
	TETHERING_ERROR_NOTSUPPORTED,	/*<< tethering is not supported */
	TETHERING_ERROR_PROFILE,	/*<< cant creat or use network profile */
	TETHERING_ERROR_GET,		/*<< failed to get tethering */
};

static bool tethering_state_is_on(const int state)
{
	return mobileap_state & state;
}

static bool tethering_is_on(void)
{
	return tethering_state_is_on(MOBILE_AP_STATE_WIFI) ||
	       tethering_state_is_on(MOBILE_AP_STATE_BT) ||
	       tethering_state_is_on(MOBILE_AP_STATE_USB);
}

static void copy_if_name(const char *src)
{
	strncpy(active_net_if_name, src, sizeof(active_net_if_name) - 1);
	active_net_if_name[sizeof(active_net_if_name) - 1] = '\0';
}

static enum tethering_ret_c init_name_type_iface(
	const net_profile_info_t *const profile_info)
{
	switch (profile_info->profile_type) {
	case NET_DEVICE_CELLULAR:
		copy_if_name(profile_info->ProfileInfo.Pdp.net_info.DevName);
		active_net_if_type = RESOURCED_IFACE_DATACALL;
		return TETHERING_ERROR_OK;
	case NET_DEVICE_WIFI:
		copy_if_name(profile_info->ProfileInfo.Wlan.net_info.DevName);
		active_net_if_type = RESOURCED_IFACE_WIFI;
		return TETHERING_ERROR_OK;
	case NET_DEVICE_ETHERNET:
		copy_if_name(
			profile_info->ProfileInfo.Ethernet.net_info.DevName);
		active_net_if_type = RESOURCED_IFACE_WIRED;
		return TETHERING_ERROR_OK;
	case NET_DEVICE_BLUETOOTH:
		copy_if_name(
			profile_info->ProfileInfo.Bluetooth.net_info.DevName);
		active_net_if_type = RESOURCED_IFACE_BLUETOOTH;
		return TETHERING_ERROR_OK;
	case NET_DEVICE_DEFAULT:
	case NET_DEVICE_USB:
	case NET_DEVICE_UNKNOWN:
	case NET_DEVICE_MAX:
	default:
		_E("Unknown type of network active profile\n");
	}
	return TETHERING_ERROR_PROFILE;
}

static void profile_evt_cb(net_event_info_t *event_cb, void *user_data)
{
	/* Handling events associated with the profile is not required */
}

static net_err_t register_client_in_libnet(void)
{
	net_err_t error;

	if (register_client)
		return NET_ERR_NONE;
	error = net_register_client_ext((net_event_cb_t)profile_evt_cb,
					NET_DEVICE_DEFAULT, NULL);
	if (error != NET_ERR_NONE)
		_E("Not registered in libnet\n");
	else {
		_D("Successful registered in libnet\n");
		register_client = true;
	}
	return error;
}

static enum tethering_ret_c init_profile(void)
{
	net_err_t net_error;
	net_profile_info_t active_profile = {0};

	net_error = register_client_in_libnet();
	if (net_error != NET_ERR_NONE) {
		_E("Failed to register client in libnet");
		return TETHERING_ERROR_PROFILE;
	}

	net_error = net_get_active_net_info(&active_profile);
	if (net_error == NET_ERR_NO_SERVICE) {
		_E("No active network connection\n");
		return TETHERING_ERROR_PROFILE;
	} else if (net_error != NET_ERR_NONE) {
		_E("Get active network connection profile failed\n");
		return TETHERING_ERROR_PROFILE;
	}
	return init_name_type_iface(&active_profile);
}

static enum tethering_ret_c check_init(void)
{
	if (tethering_is_on() == false) {
		_SD("Tethering is off\n");
		tethering_init = false;
	} else {
		_SD("Tethering is on\n");
		tethering_init = true;
	}
	return tethering_init ? TETHERING_ERROR_OK : TETHERING_ERROR_OFF;
}

static enum tethering_ret_c _initialization(void)
{
	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &mobileap_state)) {
		_E("vconf_get_int FAIL\n");
		return TETHERING_ERROR_NOTSUPPORTED;
	}
	return check_init();
}

static enum tethering_ret_c _get_traffic_value(const char *src, const char *dst,
				    long *const value)
{
	int error;
	enum tethering_ret_c ret_value = TETHERING_ERROR_OK;
	FILE *f = NULL;
	char command[MAX_COMMAND_LENGTH];
	char num_bytes[MAX_NUM_LENGTH];

	error = CREATE_COMMAND(command, src, dst);
	ret_value_errno_msg_if(error < 0 || error >= sizeof(command),
			       TETHERING_ERROR_GET,
			       "Can't create command for iptables.");
	f = popen(command, "r");
	ret_value_errno_msg_if(!f, TETHERING_ERROR_GET,
			       "Can't open pipe to iptables.");
	*value = 0;
	while (fgets(num_bytes,  sizeof(num_bytes), f)) {
		/* to safely call atol function */
		num_bytes[sizeof(num_bytes) - 1] = '\0';
		*value += atol(num_bytes);
	}
	if (ferror(f)) {
		ETRACE_ERRNO_MSG("Can't read from iptable pipe.");
		ret_value = TETHERING_ERROR_GET;
	}
	pclose(f);
	return ret_value;
}

static enum tethering_ret_c _get_tethering_traffic(const char *src,
					     long *const tx, long *const rx)
{
	int error = _get_traffic_value(src, active_net_if_name, tx);
	if (error != TETHERING_ERROR_OK)
		return error;
	return _get_traffic_value(active_net_if_name, src, rx);
}

static enum tethering_ret_c _get_tethering_traffic_all_states(
	long *const snd_bytes, long *const rcv_bytes)
{
	int error = TETHERING_ERROR_OK;
	_SD("Value of VCONFKEY_MOBILE_HOTSPOT_MODE = %d\n", mobileap_state);
	if (tethering_state_is_on(MOBILE_AP_STATE_WIFI) == true)
		error = _get_tethering_traffic(WIFI_IF, snd_bytes, rcv_bytes);
	if ((tethering_state_is_on(MOBILE_AP_STATE_BT) == true) &&
	    (error == TETHERING_ERROR_OK))
		error = _get_tethering_traffic(BT_IF, snd_bytes, rcv_bytes);
	if ((tethering_state_is_on(MOBILE_AP_STATE_USB) == true) &&
	    (error == TETHERING_ERROR_OK))
		error = _get_tethering_traffic(USB_IF, snd_bytes, rcv_bytes);
	if (error != TETHERING_ERROR_OK)
		_E("Error getting information of network interfaces\n");
	return error;
}

static bool adjust_with_delta_tethering_traffic(long *const snd_bytes,
						long *const rcv_bytes)
{
	long delta_snd_bytes;
	long delta_rcv_bytes;

	delta_snd_bytes = *snd_bytes - total_snd_bytes;
	delta_rcv_bytes = *rcv_bytes - total_rcv_bytes;

	if (!delta_snd_bytes && !delta_rcv_bytes) {
		_D("No new tethering traffic\n");
		return false;
	}

	total_snd_bytes = *snd_bytes;
	total_rcv_bytes = *rcv_bytes;
	if (delta_snd_bytes >= 0)
		*snd_bytes = delta_snd_bytes;
	if (delta_rcv_bytes >= 0)
		*rcv_bytes = delta_rcv_bytes;
	return true;
}

static void _add_tethering_app_in_tree(
	struct application_stat_tree *app_stat_tree,
	const long *const snd_bytes, const long *const rcv_bytes)
{
	struct classid_iftype_key *key;
	struct application_stat *app_stat;

	key = g_new(struct classid_iftype_key, 1);
	if (!key) {
		_E("Can't allocate %d bytes for classid_iftype_key\n",
		   sizeof(struct classid_iftype_key));
		return;
	}
	key->classid = RESOURCED_TETHERING_APP_CLASSID;
	key->iftype = active_net_if_type;
	app_stat = (struct application_stat *)
		g_tree_lookup((GTree *)app_stat_tree->tree, key);
	if (app_stat) {
		app_stat->rcv_count += (u_int32_t)(*rcv_bytes);
		app_stat->snd_count += (u_int32_t)(*snd_bytes);
	} else {
		app_stat = g_new(struct application_stat, 1);
		if (!app_stat) {
			_E("Can't allocate %d bytes for application_stat\n",
			   sizeof(struct application_stat));
			g_free(key);
			return;
		}
		memset(app_stat, 0, sizeof(struct application_stat));
		app_stat->application_id = strdup(TETHERING_APP_NAME);
		app_stat->snd_count = (u_int32_t)(*snd_bytes);
		app_stat->rcv_count = (u_int32_t)(*rcv_bytes);
		app_stat->is_roaming = get_roaming();
		g_tree_insert((GTree *)app_stat_tree->tree, key, app_stat);
	}
}

int add_tethering_traffic_info(
	struct application_stat_tree *app_stat_tree)
{
	bool have_new_traffic = false;
	long rcv_bytes = 0;
	long snd_bytes = 0;

	execute_once {
		_initialization();
	}

	if (tethering_init == false || init_profile() != TETHERING_ERROR_OK ||
	    _get_tethering_traffic_all_states(&snd_bytes, &rcv_bytes)
	    != TETHERING_ERROR_OK)
		return false;

	have_new_traffic = adjust_with_delta_tethering_traffic(&snd_bytes,
							       &rcv_bytes);
	if (have_new_traffic == true)
		_add_tethering_app_in_tree(app_stat_tree,
					   &snd_bytes, &rcv_bytes);
	return have_new_traffic;
}

void tethering_state_change_cb(keynode_t *key, void UNUSED *data)
{
	mobileap_state = vconf_keynode_get_int(key);
	check_init();
}

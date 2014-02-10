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
 *  @file: tethering.h
 *
 *  Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef _TRAFFIC_CONTROL_TETHERING_H_
#define _TRAFFIC_CONTROL_TETHERING_H_

#include "resourced.h"
#include "app-stat.h"
#include "macro.h"

#include <vconf.h>

#define MAX_COMMAND_LENGTH 256
#define MAX_NUM_LENGTH 32
#define MAX_IFACE_NAME_LENGTH 16
#define WIFI_IF "wlan0"
#define USB_IF "usb0"
#define BT_IF "bnep+"
#define IPTABLES "/usr/sbin/iptables"
#define IPTABLES_CHAIN "teth_filter_fw"
#define IPTABLES_TARGET "RETURN"
#define GREP "/bin/grep"
#define AWK  "/usr/bin/awk"
#define MOBILE_AP_STATE_NONE 0
#define MOBILE_AP_STATE_WIFI 1
#define MOBILE_AP_STATE_USB 2
#define MOBILE_AP_STATE_BT 4
#define MOBILE_AP_STATE_ALL 7

#define CREATE_COMMAND(command, source, destination) \
	snprintf(command, sizeof(command), \
		 "%s -L %s -vx | %s \".*%s.*%s[ ]*%s\" | %s '{ print $2 }'", \
		 IPTABLES, IPTABLES_CHAIN, GREP, IPTABLES_TARGET, source, \
		 destination, AWK)

/**
 * @desc add tethering app with traffic statistics to application tree
 * @param app_stat_tree - struct with tree of apps statistics
 * @return 1 if have new traffic, otherwise 0
 */
int add_tethering_traffic_info(struct application_stat_tree *app_stat_tree);

void tethering_state_change_cb(keynode_t *key, void UNUSED *data);

#endif  /*_TRAFFIC_CONTROL_TETHERING_H_ */

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

/*
 * @file genl.h
 * @desc Definitions of constants for traffic statistic
 */


#ifndef _KERNEL_MODULE_TRAFFIC_STAT_GEN_NETLINK_H_
#define _KERNEL_MODULE_TRAFFIC_STAT_GEN_NETLINK_H_

/* attributes*/
enum {
	TRAF_STAT_A_UNSPEC,
	TRAF_STAT_A_MSG,
	TRAF_STAT_DATA_IN,
	TRAF_STAT_DATA_OUT,
	TRAF_STAT_COUNT,
	TRAF_STAT_DATA_RESTRICTION,
	__TRAF_STAT_A_MAX,
};

/*
 * commands: enumeration of all commands (functions),
 * used by userspace application to identify command to be executed
 */
enum {
	TRAF_STAT_C_UNSPEC,
	TRAF_STAT_C_START,
	TRAF_STAT_C_GET_PID_OUT,
	TRAF_STAT_C_GET_CONN_IN,
	TRAF_STAT_C_STOP,
	TRAF_STAT_C_SET_RESTRICTIONS,
	__TRAF_STAT_C_MAX,
};

enum {
	RESTRICTION_NOTI_A_UNSPEC,
	RESTRICTION_A_CLASSID,
	RESTRICTION_A_IFINDEX,
	__RESTRICTION_NOTI_A_MAX,
};

enum {
	RESTRICTION_NOTI_C_UNSPEC,
	RESTRICTION_NOTI_C_ACTIVE,
	RESTRICTION_NOTI_C_WARNING,
	__RESTRICTION_NOTI_C_MAX,
};

enum {
        NET_ACTIVITY_A_UNSPEC,
        NET_ACTIVITY_A_DATA_IN,
        NET_ACTIVITY_A_DATA_OUT,
        __NET_ACTIVITY_A_MAX,
};

enum {
        NET_ACTIVITY_C_UNSPEC,
        NET_ACTIVITY_C_START,
        NET_ACTIVITY_C_STOP,
        __NET_ACTIVITY_C_MAX,
};

#endif	/*_KERNEL_MODULE_TRAFFIC_STAT_GEN_NETLINK_H_ */

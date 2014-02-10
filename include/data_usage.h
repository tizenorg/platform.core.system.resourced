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
 *  @file: data_udage.h
 *
 *  @desc Data usage API
 *  @version 1.0
 *
 *  Created on: 28 June, 2012
 */

#ifndef _RESOURCED_DATA_USAGE_H_
#define _RESOURCED_DATA_USAGE_H_

#include <resourced.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Selection rule applied for data usage enumeration
 */
typedef struct {
	unsigned char version;
	time_t from;
	time_t to;
	resourced_iface_type iftype;
	int granularity;
} data_usage_selection_rule;

/**
 * @brief Bundle structure for bringing all together application identification
 *     and properties.
 * app_id - application identification - copy it if you in
 *   callback function, don't store raw pointer on it
 * iface - interface name, NULL means all interfaces,
 *   don't store raw pointer on it in the callback function, copy it by value
 * interval - time interval for given result, NULL means entire interval
 * foreground - foreground restrictions and counters
 * background - background restrictions and counters
 */
typedef struct {
	const char *app_id;
	resourced_iface_type iftype;
	resourced_tm_interval *interval;
	resourced_common_info foreground;
	resourced_common_info background;
	resourced_roaming_type roaming;
	resourced_hw_net_protocol_type hw_net_protocol_type;
} data_usage_info;

/**
 * @brief callback for enumerate counters and restrictions
 */
typedef resourced_cb_ret(*data_usage_info_cb) (const data_usage_info *info,
					       void *user_data);

/**
 * The callback is called for each application that used network
 * in between timestamps specified.
 *
 * If interface name is not specified, each application will only appear
 * once with the total traffic used over all interfaces.
 *
 * @brief Data usage enumerate function
 */
resourced_ret_c data_usage_foreach(const data_usage_selection_rule *rule,
			     data_usage_info_cb info_cb, void *user_data);

/**
 * @brief Structure for information on restrictions.
 * app_id - application identification - copy it if you in
 *   callback function, don't store raw pointer on it
 * iftype - type of network interface
 */
typedef struct {
	const char *app_id;
	resourced_iface_type iftype;
	resourced_restriction_state rst_state;
	int rcv_limit;
	int send_limit;
	int quota_id;
	resourced_roaming_type roaming;
} resourced_restriction_info;

/**
 * @brief callback for processing information of restrictions
 */
typedef resourced_cb_ret(*resourced_restriction_cb)(
	const resourced_restriction_info *info, void *user_data);

/**
 * The callback is called for each application that restricted now
 *
 * @brief Restrictions enumerate function
 */
resourced_ret_c restrictions_foreach(resourced_restriction_cb restriction_cb,
				void *user_data);

/**
 * If interface name is specified in rule, the callback will be called
 * exactly 1 time with the total traffic counts for that interface
 * by specified application in the specified time interval.
 *
 * If interface name is not specified, the callback will be called once
 * for each interface used by application during the specified interval.
 * It could be 0 if the application did not use any network interfaces
 * during that period.
 *
 * @brief Data usage details enumerate function
 */
resourced_ret_c data_usage_details_foreach(const char *app_id,
					   data_usage_selection_rule *rule,
					   data_usage_info_cb info_cb,
					   void *user_data);

/**
 * @desc Reset rule. It's statistics erasing description.
 * app_id - Erase statistics per appropriate app_id.
 *	app_id can be NULL in this case erasing all datas
 * iftype - Erase statistics per appropriate network interface type
 *	@see resourced_iface_type, if iftype is RESOURCED_IFACE_LAST_ELEM - erase all
 *	RESOURCED_IFACE_UNKNOW - means undetermined interface
 *	on moment of storing data.
 * interval - It's time interval, @see resourced_tm_interval. It should be set.
 *      Zero interval since 0 till 0 means entire interval.
 * connection_state - It's mask on time interval.
 *	Possible variation LAST and TOTAL for send and received data.
 */
typedef struct {
	unsigned char version;
	char *app_id;
	resourced_iface_type iftype;
	resourced_tm_interval *interval;
	resourced_connection_period_type connection_state;
} data_usage_reset_rule;

resourced_ret_c reset_data_usage(const data_usage_reset_rule *rule);

struct net_activity_info {
	int type;		/*<< ingress/egress */
	char *appid;
	int iftype;
	int bytes;
};

typedef resourced_cb_ret(*net_activity_cb)(struct net_activity_info *info);

/**
 * @desc This function registering callback which invokes per every packet.
 *	Function creates new reading thread and returns.
 */
resourced_ret_c register_net_activity_cb(net_activity_cb activity_cb);

/**
 * @desc This function updates the resourced counters and stores in the database
 */
resourced_ret_c resourced_update_statistics(void);

resourced_ret_c get_restriction_state(const char *pkg_id,
	resourced_iface_type iftype, resourced_restriction_state *state);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _RESOURCED_DATA_USAGE_H_ */

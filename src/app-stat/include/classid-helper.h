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
 *  @file: classid-helper.h
 *
 *  @desc Performance management daemon. Helper function
 *		for working with classid table.
 *  @version 1.0
 *
 */


#ifndef _GRABBER_CONTROL_CLASSID_HELPER_H_
#define _GRABBER_CONTROL_CLASSID_HELPER_H_

#include <sys/types.h>
#include <glib.h>
#include <stdbool.h>

typedef GArray int_array;

/**
 * @desc Get all pids from cgroup
 *     Should be invoked after update_classids
 * @return array, you should free it
 */
int_array *get_monitored_pids(void);

/**
 * @desc update class id - pid table. At present one pid per classid.
 */
int update_classids(void);

/**
 * @desc Get appid from classid task table. At present it is package name.
 */
char *get_app_id_by_pid(const pid_t pid);
char *get_app_id_by_classid(const u_int32_t classid, const bool update_state);

void raise_update_classid(void);

void reduce_udpate_classid(void);

int is_update_classid(void);

#endif	/*_GRABBER_CONTROL_CLASSID_HELPER_H_*/

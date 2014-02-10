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
 *
 */

#include <resourced.h>
#include <sys/types.h>

/*
 * Cgroup creation interface
 */

#ifndef _CGROUP_LIBRARY_CGROUP_H_
#define _CGROUP_LIBRARY_CGROUP_H_

/**
 * @desc Make net_cls cgroup and put in it the given pid and
 * generated classid.
 * If cgroup alreay exists function just put pid in it.
 * @param pid - process, that will be added to cgroup pkg_name,
 * @param pkg_name - package name.
 */
resourced_ret_c make_net_cls_cgroup_with_pid(const int pid,
	const char *pkg_name);

/**
 * @desc take classid from net_cls cgroup by appid
 *	This function converts appid to pkgname.
 * @param pkg_name - name of the cgroup
 * @param create - in case of true - create cgroup if it's not exists
 * @return classid
 */
u_int32_t get_classid_by_app_id(const char *app_id, int create);


/**
 * @desc take classid from net_cls cgroup with name pkg_name
 * @param pkg_name - name of the cgroup
 * @param create - in case of true - create cgroup if it's not exists
 * @return classid
 */
u_int32_t get_classid_by_pkg_name(const char *pkg_name, int create);

/**
 * @desc Put value to cgroup,
 * @param cgroup_name - cgroup path
 * @param file_name - cgroup content to write
 * @param value - data to write
 * @return negative value if error
 */
int cgroup_write_node(const char *cgroup_name,  const char *file_name, unsigned int value);


#endif /*_CGROUP_LIBRARY_CGROUP_H_*/

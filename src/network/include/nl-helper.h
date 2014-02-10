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

/** @file nl-helper.h
 *
 *  @desc Common netlink helper function
 *
 *  Created on: Jun 25, 2012
 */

#ifndef RESMAN_NL_HELPER_H_
#define RESMAN_NL_HELPER_H_

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define NLA_BUF_MAX 65560	/*(65 * 1024) - used in tc_common,
	 we'll do the same */

/*TODO: move to common place and rewrite because it's from TC*/
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

typedef struct {
	struct nlmsghdr n;
	struct tcmsg t;
	char buf[NLA_BUF_MAX];
} rt_param;

void put_attr(rt_param *arg, int type, const void *data, int data_len);

#endif	/*RESMAN_NL_HELPER_H_ */

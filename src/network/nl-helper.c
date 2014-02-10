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

/**
 *  @file nl-helper.c
 *  @desc Common netlink helper function
 *
 *  Created on: Jun 25, 2012
 */

#include "nl-helper.h"
#include "trace.h"

#include <linux/rtnetlink.h>
#include <string.h>

void put_attr(rt_param *arg, int type, const void *data, int data_len)
{
	struct rtattr *rta = 0;
	size_t rta_len = 0, align_len = 0, align_nlmsg_len = 0;

	if (!arg) {
		_D("Please, provide valid arg");
		return;
	}

	rta_len = RTA_LENGTH(data_len);
	align_len = RTA_ALIGN(data_len);
	align_nlmsg_len = NLMSG_ALIGN(arg->n.nlmsg_len);
	if (align_nlmsg_len + align_len > sizeof(rt_param)) {
		_E("Not enough buffer size to store %d bytes in %d", data_len,
		   sizeof(rt_param));
		return;
	}

	rta = NLMSG_TAIL(&arg->n);
	rta->rta_type = type;
	rta->rta_len = rta_len;

	memcpy(RTA_DATA(rta), data, data_len);
	arg->n.nlmsg_len = align_nlmsg_len + align_len;
}

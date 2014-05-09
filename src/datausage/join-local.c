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

/**
 * @file join.c
 * @desc Implement Performance API. Joining performance control.
 *    Entity for creation cgroup
 */

#include "datausage-common.h"
#include "macro.h"
#include "module.h"
#include "trace.h"

resourced_ret_c join_net_cls(const char *app_id, const pid_t pid)
{
	struct netstat_data_type net_data;
	int ret = RESOURCED_ERROR_NONE;
	uint32_t args[2];
	static const struct module_ops *net_stat;

	if (net_stat == NULL) {
		net_stat = find_module("datausage");
		ret_value_msg_if(net_stat == NULL, ret,
			"Can't find datausage module!");
	}

	args[0] = (uint32_t)app_id;
	args[1] = (uint32_t)pid;

	net_data.op_type = JOIN_NET_CLS;
	net_data.args = args;

	if (net_stat->control)
		ret = net_stat->control(&net_data);
	return ret;
}



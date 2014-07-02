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
 */

/**
 * @file datausage.c
 *
 * @desc Datausage module
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "counter-process.h"
#include "counter.h"
#include "datausage-common.h"
#include "datausage-vconf-callbacks.h"
#include "iface-cb.h"
#include "macro.h"
#include "module-data.h"
#include "module.h"
#include "protocol-info.h"
#include "resourced.h"
#include "restriction-handler.h"
#include "roaming.h"
#include "storage.h"
#include "trace.h"

static int resourced_datausage_init(void *data)
{
	struct modules_arg *marg = (struct modules_arg *)data;
	struct shared_modules_data *m_data = get_shared_modules_data();
	int ret_code;

	_D("Initialize network counter function\n");
	ret_value_msg_if(marg == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
			 "Invalid modules argument\n");
	ret_value_msg_if(m_data == NULL, RESOURCED_ERROR_FAIL,
			 "Invalid shared modules data\n");
	m_data->carg = init_counter_arg(marg->opts);

	ret_code = resourced_init_counter_func(m_data->carg);
	ret_value_msg_if(ret_code < 0, ret_code, "Error init counter func\n");

	return RESOURCED_ERROR_NONE;
}

static int resourced_datausage_finalize(void *data)
{
	struct shared_modules_data *m_data = get_shared_modules_data();

	_D("Finalize network counter function\n");

	resourced_finalize_counter_func(m_data->carg);
	finalize_carg(m_data->carg);
	finalize_storage_stm();
	return RESOURCED_ERROR_NONE;
}

static int resourced_datausage_control(void *data)
{
	struct netstat_data_type *net_arg = (struct netstat_data_type*)data;

	ret_value_msg_if(net_arg == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
		"Please provide valid argument (net_arg)!");
	switch (net_arg->op_type) {
	case JOIN_NET_CLS:
	{
		ret_value_msg_if(net_arg->args == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
			"Please provide valid argument (net_arg->arg)!");

		return join_app_performance((const char *)(net_arg->args[0]), (const pid_t)(net_arg->args[1]));
	}
	default:
		_E("Invalid netstat argument type %d", net_arg->op_type);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;
}

static struct module_ops datausage_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "datausage",
	.init = resourced_datausage_init,
	.exit = resourced_datausage_finalize,
	.control = resourced_datausage_control,
};

MODULE_REGISTER(&datausage_modules_ops)

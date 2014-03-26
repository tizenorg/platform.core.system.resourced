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
 * @file swap-common.c
 * @desc Implement swap API for external module
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "macro.h"
#include "module.h"
#include "module-data.h"
#include "resourced.h"
#include "swap-common.h"
#include "trace.h"

static const struct module_ops *swap;
static int swap_module;

void swap_find_module()
{
	if (!swap_module) {
		swap = find_module("swap");
		swap_module = 1;
	}
}

int swap_control(enum swap_control_type type, unsigned long *args)
{
	struct swap_data_type s_data;
	int ret = RESOURCED_ERROR_NONE;

	if (!swap) {
		swap_find_module();
		if (!swap)
			return ret;
	}

	s_data.data_type.control_type = type;
	s_data.args = args;

	if (swap->control)
		ret = swap->control(&s_data);
	return ret;
}

int swap_status(enum swap_status_type type, unsigned long *args)
{
	int ret = RESOURCED_ERROR_NONE;
	struct swap_data_type s_data;

	if (!swap) {
		swap_find_module();
		if (!swap) {
			if (type == SWAP_CHECK_PID)
				ret = RESOURCED_ERROR_FAIL;
			return ret;
		}
	}

	s_data.data_type.status_type = type;
	s_data.args = args;

	if (swap->status)
		ret = swap->status(&s_data);
	return ret;
}

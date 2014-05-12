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

#include <resourced.h>

#include "appid-helper.h"
#include "cgroup.h"
#include "const.h"
#include "trace.h"

API resourced_ret_c join_app_performance(const char *app_id, const pid_t pid)
{
	char pkgname[MAX_PATH_LENGTH];
	if (!app_id)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	extract_pkgname(app_id, pkgname, sizeof(pkgname));
	return make_net_cls_cgroup_with_pid(pid, pkgname);
}

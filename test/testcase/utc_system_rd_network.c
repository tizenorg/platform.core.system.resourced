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
 */


/*
 * @file utc_system_rd_network.c
 *
 * @desc Core API testcase
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */
#include <tet_api.h>
#include <resourced.h>
#include <rd-network.h>

#define API_NAME_NETWORK_GET_RESTRICTION_STATE "network_get_restriction_state"

static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_system_network_get_restriction_state_p(void);
static void utc_system_network_get_restriction_state_n(void);

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

struct tet_testlist tet_testlist[] = {
	{ utc_system_network_get_restriction_state_p, POSITIVE_TC_IDX },
	{ utc_system_network_get_restriction_state_n, NEGATIVE_TC_IDX },
	{ NULL, 0 },
};

static void startup(void)
{
}

static void cleanup(void)
{
}

/**
 * @brief Positive test case of network_get_restriction_state()
 */
static void utc_system_network_get_restriction_state_p(void)
{
	int ret;
	network_restriction_state state;

	ret = network_get_restriction_state(RESOURCED_ALL_APP, NETWORK_IFACE_ALL, &state);

	dts_check_eq(API_NAME_NETWORK_GET_RESTRICTION_STATE, ret, NETWORK_ERROR_NONE);
}

/**
 * @brief Negative test case of network_get_restriction_state()
 */
static void utc_system_network_get_restriction_state_n(void)
{
	int ret;
	network_restriction_state state;

	ret = network_get_restriction_state(RESOURCED_ALL_APP, NETWORK_IFACE_ALL, NULL);

	dts_check_ne(API_NAME_NETWORK_GET_RESTRICTION_STATE, ret, NETWORK_ERROR_NONE);
}

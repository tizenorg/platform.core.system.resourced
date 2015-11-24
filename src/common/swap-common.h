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
 * @file swap-common.h
 * @desc swap common process
 **/

#ifndef __SWAP_COMMON_H__
#define __SWAP_COMMON_H__

#include "memory-common.h"

enum swap_state {
	SWAP_ARG_START = -1,
	SWAP_OFF,
	SWAP_ON,
	SWAP_ARG_END,
};

struct swap_status_msg {
	enum memcg_type type;
	struct memcg_info *info;
	pid_t pid;
};

enum swap_compact_reason {
	SWAP_COMPACT_LOWMEM_LOW,
	SWAP_COMPACT_LOWMEM_MEDIUM,
	SWAP_COMPACT_SWAP_FULL,
	SWAP_COMPACT_RESASON_MAX,
};

enum swap_state swap_get_state(void);

#endif /* __SWAP_COMMON_H__ */

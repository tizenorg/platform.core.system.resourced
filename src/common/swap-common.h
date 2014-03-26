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

enum swap_control_type {
	SWAP_START,
	SWAP_RESTART,
	SWAP_MOVE_CGROUP,
};

enum swap_status_type {
	SWAP_GET_TYPE,
	SWAP_GET_CANDIDATE_PID,
	SWAP_SET_CANDIDATE_PID,
	SWAP_GET_STATUS,
	SWAP_CHECK_PID,
	SWAP_CHECK_CGROUP,
	SWAP_CHECK_SWAPOUT_COUNT,
};

struct swap_data_type {
	union {
		enum swap_control_type	control_type;
		enum swap_status_type	status_type;
	} data_type;
	unsigned long *args;
};

enum {
	SWAP_OFF,
	SWAP_ON,
	SWAP_ARG_END,
};

enum {
	SWAP_FALSE,
	SWAP_TRUE,
};

#define GBtoB(x)		(x<<30)
#define MBtoB(x)		(x<<20)

#define MBtoPage(x)		(x<<8)

int swap_control(enum swap_control_type type, unsigned long *args);
int swap_status(enum swap_status_type type, unsigned long *args);

#endif /* __SWAP_COMMON_H__ */

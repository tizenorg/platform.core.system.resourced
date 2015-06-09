/*
 * resourced
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file  proc-usage-stats.h
 * @desc  process usage stats module init
 **/

#ifndef __RESOURCED_PROC_USAGE_STATS_H__
#define __RESOURCED_PROC_USAGE_STATS_H__
#include <resourced.h>

/* Initialize proc usage stats module by registering it in edbus. */
resourced_ret_c proc_usage_stats_init(void);

#endif /* __RESOURCED_PROC_USAGE_STATS_H__ */


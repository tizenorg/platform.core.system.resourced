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
 * @file  utils.h
 * @desc  file IO and proc fs functions
 **/

#ifndef __RESOURCED_TESTS_UTILS_H__
#define __RESOURCED_TESTS_UTILS_H__

#include "resourced_tests.h"

/* Memory size conversion macros */
#define kBtoMB(val) (int)((val*1000) >> 20)
#define KBtoB(val) (int)(val << 10)
#define MBtoB(val) (int)(val << 20)

/* File write abstract functions */
int fwrite_str(char *path, char *str);
int fwrite_int(char *path, int num);

/* Proc fs util functions */
unsigned int procfs_get_available(void);
unsigned int procfs_get_total(void);
int procfs_set_oom_score_adj(int pid, int oom);

int pid_exists(int pid);

#endif

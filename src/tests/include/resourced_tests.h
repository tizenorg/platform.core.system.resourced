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
 * @file  resourced_tests.h
 * @desc  common definitions for test package
 **/

#ifndef __RESOURCED_TESTS_H__
#define __RESOURCED_TESTS_H__

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <systemd/sd-journal.h>

#define STRING_MAX 256

#define _E(fmt, arg...) sd_journal_print(LOG_ERR, "[%s,%d] "fmt, __FUNCTION__, __LINE__, ##arg)
#define _D(fmt, arg...) sd_journal_print(LOG_DEBUG, "[%s,%d] "fmt, __FUNCTION__, __LINE__, ##arg)
#define _I(fmt, arg...) sd_journal_print(LOG_INFO, "[%s,%d] "fmt, __FUNCTION__, __LINE__, ##arg)

/* resourced_tests package error codes */
enum {
	ERROR_NONE = 0,
	ERROR_INVALID_INPUT = -1,
	ERROR_IO = -2,
	ERROR_MEMORY = -3,
	ERROR_FAIL = -4,
};

#endif

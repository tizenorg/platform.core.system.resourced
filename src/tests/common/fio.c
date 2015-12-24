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
 * @file  fio.c
 * @desc  File I/O related functions
 **/

#include <errno.h>
#include "resourced_tests.h"

/* File IO abstract function
 * Writes the string (in str) to the file (with path as path)
 */
int fwrite_str(char *path, char *str)
{
	int ret;
	FILE *file;

	file = fopen(path, "w");
	if (!file) {
		_E("IO: Error opening file %s", path);
		return RESOURCED_ERROR_FAIL;
	}

	ret = fputs(str, file);
	fclose(file);

	if (ret < 0)
		return RESOURCED_ERROR_FAIL;
	else
		return RESOURCED_ERROR_NONE;
}

/* File IO abstract function
 * Writes the integer (in num) to the file (with path as path)
 * Uses fwrite_str to accomplish the task
 */
int fwrite_int(char *path, int num)
{
	char content_str[STRING_MAX];

	snprintf(content_str, sizeof(content_str), "%d", num);
	return fwrite_str(path, content_str);
}


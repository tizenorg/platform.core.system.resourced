/*
   Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License
*/

/*
 *  @file: trace.c
 *  @desc: log path handling functions
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>

#include "macro.h"
#include "util.h"
#include "trace.h"

static FILE *log_file = NULL;
static int stdout_bak = -1;
static int stderr_bak = -1;
API enum log_type logtype = LOG_TYPE_DLOG;

int log_close(void)
{
	int r;

	if (!log_file)
		return 0;

	if (fileno(log_file) == STDERR_FILENO)
		return 0;

	fclose(log_file);
	log_file = NULL;

	if (stdout_bak >= 0) {
		r = dup2(stdout_bak, STDOUT_FILENO);
		if (r < 0)
			return -errno;

		close(stdout_bak);
	}

	if (stderr_bak >= 0) {
		r = dup2(stderr_bak, STDERR_FILENO);
		if (r < 0)
			return -errno;

		close(stderr_bak);
	}

	return 0;
}

static int log_file_backup(FILE *f)
{
	int r, fd;

	stdout_bak = dup(STDOUT_FILENO);
	stderr_bak = dup(STDERR_FILENO);

	fd = fileno(log_file);
	r = dup2(fd, STDOUT_FILENO);
	if (r < 0)
		return -errno;

	r = dup2(fd, STDERR_FILENO);
	if (r < 0)
		return -errno;

	return 0;
}

static int log_open_file(const char *path)
{
	assert(path);

	if (log_file)
		return -EALREADY;

	log_file = fopen(path, "a+");
	if (!log_file)
		return -errno;

	return log_file_backup(log_file);
}

int log_open(enum log_type type, const char *path)
{
	logtype = type;

	switch (type) {
	case LOG_TYPE_FILE:
		return log_open_file(path);

	default:
		return log_close();
	}
}

static int vlog_write(int level, const char *format, va_list ap)
{
	_cleanup_free_ char *buff = NULL;
	int r;

	r = vasprintf(&buff, format, ap);
	if (r < 0)
		return -ENOMEM;

	fprintf(log_file ? log_file : level <= LOG_ERR ? stderr : stdout,
		"%s\n", buff);

	return 0;
}

int log_write(int level, const char *format, ...)
{
	va_list ap;
	int r;

	va_start(ap, format);
	r = vlog_write(level, format, ap);
	va_end(ap);

	return r;
}

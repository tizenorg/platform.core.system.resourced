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


/*
 * @file trace.h
 * Common macros for tracing
 */

#ifndef _SYSTEM_RESOURCE_TRACE_H_
#define _SYSTEM_RESOURCE_TRACE_H_

#include "config.h"
#include <dlog.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syslog.h>

#include "macro.h"

#undef LOG_TAG
#define LOG_TAG "RESOURCED"

#define WALK_TREE(list, func) g_tree_foreach((GTree *)list, func, NULL)

enum log_type {
	LOG_TYPE_STANDARD = 0,
	LOG_TYPE_FILE,
	LOG_TYPE_DLOG,
	LOG_TYPE_MAX
};

extern enum log_type logtype;

#define _E(fmt, arg...) do {			\
	switch (logtype) {				\
	case LOG_TYPE_DLOG:			\
		LOGE(fmt, ##arg);		\
	default:				\
		log_write(LOG_ERR, fmt, ##arg);	\
	}					\
} while (0)

#define _D(fmt, arg...) do {				\
	switch (logtype) {					\
	case LOG_TYPE_DLOG:				\
		LOGD(fmt, ##arg);			\
	default:					\
		log_write(LOG_DEBUG, fmt, ##arg);	\
	}						\
} while (0)

#define _I(fmt, arg...) do {				\
	switch (logtype) {					\
	case LOG_TYPE_DLOG:				\
		LOGD(fmt, ##arg);			\
	default:					\
		log_write(LOG_INFO, fmt, ##arg);	\
	}						\
} while (0)

#define _SE(fmt, arg...) SECURE_LOGE(fmt, ##arg)
#define _SD(fmt, arg...) SECURE_LOGD(fmt, ##arg)
#define _SI(fmt, arg...) SECURE_LOGI(fmt, ##arg)

#define TRACE_DB_ERR(a) if (a != NULL) { \
	_D("%s\n", a); \
	sqlite3_free(a); \
}

#define TRACE_RET_ERRCODE(type, error_code) do { \
	char buf[256]; \
	_##type("errno %d, errmsg %s", error_code, strerror_r(-error_code, buf, sizeof(buf))); \
} while (0)

#define DTRACE_RET_ERRCODE(error_code) TRACE_RET_ERRCODE(D, error_code)

#define ETRACE_RET_ERRCODE(error_code) TRACE_RET_ERRCODE(E, error_code)

#define TRACE_RET_ERRCODE_MSG(type, error_code, fmt, arg...) do { \
	char buf[256]; \
	_##type(fmt, ##arg); \
	_##type("errno %d, errmsg %s", error_code, strerror_r(-error_code, buf, sizeof(buf))); \
} while (0)

#define DTRACE_RET_ERRCODE_MSG(error_code, fmt, arg...) \
	TRACE_RET_ERRCODE_MSG(D, error_code, fmt, ##arg)

#define ETRACE_RET_ERRCODE_MSG(error_code, fmt, arg...) \
	TRACE_RET_ERRCODE_MSG(E, error_code, fmt, ##arg)

#define DTRACE_ERRNO() TRACE_RET_ERRCODE(D, -errno)

#define ETRACE_ERRNO() TRACE_RET_ERRCODE(E, -errno)

#define DTRACE_ERRNO_MSG(fmt, arg...) \
	TRACE_RET_ERRCODE_MSG(D, -errno, fmt, ##arg)

#define ETRACE_ERRNO_MSG(fmt, arg...) \
	TRACE_RET_ERRCODE_MSG(E, -errno, fmt, ##arg)

#define LOG_DUMP(fp, fmt, arg...) \
	if (fp) fprintf(fp, fmt, ##arg); \
	else _E(fmt, ##arg);

API int log_close(void);
API int log_open(enum log_type type, const char *path);
API int log_write(int level, const char *format, ...);

#endif	/* _SYSTEM_RESOURCE_TRACE_H_ */

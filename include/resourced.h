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

#ifndef _RESOURCED_H_
#define _RESOURCED_H_

#include <sys/types.h>
#include <signal.h>

#define RESOURCED_ALL_APP "RESOURCED_ALL_APPLICATION_IDENTIFIER"
#define TETHERING_APP_NAME "RESOURCED_TETHERING_APPLICATION_IDENTIFIER"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

/**
 * @brief State of the monitored process
 */
typedef enum {
	RESOURCED_STATE_UNKNOWN = 0,
	RESOURCED_STATE_FOREGROUND = 1 << 1,		/** < foreground state */
	RESOURCED_STATE_BACKGROUND = 1 << 2,		/** < background state */
	RESOURCED_STATE_LAST_ELEM = 1 << 3
} resourced_state_t;

/**
 * @brief return code of the rsml's function
 */
typedef enum {
	RESOURCED_ERROR_NONMONITOR = -9,		/** < Process don't show watchdog popup */
	RESOURCED_ERROR_NOTIMPL = -7,		 /**< Not implemented yet error */
	RESOURCED_ERROR_UNINITIALIZED = -6,	 /**< Cgroup doen't
					   mounted or daemon not started */
	RESOURCED_ERROR_NO_DATA = -5,		 /**< Success, but no data */
	RESOURCED_ERROR_INVALID_PARAMETER = -4,/**< Invalid parameter */
	RESOURCED_ERROR_OUT_OF_MEMORY = -3,	 /**< Out of memory */
	RESOURCED_ERROR_DB_FAILED = -2,	 /**< Database error */
	RESOURCED_ERROR_FAIL = -1,		 /**< General error */
	RESOURCED_ERROR_OK = 0		 /**< General success */
} resourced_ret_c;

#define RESOURCED_ERROR_NONE RESOURCED_ERROR_OK

/**
 * @desc After invoking this function, application will be in
 *   the monitored scope.
 * @details It creates an appropriate cgroup,
 *   It creates a unit file for the systemd.
 * @param app_id[in] - application identifier, it's package name now
 * @param pid - pid to put in to cgroup, or self pid of 0
 * @return 0 if success or error code
 */
resourced_ret_c join_app_performance(const char *app_id, const pid_t pid);

/**
 * @desc Description of the boolean option for enabling/disabling
 *	some behaviar
 */
typedef enum {
	RESOURCED_OPTION_UNDEF,
	RESOURCED_OPTION_ENABLE,
	RESOURCED_OPTION_DISABLE
} resourced_option_state;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _RESOURCED_H_ */

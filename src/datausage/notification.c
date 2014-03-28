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
 * @file notification.c
 *
 * @desc Notification specific functions
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <resourced.h>
#include <vconf.h>

#include "edbus-handler.h"
#include "notification.h"
#include "trace.h"
#include "macro.h"
#include "roaming.h"

#define VCONFKEY_SETAPPL_DATA_LIMIT_INT         VCONFKEY_SETAPPL_PREFIX"/data_limit"

#define RESTRICTION_ACTIVE "RestrictionActive"
#define RESTRICTION_WARNING "RestrictionWarning"

#define NOTI_LAUNCHING_PARAM	"DataUsage"
#define NOTI_KEY		"_SYSPOPUP_CONTENT_"
#define NOTI_KEY_LIMIT	"_DATAUSAGE_LIMIT_"
#define NOTI_VALUE_BLOCK	"data_blocked"
#define NOTI_VALUE_WARN	"data_warning"

static int noti_id = 0;
static int quota_limit = -1;

int *get_noti_id(void)
{
	return &noti_id;
}

int clear_datausage_noti(int id)
{
	DBusError err;
	DBusMessage *msg;
	char buf[MAX_DEC_SIZE(int)];
	char *pa[1];
	int i, ret, ret_val;

	snprintf(buf, sizeof(buf), "%d", noti_id);

	pa[0] = buf;
	i = 0;

	do {
		msg = dbus_method_sync(SYSTEM_POPUP_BUS_NAME, SYSTEM_POPUP_PATH_NAME, SYSTEM_POPUP_IFACE_NAME, "NotiOff", "i", pa);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return -EBADMSG;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &ret_val, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("no message : [%s:%s]\n", err.name, err.message);
		ret_val = -EBADMSG;
	} else {
		_D("clear warning noti id : %d", noti_id);
		noti_id = 0;
	}

	dbus_message_unref(msg);
	dbus_error_free(&err);

	return ret_val;
}


static int show_datausage_noti(const char *value)
{
	DBusError err;
	DBusMessage *msg;
	char str_val[32];
	char *pa[1];
	int i, ret, ret_val;

	snprintf(str_val, sizeof(str_val), "%s", value);

	pa[0] = str_val;
	i = 0;

	do {
		msg = dbus_method_sync(SYSTEM_POPUP_BUS_NAME, SYSTEM_POPUP_PATH_NAME, SYSTEM_POPUP_IFACE_NAME, "NotiOn", "s", pa);
		if (msg)
			break;
		_E("Re-try to sync DBUS message, err_count : %d", i);
	} while (i++ < RETRY_MAX);

	if (!msg) {
		_E("Failed to sync DBUS message.");
		return -EBADMSG;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &noti_id, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("no message : [%s:%s]\n", err.name, err.message);
		ret_val = -EBADMSG;
	} else {
		ret_val = noti_id;
	}

	dbus_message_unref(msg);
	dbus_error_free(&err);

	_D("[%s] %s - %s : %d\n", str_val, SYSTEM_POPUP_PATH_NAME, SYSTEM_POPUP_IFACE_NAME, ret_val);

	return ret_val;
}

static int show_datausage_popup(const char *value)
{
	char buf[MAX_DEC_SIZE(int)];
	char str_val[32];
	char *pa[4];
	int ret;

	if (get_roaming() == RESOURCED_ROAMING_ENABLE) {
		if (vconf_get_int("db/setting/data_limit_roaming", &quota_limit)) {
			_E("vconf_get_int FAIL for roaming\n");
			return RESOURCED_ERROR_FAIL;
		}
	} else {
		if (vconf_get_int(VCONFKEY_SETAPPL_DATA_LIMIT_INT, &quota_limit)) {
			_E("vconf_get_int FAIL\n");
			return RESOURCED_ERROR_FAIL;
		};
	}

	if (quota_limit < 0) {
		_D("quota_limit is not set\n");
		return RESOURCED_ERROR_NONE;
	}

	snprintf(str_val, sizeof(str_val), "%s", value);
	snprintf(buf, sizeof(buf), "%d", quota_limit);

	pa[0] = NOTI_KEY;
	pa[1] = str_val;
	pa[2] = NOTI_KEY_LIMIT;
	pa[3] = buf;

		ret = dbus_method_async(SYSTEM_POPUP_BUS_NAME, SYSTEM_POPUP_PATH_NAME, SYSTEM_POPUP_IFACE_NAME, NOTI_LAUNCHING_PARAM, "ssss", pa);
		if (ret < 0)
			_E("no message : failed to setting %d", ret);
		
		return ret;

}


void send_restriction_notification(const char *appid)
{
	if (broadcast_edbus_signal(RESOURCED_PATH_NETWORK,
	                           RESOURCED_INTERFACE_NETWORK,
	                           RESTRICTION_ACTIVE,
	                           DBUS_TYPE_STRING,
	                           (void *)(&appid)) != RESOURCED_ERROR_NONE) {
		_E("Failed to send DBUS message.");
	}

	show_datausage_popup(NOTI_VALUE_BLOCK);
}

void send_restriction_warn_notification(const char *appid)
{
	if (broadcast_edbus_signal(RESOURCED_PATH_NETWORK,
	                           RESOURCED_INTERFACE_NETWORK,
	                           RESTRICTION_WARNING,
	                           DBUS_TYPE_STRING,
	                           (void *)(&appid)) != RESOURCED_ERROR_NONE) {
		_E("Failed to send DBUS message.");
	}

	if (noti_id > 0)
		clear_datausage_noti(noti_id);

	show_datausage_noti(NOTI_VALUE_WARN);
}


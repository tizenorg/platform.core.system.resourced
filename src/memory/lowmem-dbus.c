/*
 * resourced
 *
 * Copyright (c) 2012 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file lowmem_dbus.c
 *
 * @desc lowmem dbus for oom triger
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <Ecore.h>

#include "trace.h"
#include "lowmem-handler.h"
#include "edbus-handler.h"
#include "resourced.h"
#include "macro.h"

#define SIGNAL_NAME_OOM_SET_THRESHOLD			"SetThreshold"
#define SIGNAL_NAME_OOM_SET_LEAVE_THRESHOLD		"SetLeaveThreshold"

static void lowmem_dbus_oom_set_threshold(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	int level, thres;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM, SIGNAL_NAME_OOM_SET_THRESHOLD);

	if (ret == 0) {
		_D("there is no oom set threshold signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &level, DBUS_TYPE_INT32, &thres, DBUS_TYPE_INVALID);

	if (ret == 0) {
		_D("there is no message");
		return;
	}

	set_threshold(level, thres);
}

static void lowmem_dbus_oom_set_leave_threshold(void *data, DBusMessage *msg)
{
	DBusError err;
	int ret;
	int thres;

	ret = dbus_message_is_signal(msg, RESOURCED_INTERFACE_OOM, SIGNAL_NAME_OOM_SET_LEAVE_THRESHOLD);

	if (ret == 0) {
		_D("there is no oom set leave threshold signal");
		return;
	}

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &thres, DBUS_TYPE_INVALID);

	if (ret == 0) {
		_D("there is no message");
		return;
	}

	set_leave_threshold(thres);
}

static DBusMessage *edbus_oom_triger(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	int state = 1;

	lowmem_oom_killer_cb(MEMCG_MEMORY);

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &state);

	return reply;
}

static struct edbus_method edbus_methods[] = {
	{ "oom_triger",   NULL,   "i", edbus_oom_triger },
	/* Add methods here */
};

void lowmem_dbus_init(void)
{
	const resourced_ret_c ret = edbus_add_methods(RESOURCED_PATH_OOM,
		edbus_methods, ARRAY_SIZE(edbus_methods));

	ret_value_msg_if(ret != RESOURCED_ERROR_NONE, ,
		"DBus method registration for %s is failed",
			RESOURCED_PATH_OOM);

	register_edbus_signal_handler(RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
			SIGNAL_NAME_OOM_SET_THRESHOLD,
		    lowmem_dbus_oom_set_threshold);
	register_edbus_signal_handler(RESOURCED_PATH_OOM, RESOURCED_INTERFACE_OOM,
			SIGNAL_NAME_OOM_SET_LEAVE_THRESHOLD,
		    lowmem_dbus_oom_set_leave_threshold);
}

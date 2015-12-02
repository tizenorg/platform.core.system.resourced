/*
 * resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file module.c
 * @desc Module helper functions
 **/

#include "macro.h"
#include "module.h"
#include "resourced.h"
#include "trace.h"
#include "edbus-handler.h"

#include <glib.h>

static GSList *modules_list;

void add_module(const struct module_ops *module)
{
	ret_msg_if(!module, "Invalid module handler\n");
	if (module->priority == MODULE_PRIORITY_HIGH)
		modules_list = g_slist_prepend(modules_list, (gpointer)module);
	else
		modules_list = g_slist_append(modules_list, (gpointer)module);
}

void remove_module(const struct module_ops *module)
{
	modules_list = g_slist_remove(modules_list, (gpointer)module);
}

const struct module_ops *find_module(const char *name)
{
	GSList *iter;
	const struct module_ops *module;

	gslist_for_each_item(iter, modules_list) {
		module = (struct module_ops *)iter->data;
		if (!strcmp(module->name, name))
			return module;
	}
	return NULL;
}

void modules_check_runtime_support(void UNUSED *data)
{
	GSList *iter, *next;
	const struct module_ops *module;
	int ret_code = RESOURCED_ERROR_NONE;

	gslist_for_each_safe(modules_list, iter, next, module) {
		module = (const struct module_ops *)iter->data;
		_D("check runtime support [%s] module\n", module->name);

		if (!module->check_runtime_support)
			continue;

		ret_code = module->check_runtime_support((void *)module);
		if (ret_code != RESOURCED_ERROR_NONE) {
			_E("%s module check failed", module->name);
			remove_module(module);
			continue;
		}
	}
}

static void module_initcall_level(void *data, int priority)
{
	GSList *iter;
	struct module_ops *module;
	int ret_code = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, modules_list) {
		module = (struct module_ops *)iter->data;
		if (priority != MODULE_PRIORITY_ALL &&
		    module->priority != priority)
			continue;
		if (module->init && !module->initalized) {
			_D("Initialized [%s] module\n", module->name);
			ret_code = module->init(data);
			module->initalized = MODULE_INITIALIZED;
		}
		if (ret_code < 0)
			_E("Fail to initialize [%s] module\n", module->name);
	}
}

void modules_init(void *data)
{
	module_initcall_level(data, MODULE_PRIORITY_ALL);
}

void modules_early_init(void *data)
{
	module_initcall_level(data, MODULE_PRIORITY_EARLY);
}

void modules_late_init(void *data)
{
	module_initcall_level(data, MODULE_PRIORITY_HIGH);
	module_initcall_level(data, MODULE_PRIORITY_NORMAL);
}

void modules_exit(void *data)
{
	GSList *iter;
	struct module_ops *module;
	int ret_code = RESOURCED_ERROR_NONE;

	gslist_for_each_item(iter, modules_list) {
		module = (struct module_ops *)iter->data;
		_D("Deinitialize [%s] module\n", module->name);
		if (module->exit) {
			ret_code = module->exit(data);
			module->initalized = MODULE_NONINITIALIZED;
		}
		if (ret_code < 0)
			_E("Fail to deinitialize [%s] module\n", module->name);
	}
}

void modules_dump(FILE *fp, int mode)
{
	GSList *iter;
	const struct module_ops *module;

	gslist_for_each_item(iter, modules_list) {
		module = (struct module_ops *)iter->data;
		_D("dump [%s] module\n", module->name);
		if (module->dump)
			module->dump(fp, mode, module->dump_data);
	}
}

static DBusMessage *edbus_list_active_modules_handler(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	struct module_ops *module;
	GSList *list_iter;

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	if (!dbus_message_iter_open_container(&iter,
					      DBUS_TYPE_ARRAY,
					      DBUS_TYPE_STRING_AS_STRING,
					      &array_iter)) {
		_E("Failed to open DBus container");
		goto finish;
	}

	gslist_for_each_item(list_iter, modules_list) {
		module = (struct module_ops *)list_iter->data;

		if (!dbus_message_iter_append_basic(&array_iter,
						    DBUS_TYPE_STRING,
						    &module->name)) {
			_E("Failed to append string to DBus container");
			goto finish;
		}
	}

	if (!dbus_message_iter_close_container(&iter, &array_iter))
		_E("Failed to close DBus container");

finish:
	return reply;
}

static struct edbus_method resourced_module_methods[] = {
	{ "ListActiveModuels",	NULL,	"as",	edbus_list_active_modules_handler	},
	{ NULL,			NULL,	NULL,	NULL					},
	/* Add methods here */
};

int modules_add_methods(void)
{
	return edbus_add_methods(RESOURCED_DBUS_OBJECT_PATH,
				 resourced_module_methods,
				 ARRAY_SIZE(resourced_module_methods));
}

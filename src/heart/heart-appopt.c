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
 */

/*
 * @file heart-appopt.c
 *
 * @desc heart application optimization module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <Ecore.h>
#include <stdbool.h>
#include <sqlite3.h>
#include <time.h>

#include "resourced.h"
#include "trace.h"
#include "module.h"
#include "macro.h"
#include "notifier.h"
#include "heart.h"
#include "heart-common.h"
#include "proc-common.h"
#include "edbus-handler.h"

#define APPOPT_DB_FILE_NAME	RD_SYS_DB"/.resourced-heart-appopt.db"
#define APP_NAMES_TABLE		"appnames"
#define APP_OPTS_TABLE		"appopts"
#define QUERY_CREATE_APPNAMES	"CREATE TABLE IF NOT EXISTS "APP_NAMES_TABLE" (appkey INTEGER PRIMARY KEY AUTOINCREMENT, appname TEXT NOT NULL UNIQUE);"
#define QUERY_CREATE_APPOPTS	"CREATE TABLE IF NOT EXISTS "APP_OPTS_TABLE" (appkey INTEGER PRIMARY KEY, last_used INT NOT NULL, cur_opt INT NOT NULL, to_be_opt INT NOT NULL, FOREIGN KEY(appkey) REFERENCES "APP_NAMES_TABLE"(appkey));"
#define QUERY_INSERT_APPNAME	"INSERT OR IGNORE INTO "APP_NAMES_TABLE"(appname) VALUES ('%s');"
#define QUERY_INSERT_APPOPTS	"REPLACE INTO "APP_OPTS_TABLE" VALUES ('%d','%d','%d','%d');"
#define QUERY_DELETE_ENTRY	"DELETE FROM %s WHERE appkey = %d;"
#define QUERY_SELECT_APPOPTS	"SELECT appname,last_used,cur_opt,to_be_opt FROM "APP_NAMES_TABLE","APP_OPTS_TABLE" WHERE "APP_NAMES_TABLE".appkey = "APP_OPTS_TABLE".appkey;"
#define QUERY_SELECT_APPNAME	"SELECT * FROM "APP_NAMES_TABLE " WHERE appname = '%s';"
#define APPOPT_DATA_MAX		1024
#define SQLITE_BUSY_TIMEOUT	50000

#define PKGMGR_STATUS_OBJECT_PATH	"/org/tizen/pkgmgr_status"
#define PKGMGR_STATUS_INTERFACE_NAME	"org.tizen.pkgmgr_status"
#define PKGMGR_STATUS_SIGNAL		"status"

#define APPOPT_STR_INSTALL	"install"
#define APPOPT_STR_UNINSTALL	"uninstall"
#define APPOPT_STR_START	"start"
#define APPOPT_STR_END		"end"
#define APPOPT_STR_OK		"ok"

struct appopt_data {
	char *appname;
	int last_used;
	int cur_opt;
	int to_be_opt;
};

enum appopt_cmd_type {
	APPOPT_CMD_INSERT,
	APPOPT_CMD_REMOVE,
	APPOPT_CMD_SELECT,
};

struct appopt_cmd {
	enum appopt_cmd_type type;
	struct appopt_data data;
};

static pthread_mutex_t heart_appopt_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t heart_appopt_db_cmd_thread = 0;
static GQueue *queue = NULL;
GArray *appopt_cache;
int appopt_cache_ready = 0;

static int heart_appopt_db_cache_entries(sqlite3 *db)
{
	sqlite3_stmt *stmt;
	struct appopt_data data;
	char buf[APPOPT_DATA_MAX] = {0, };
	int ret;

	snprintf(buf, APPOPT_DATA_MAX, QUERY_SELECT_APPOPTS);

	ret = sqlite3_prepare_v2(db, buf, -1, &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("Failed to prepare query %s", sqlite3_errmsg(db));
		return RESOURCED_ERROR_DB_FAILED;
	}

	do {
		ret = sqlite3_step(stmt);
		switch (ret) {
		case SQLITE_ROW:
			if (asprintf(&data.appname, "%s", (char *) sqlite3_column_text(stmt, 0)) < 0) {
				_E("asprintf failed");
				ret = RESOURCED_ERROR_OUT_OF_MEMORY;
				goto error_malloc;
			}

			data.last_used = sqlite3_column_int(stmt, 1);
			data.cur_opt = sqlite3_column_int(stmt, 2);
			data.to_be_opt = sqlite3_column_int(stmt, 3);
			g_array_append_val(appopt_cache, data);
			break;
		case SQLITE_DONE:
			_D("SQLITE_DONE");
			break;
		case SQLITE_ERROR:
			/* FALLTHROUGH */
			_E("sqlite3_step failed %s", sqlite3_errmsg(db));
		default:
			g_array_remove_range(appopt_cache, 0, appopt_cache->len);
			ret = RESOURCED_ERROR_DB_FAILED;
			break;
		}
	} while (ret == SQLITE_ROW);

	sqlite3_finalize(stmt);

	return RESOURCED_ERROR_NONE;

error_malloc:
	sqlite3_finalize(stmt);
	g_array_remove_range(appopt_cache, 0, appopt_cache->len);
	return ret;
}

static int heart_appopt_db_get_appkey(sqlite3 *db, char *appname, int *appkey)
{
	sqlite3_stmt *stmt;
	char buf[APPOPT_DATA_MAX] = {0, };
	int ret;

	snprintf(buf, APPOPT_DATA_MAX, QUERY_SELECT_APPNAME, appname);

	ret = sqlite3_prepare_v2(db, buf, -1, &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("Failed to prepare query %s", sqlite3_errmsg(db));
		return RESOURCED_ERROR_DB_FAILED;
	}

	ret = sqlite3_step(stmt);

	switch (ret) {
	case SQLITE_ROW:
		*appkey = sqlite3_column_int(stmt, 0);
		ret = RESOURCED_ERROR_NONE;
		break;
	case SQLITE_DONE:
		_E("Appkey not found for %s", appname);
		ret = RESOURCED_ERROR_NO_DATA;
		break;
	case SQLITE_ERROR:
		/* FALLTHROUGH */
		_E("sqlite3_step failed %s", sqlite3_errmsg(db));
	default:
		ret = RESOURCED_ERROR_DB_FAILED;
		break;
	}

	sqlite3_finalize(stmt);

	return ret;
}

static int heart_appopt_db_open_transaction(sqlite3 *db)
{
	char *sqlite3_error_msg = NULL;

	if (sqlite3_exec(db, "PRAGMA journal_mode = PERSIST", NULL, NULL, &sqlite3_error_msg) != SQLITE_OK) {
		_E("sqlite3_exec(\"PRAGMA journal_mode = PERSIST\") failed! -> %s", sqlite3_error_msg);
		sqlite3_free(sqlite3_error_msg);
		return RESOURCED_ERROR_DB_FAILED;
	}

	if (sqlite3_exec(db, "BEGIN EXCLUSIVE", NULL, NULL, &sqlite3_error_msg) != SQLITE_OK) {
		_E("sqlite3_exec(\"BEGIN EXCLUSIVE\") failed! -> %s", sqlite3_error_msg);
		sqlite3_free(sqlite3_error_msg);
		return RESOURCED_ERROR_DB_FAILED;
	}

	return RESOURCED_ERROR_NONE;
}

static int heart_appopt_db_insert_entry(sqlite3 *db, struct appopt_data *data)
{
	char buf[APPOPT_DATA_MAX] = {0, };
	char *sqlite3_error_msg = NULL;
	int appkey, ret;

	if (!data) {
		_E("No data data found.");
		return RESOURCED_ERROR_DB_FAILED;
	}

	ret = heart_appopt_db_open_transaction(db);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	/* Make sure appname is present in the appnames dictionary */

	snprintf(buf, APPOPT_DATA_MAX, QUERY_INSERT_APPNAME, data->appname);

	if (sqlite3_exec(db, buf, NULL, NULL, &sqlite3_error_msg) != SQLITE_OK) {
		_E("sqlite3_exec(\"%s\") failed! -> %s", buf, sqlite3_error_msg);
		sqlite3_free(sqlite3_error_msg);
		goto error_db;
	}

	/* Get the appkey for the app the opts are to be added for */

	ret = heart_appopt_db_get_appkey(db, data->appname, &appkey);
	if (ret != RESOURCED_ERROR_NONE)
		goto error_db;

	/* Insert/update application optimization settings */

	snprintf(buf, APPOPT_DATA_MAX, QUERY_INSERT_APPOPTS, appkey,
		 data->last_used, data->cur_opt, data->to_be_opt);

	if (sqlite3_exec(db, buf, NULL, NULL, &sqlite3_error_msg) != SQLITE_OK) {
		_E("sqlite3_exec(\"%s\") failed! -> %s", buf, sqlite3_error_msg);
		sqlite3_free(sqlite3_error_msg);
		goto error_db;
	}

	if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
		_E("sqlite3_exec(\"COMMIT\") failed!");
		goto error_db;
	}

	return RESOURCED_ERROR_NONE;

error_db:
	if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
		_E("sqlite3_exec(\"ROLLBACK\") failed!");

	return RESOURCED_ERROR_DB_FAILED;
}

static int heart_appopt_db_remove_entry(sqlite3 *db, struct appopt_data *data)
{
	char buf[APPOPT_DATA_MAX] = {0, };
	char *sqlite3_error_msg = NULL;
	int appkey, ret;

	if (!data) {
		_E("No data data found.");
		return RESOURCED_ERROR_DB_FAILED;
	}

	/* Get the appkey for the app the opts are to be added for */

	ret = heart_appopt_db_get_appkey(db, data->appname, &appkey);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	ret = heart_appopt_db_open_transaction(db);
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	/* Delete app optimization data */

	snprintf(buf, APPOPT_DATA_MAX, QUERY_DELETE_ENTRY, APP_OPTS_TABLE, appkey);

	if (sqlite3_exec(db, buf, NULL, NULL, &sqlite3_error_msg) != SQLITE_OK) {
		_E("sqlite3_exec(\"%s\") failed! -> %s", buf, sqlite3_error_msg);
		sqlite3_free(sqlite3_error_msg);
		goto error_db;
	}

	/* Delete app name data */

	snprintf(buf, APPOPT_DATA_MAX, QUERY_DELETE_ENTRY, APP_NAMES_TABLE, appkey);

	if (sqlite3_exec(db, buf, NULL, NULL, &sqlite3_error_msg) != SQLITE_OK) {
		_E("sqlite3_exec(\"%s\") failed! -> %s", buf, sqlite3_error_msg);
		sqlite3_free(sqlite3_error_msg);
		goto error_db;
	}

	if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
		_E("sqlite3_exec(\"COMMIT\") failed!");
		goto error_db;
	}

	return RESOURCED_ERROR_NONE;

error_db:
	if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
		_E("sqlite3_exec(\"ROLLBACK\") failed!");

	return RESOURCED_ERROR_DB_FAILED;
}

static int appopt_db_busy(void * UNUSED user, int attempts)
{
	_E("DB locked by another process, attempts number %d", attempts);

	usleep(SQLITE_BUSY_TIMEOUT); /* wait for a half second*/
	return 1;
}

static void heart_appopt_execute_db_cmd(struct appopt_cmd *cmd)
{
	sqlite3 *appopt_db;

	if (sqlite3_open(APPOPT_DB_FILE_NAME, &appopt_db) != SQLITE_OK) {
		_E("Can't open database %s: %s", APPOPT_DB_FILE_NAME,
		   sqlite3_errmsg(appopt_db));
		sqlite3_close(appopt_db);
		return;
	}

	if (sqlite3_exec(appopt_db, "PRAGMA locking_mode = NORMAL", 0, 0, 0) != SQLITE_OK) {
		_E("Can't set locking mode %s", sqlite3_errmsg(appopt_db));
		sqlite3_close(appopt_db);
		return;
	} else {
		if (sqlite3_busy_handler(appopt_db, appopt_db_busy, NULL) != SQLITE_OK)
			_E("Couldn't set busy handler!");
	}

	if (sqlite3_exec(appopt_db, "PRAGMA foreign_keys = ON;", 0, 0, 0) != SQLITE_OK) {
		_E("Can't set locking mode %s", sqlite3_errmsg(appopt_db));
		sqlite3_close(appopt_db);
		return;
	}

	switch (cmd->type) {
	case APPOPT_CMD_INSERT:
		if (heart_appopt_db_insert_entry(appopt_db, &cmd->data) != RESOURCED_ERROR_NONE) {
			_E("Appopt data insertion failed");
		} else {
			/* invalidate cache on db update success */
			g_array_remove_range(appopt_cache, 0, appopt_cache->len);
			appopt_cache_ready = 0;
		}
		break;
	case APPOPT_CMD_REMOVE:
		if (heart_appopt_db_remove_entry(appopt_db, &cmd->data) != RESOURCED_ERROR_NONE) {
			_E("Query execution failed");
		} else {
			/* invalidate cache on db remove success */
			g_array_remove_range(appopt_cache, 0, appopt_cache->len);
			appopt_cache_ready = 0;
		}
		break;
	case APPOPT_CMD_SELECT:
		g_array_remove_range(appopt_cache, 0, appopt_cache->len);
		appopt_cache_ready = 0;
		if (heart_appopt_db_cache_entries(appopt_db) != RESOURCED_ERROR_NONE) {
			_E("Failed to fetch rows");
			g_array_remove_range(appopt_cache, 0, appopt_cache->len);
		} else {
			appopt_cache_ready = 1;
		}
		break;
	default:
		_E("Unknown appopt command");
		break;
	}

	sqlite3_close(appopt_db);
}

static void *heart_appopt_db_cmd_thread_main(void *arg)
{
	struct appopt_cmd *cmd;
	int ret;

	do {
		ret = pthread_mutex_lock(&heart_appopt_mutex);
		if (ret) {
			_E("pthread_mutex_lock() failed, %d", ret);
			break;
		}

		cmd = g_queue_pop_head(queue);
		if (!cmd)
			break;

		heart_appopt_execute_db_cmd(cmd);

		pthread_mutex_unlock(&heart_appopt_mutex);

		free(cmd->data.appname);
		free(cmd);
	} while (1);

	heart_appopt_db_cmd_thread = 0;
	pthread_mutex_unlock(&heart_appopt_mutex);
	pthread_exit((void *)0);
}

static int heart_appopt_enqueue_db_cmd(struct appopt_cmd *cmd)
{
	pthread_attr_t attr;
	int ret;

	ret = pthread_mutex_lock(&heart_appopt_mutex);
	if (ret) {
		_E("pthread_mutex_lock() failed, %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	g_queue_push_tail(queue, cmd);

	if (heart_appopt_db_cmd_thread) {
		pthread_mutex_unlock(&heart_appopt_mutex);
		return RESOURCED_ERROR_NONE;
	}

	ret = pthread_attr_init(&attr);
	if (ret < 0) {
		_E("Failed to initialize pthread attributes, %d", ret);
		pthread_mutex_unlock(&heart_appopt_mutex);
		return RESOURCED_ERROR_FAIL;
	}

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (ret < 0) {
		_E("Failed to set detached state, %d", ret);
		pthread_mutex_unlock(&heart_appopt_mutex);
		return RESOURCED_ERROR_FAIL;
	}

	ret = pthread_create(&heart_appopt_db_cmd_thread, &attr,
			     heart_appopt_db_cmd_thread_main, NULL);
	if (ret < 0) {
		_E("pthread creation for heart_storage_verifying_thread_main failed, %d", ret);
		pthread_mutex_unlock(&heart_appopt_mutex);
		return RESOURCED_ERROR_FAIL;
	}

	pthread_mutex_unlock(&heart_appopt_mutex);

	return RESOURCED_ERROR_NONE;
}

static int heart_appopt_request_appopt_list()
{
	struct appopt_cmd *cmd;

	cmd = calloc(1, sizeof(struct appopt_cmd));
	if (!cmd) {
		_E("malloc failed");
		return RESOURCED_ERROR_FAIL;
	}
	cmd->type = APPOPT_CMD_SELECT;

	if (heart_appopt_enqueue_db_cmd(cmd)) {
		_E("Failed to enqueue db query!");
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}

static int heart_appopt_enqueue_insert_cmd(char *appname, int last_used,
					int cur_opt, int to_be_opt)
{
	struct appopt_cmd *cmd;
	struct appopt_data *data;
	int ret;

	cmd = malloc(sizeof(struct appopt_cmd));
	if (!cmd) {
		_E("malloc failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	cmd->type = APPOPT_CMD_INSERT;
	data = &cmd->data;
	data->last_used = last_used;
	data->cur_opt = cur_opt;
	data->to_be_opt = to_be_opt;

	if (asprintf(&data->appname, "%s", appname) < 0) {
		free(cmd);
		_E("asprintf failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	ret = heart_appopt_enqueue_db_cmd(cmd);
	if (ret != RESOURCED_ERROR_NONE) {
		free(data->appname);
		free(cmd);
		_E("Failed to enqueue db query!");
		return ret;
	}

	return RESOURCED_ERROR_NONE;
}

static int heart_appopt_enqueue_remove_cmd(char *appname)
{
	struct appopt_cmd *cmd;
	struct appopt_data *data;
	int ret;

	cmd = malloc(sizeof(struct appopt_cmd));
	if (!cmd) {
		_E("malloc failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	cmd->type = APPOPT_CMD_REMOVE;
	data = &cmd->data;

	if (asprintf(&data->appname, "%s", appname) < 0) {
		free(cmd);
		_E("asprintf failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	ret = heart_appopt_enqueue_db_cmd(cmd);
	if (ret != RESOURCED_ERROR_NONE) {
		free(data->appname);
		free(cmd);
		_E("Failed to enqueue db query!");
		return ret;
	}

	return RESOURCED_ERROR_NONE;
}

static DBusMessage *edbus_request_appopt_list(E_DBus_Object *obj, DBusMessage *msg)
{
	if (appopt_cache->len) {
		_I("Rows already cached.");
		return dbus_message_new_method_return(msg);
	}

	if (heart_appopt_request_appopt_list() != RESOURCED_ERROR_NONE)
		_I("Failed to request appopt list.");

	return dbus_message_new_method_return(msg);
}

static DBusMessage *edbus_get_appopt_list(E_DBus_Object *obj, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter arr;
	int i;

	if (!appopt_cache_ready) {
		_I("Cache not ready, execute RequestAppOptList beforehand.");
		return dbus_message_new_method_return(msg);
	}

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(siii)", &arr);

	for (i = 0; i < appopt_cache->len; i++) {
		DBusMessageIter sub;
		struct appopt_data *data;

		data = &g_array_index(appopt_cache, struct appopt_data, i);

		dbus_message_iter_open_container(&arr, DBUS_TYPE_STRUCT, NULL, &sub);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &data->appname);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &data->last_used);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &data->cur_opt);
		dbus_message_iter_append_basic(&sub, DBUS_TYPE_INT32, &data->to_be_opt);

		dbus_message_iter_close_container(&arr, &sub);
	}

	dbus_message_iter_close_container(&iter, &arr);

	return reply;
}

static DBusMessage *edbus_insert_appopt(E_DBus_Object *obj, DBusMessage *msg)
{
	char *appname;
	int last_used, cur_opt, to_be_opt, ret;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &appname,
			DBUS_TYPE_INT32, &last_used, DBUS_TYPE_INT32, &cur_opt,
			DBUS_TYPE_INT32, &to_be_opt, DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		return dbus_message_new_method_return(msg);
	}

	heart_appopt_enqueue_insert_cmd(appname, last_used,
					cur_opt, to_be_opt);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *edbus_remove_appopt(E_DBus_Object *obj, DBusMessage *msg)
{
	char *appname;
	int ret;

	ret = dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &appname,
				    DBUS_TYPE_INVALID);
	if (!ret) {
		_E("Wrong message arguments!");
		return dbus_message_new_method_return(msg);
	}

	heart_appopt_enqueue_remove_cmd(appname);

	return dbus_message_new_method_return(msg);
}

static const struct edbus_method edbus_methods[] = {
	{ "InsertAppOpt", "siii", NULL, edbus_insert_appopt },
	{ "RemoveAppOpt", "s", NULL, edbus_remove_appopt },
	{ "RequestAppOptList", NULL, NULL, edbus_request_appopt_list },
	{ "GetAppOptList", NULL, "a(siii)", edbus_get_appopt_list },
};

static void destroy_array_element(gpointer data)
{
	struct appopt_data *d = (struct appopt_data*) data;

	if (d->appname)
		free(d->appname);
}

static int heart_appopt_init_db(void)
{
	sqlite3 *appopt_db;
	char *sqlite3_error_msg = NULL;
	char buf[APPOPT_DATA_MAX] = {0, };
	int ret;

	ret = sqlite3_open(APPOPT_DB_FILE_NAME, &appopt_db);
	if (ret != SQLITE_OK) {
		_E("Can't open database %s: %s", APPOPT_DB_FILE_NAME,
		   sqlite3_errmsg(appopt_db));
		goto error_db_open;
	}

	snprintf(buf, APPOPT_DATA_MAX, "%s", QUERY_CREATE_APPNAMES);

	ret = sqlite3_exec(appopt_db, buf, NULL, NULL, &sqlite3_error_msg);
	if (ret != SQLITE_OK) {
		_E("create failed", sqlite3_error_msg);
		sqlite3_free(sqlite3_error_msg);
		goto error_db_open;
	}

	snprintf(buf, APPOPT_DATA_MAX, "%s", QUERY_CREATE_APPOPTS);

	ret = sqlite3_exec(appopt_db, buf, NULL, NULL, &sqlite3_error_msg);
	if (ret != SQLITE_OK) {
		_E("create failed", sqlite3_error_msg);
		sqlite3_free(sqlite3_error_msg);
		goto error_db_open;
	}

	return RESOURCED_ERROR_NONE;

error_db_open:
	sqlite3_close(appopt_db);
	return RESOURCED_ERROR_DB_FAILED;
}

static void heart_appopt_pkgmgr_status(void *data, DBusMessage *msg)
{
	DBusError err;
	dbus_error_init(&err);
	struct timeval tv;
	char *req_id, *pkgtype, *pkgid, *key, *val;
	static int pkg_install = 0, pkg_uninstall = 0;
	int ret;

	if (dbus_message_is_signal(msg, PKGMGR_STATUS_INTERFACE_NAME,
		    PKGMGR_STATUS_SIGNAL) == 0) {
		_D("not a pkgmgr_status signal");
		return;
	}

	if (dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &req_id,
		DBUS_TYPE_STRING, &pkgtype, DBUS_TYPE_STRING, &pkgid,
		DBUS_TYPE_STRING, &key, DBUS_TYPE_STRING, &val,
		DBUS_TYPE_INVALID) == 0) {
		_D("there is no message");
		return;
	}
	dbus_error_free(&err);

	_D("heart_appopt_pkgmgr_status:"
	   "req_id: %s, pkgtype: %s, pkgid: %s, key: %s, val: %s",
	    req_id, pkgtype, pkgid, key, val);

	if (!strncmp(key, APPOPT_STR_START, strlen(APPOPT_STR_START)+1)) {
		if (!strncmp(val, APPOPT_STR_INSTALL, strlen(APPOPT_STR_INSTALL)+1))
			pkg_install = 1;
		else if (!strncmp(val, APPOPT_STR_UNINSTALL, strlen(APPOPT_STR_UNINSTALL)+1))
			pkg_uninstall = 1;
	} else if (!strncmp(key, APPOPT_STR_END, strlen(APPOPT_STR_END)+1)) {
		if (!strncmp(val, APPOPT_STR_OK, strlen(APPOPT_STR_OK)+1)) {
			if (pkg_install) {
				gettimeofday(&tv, NULL);
				ret = heart_appopt_enqueue_insert_cmd(pkgid, tv.tv_sec,
									0, 0);
				if (ret != RESOURCED_ERROR_NONE)
					_E("Failed to add appopt entry for new package");

			} else if (pkg_uninstall) {
				ret = heart_appopt_enqueue_remove_cmd(pkgid);
				if (ret != RESOURCED_ERROR_NONE)
					_E("Failed to remove appopt entry for removed package");
			}
		}
		pkg_install = 0;
		pkg_uninstall = 0;
	}
}

static const struct edbus_signal edbus_signals[] = {
	{PKGMGR_STATUS_OBJECT_PATH, PKGMGR_STATUS_INTERFACE_NAME,
	 PKGMGR_STATUS_SIGNAL, heart_appopt_pkgmgr_status, NULL},
};

static int heart_appopt_init(void *data)
{
	int ret = RESOURCED_ERROR_NONE;

	ret = pthread_mutex_init(&heart_appopt_mutex, NULL);
	if (ret < 0) {
		_E("mutex_init failed %d", ret);
		return RESOURCED_ERROR_FAIL;
	}

	queue = g_queue_new();
	if (!queue) {
		_E("queue init failed");
		return RESOURCED_ERROR_OUT_OF_MEMORY;
	}

	g_queue_init(queue);

	appopt_cache = g_array_new(FALSE, TRUE, sizeof(struct appopt_data));
	g_array_set_clear_func(appopt_cache, destroy_array_element);

	ret = heart_appopt_init_db();
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	ret = heart_appopt_request_appopt_list();
	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	ret = edbus_add_signals(edbus_signals, ARRAY_SIZE(edbus_signals));
	if (ret != RESOURCED_ERROR_NONE)
		_E("DBus signals registration failed.");

	ret = edbus_add_methods(RESOURCED_PATH_APPOPT, edbus_methods, ARRAY_SIZE(edbus_methods));
	if (ret != RESOURCED_ERROR_NONE)
		_E("DBus method registration for %s failed.", RESOURCED_PATH_APPOPT);

	return ret;
}

static int heart_appopt_exit(void *data)
{
	g_array_free(appopt_cache, TRUE);

	return RESOURCED_ERROR_NONE;
}

static const struct heart_module_ops heart_appopt_ops = {
	.name		= "APPOPT",
	.init		= heart_appopt_init,
	.exit		= heart_appopt_exit,
};
HEART_MODULE_REGISTER(&heart_appopt_ops)

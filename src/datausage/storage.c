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
 * @file storage.c
 *
 * @desc Entity for storing applications statistics
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <glib.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "const.h"
#include "iface.h"
#include "database.h"

#include "macro.h"
#include "protocol-info.h"
#include "storage.h"
#include "trace.h"

static sqlite3_stmt *update_statistics_query;
static sqlite3_stmt *update_iface_query;

enum { read_until_null = -1 };

static void handle_on_iface(const int ifindex, resourced_option_state state)
{
	_D("Handling network interface %d, %d", ifindex, state);

	if (!update_iface_query) {
		_E("Uninitialized statement");
		return;
	}
	sqlite3_bind_int(update_iface_query, 1, get_iftype(ifindex));
	sqlite3_bind_int(update_iface_query, 2, state);

	if (sqlite3_step(update_iface_query) != SQLITE_DONE)
		_E("Failed to record iface state. %s",
			sqlite3_errmsg(resourced_get_database()));

	sqlite3_reset(update_iface_query);
}

static void handle_on_iface_up(const int ifindex)
{
	init_iftype();
	handle_on_iface(ifindex, RESOURCED_OPTION_ENABLE);
}

static void handle_on_iface_down(const int ifindex)
{
	handle_on_iface(ifindex, RESOURCED_OPTION_DISABLE);
}

static int init_update_statistics_query(sqlite3 *db)
{
	int rc;

	if (update_statistics_query)
		return SQLITE_OK;

	rc = sqlite3_prepare_v2(db,
			       "insert into statistics "		\
			       "(binpath, received, sent, time_stamp, "	\
			       "iftype, is_roaming, hw_net_protocol_type) " \
			       "values (?, ?, ?, ?, ?, ?, ?)",
			       read_until_null, &update_statistics_query, NULL);

	if (rc != SQLITE_OK) {
		_E("Failed to prepare query %s\n", sqlite3_errmsg(db));
		sqlite3_finalize(update_statistics_query);
	}
	return rc;
}

static int init_update_iface_query(sqlite3 *db)
{
	int rc;

	if (update_iface_query)
		return SQLITE_OK;

	rc =  sqlite3_prepare_v2(db,
				"insert into iface_status " \
		"(update_time, iftype, ifstatus) " \
		"values (datetime('now'), ?, ?)", read_until_null,
		&update_iface_query, NULL);

	if (rc != SQLITE_OK) {
		_E("Failed to prepare query %s\n", sqlite3_errmsg(db));
		sqlite3_finalize(update_iface_query);
	}
	return rc;
}

static gboolean store_application_stat(gpointer key, gpointer value,
	gpointer __attribute((__unused__)) userdata)
{
	struct application_stat *stat = (struct application_stat *)value;
	struct classid_iftype_key *stat_key = (struct classid_iftype_key *)key;
	time_t *last_touch_time = (time_t *)userdata;
	resourced_hw_net_protocol_type hw_net_protocol_type =
		get_hw_net_protocol_type(stat_key->iftype);

	if (!update_statistics_query) {
		_E("Uninitialized statement");
		return FALSE;
	}

	if (!stat->rcv_count && !stat->snd_count)
		return FALSE;

	if (sqlite3_bind_text(update_statistics_query, 1, stat->application_id, read_until_null,
			SQLITE_STATIC) != SQLITE_OK) {
		_SE("Can not bind application_id: %s", stat->application_id);
		return FALSE;
	}
	if (sqlite3_bind_int(update_statistics_query, 2, stat->rcv_count) != SQLITE_OK) {
		_E("Can not bind rcv_count %d:", stat->rcv_count);
		return FALSE;
	}
	if (sqlite3_bind_int(update_statistics_query, 3, stat->snd_count) != SQLITE_OK) {
		_E("Can not bind snd_count: %d", stat->snd_count);
		return FALSE;
	}
	if (sqlite3_bind_int64(update_statistics_query, 4, (sqlite3_int64) (*last_touch_time)) !=
		SQLITE_OK) {
		_E("Can not bind last_touch_time: %ld", *last_touch_time);
		return FALSE;
	}
	if (sqlite3_bind_int(update_statistics_query, 5, (int)(stat_key->iftype)) != SQLITE_OK) {
		_E("Can not bind iftype: %d", (int)stat_key->iftype);
		return FALSE;
	}
	if (sqlite3_bind_int(update_statistics_query, 6, (int)(stat->is_roaming)) != SQLITE_OK) {
		_E("Can not bind is_roaming: %d", (int)(stat->is_roaming));
		return FALSE;
	}
	if (sqlite3_bind_int(update_statistics_query, 7,
			     (int)hw_net_protocol_type) != SQLITE_OK) {
		_E("Can not bind protocol_type: %d", (int)hw_net_protocol_type);
		return FALSE;
	}

	/*we want to reuse tree*/
	stat->rcv_count = 0;
	stat->snd_count = 0;
	if (sqlite3_step(update_statistics_query) != SQLITE_DONE)
		_E("Failed to record appstat. %s", sqlite3_errmsg(resourced_get_database()));

	sqlite3_reset(update_statistics_query);
	return FALSE;
}

int store_result(struct application_stat_tree *stats, int flush_period)
{
	time_t current_time;

	time(&current_time);

	if (current_time - stats->last_touch_time > flush_period) {

		if (init_update_statistics_query(resourced_get_database()) != SQLITE_OK) {
			_D("Failed to initialize data usage quota statements: %s\n",
			   sqlite3_errmsg(resourced_get_database()));
			return 0; /* Do not iterate and free results */
		}

		g_tree_foreach((GTree *) stats->tree,
			       store_application_stat,
			       &stats->last_touch_time);

		stats->last_touch_time = current_time;
		return 1;
	}
	return 0;
}

void finalize_storage_stm(void)
{
	sqlite3_finalize(update_statistics_query);
	sqlite3_finalize(update_iface_query);
}

iface_callback *create_iface_storage_callback(void)
{
	iface_callback *ret_arg =
		(iface_callback *)malloc(sizeof(iface_callback));

	if (init_update_iface_query(resourced_get_database())
		!= SQLITE_OK) {
		_E("Initialization database failed\n");
	}
	ret_value_msg_if(!ret_arg, NULL, "Malloc of iface_callback failed\n");
	ret_arg->handle_iface_up = handle_on_iface_up;
	ret_arg->handle_iface_down = handle_on_iface_down;

	return ret_arg;
}

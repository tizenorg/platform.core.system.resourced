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
 * @file datausage-quota.c
 *
 * @desc Quota logic implementation
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <sqlite3.h>
#include <string.h>
#include <time.h>
#include <vconf.h>

#include "const.h"
#include "database.h"
#include "datausage-quota.h"
#include "resourced.h"
#include "trace.h"
#include "const.h"

#define INSERT_QUERY "REPLACE INTO quotas " \
	"(binpath, sent_quota, rcv_quota, " \
	"snd_warning_threshold, rcv_warning_threshold, time_period, " \
	"start_time, iftype, roaming) " \
	"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"

#define REMOVE_QUOTA "DELETE FROM quotas WHERE binpath=? AND iftype=? " \
	" AND roaming=?"

#define QUOTA_CEILING_VALUE 10737418220

/* Warning threshold part in percent*/
enum {
	WARNING_THRESHOLD_DEFAULT_PART = 5,
	WARNING_THRESHOLD_PART_10 = 10,
	WARNING_THRESHOLD_PART_15 = 15,
	WARNING_THRESHOLD_PART_20 = 20,
};

static sqlite3_stmt *datausage_quota_insert;
static sqlite3_stmt *datausage_quota_remove;

static int init_datausage_quota_insert(sqlite3 *db)
{
	int rc;

	if (datausage_quota_insert)
		return SQLITE_OK;

	rc = sqlite3_prepare_v2(db, INSERT_QUERY,
				    -1, &datausage_quota_insert, NULL);

	if (rc != SQLITE_OK) {
		_E("can not prepare datausage_quota_insert");
		datausage_quota_insert = NULL;
		sqlite3_finalize(datausage_quota_insert);
	}

	return rc;
}

static int init_datausage_quota_remove(sqlite3 *db)
{
	int rc;

	if (datausage_quota_remove)
		return SQLITE_OK;

	 rc = sqlite3_prepare_v2(db, REMOVE_QUOTA, -1,
			&datausage_quota_remove, NULL);
	if (rc != SQLITE_OK) {
		_E("can not prepare datausage_quota_remove");
		datausage_quota_remove = NULL;
		sqlite3_finalize(datausage_quota_remove);
		return rc;
	}

	return rc;
}


API resourced_ret_c remove_datausage_quota(
	const struct datausage_quota_reset_rule *rule)
{
	char delete_arg[MAX_NAME_LENGTH];
	resourced_ret_c error_code = RESOURCED_ERROR_NONE;

	if (!rule || !rule->app_id)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	if (rule->iftype <= RESOURCED_IFACE_UNKNOWN ||
	    rule->iftype >= RESOURCED_IFACE_LAST_ELEM)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	if (rule->roaming < RESOURCED_ROAMING_UNKNOWN ||
	    rule->roaming >= RESOURCED_ROAMING_LAST_ELEM)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	libresourced_db_initialize_once();

	if (init_datausage_quota_remove(resourced_get_database()) != SQLITE_OK) {
		_D("Failed to initialize data usage quota statements: %s\n",
		   sqlite3_errmsg(resourced_get_database()));
		return RESOURCED_ERROR_DB_FAILED;
	}

	if (sqlite3_bind_text(datausage_quota_remove, 1, rule->app_id, -1, SQLITE_STATIC) !=
	    SQLITE_OK) {
		_SE("Can not bind app_id: %s for preparing statement",
		   rule->app_id);
		error_code =  RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_remove, 2, rule->iftype)
	    != SQLITE_OK) {
		_E("Can not bind iftype:%d for preparing statement",
			rule->iftype);
		error_code =  RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_remove, 3, rule->roaming)
	    != SQLITE_OK) {
		_E("Can not bind iftype:%d for preparing statement",
			rule->roaming);
		error_code =  RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_step(datausage_quota_remove) != SQLITE_DONE) {
		_E("failed to remove record");
		error_code =  RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	snprintf(delete_arg, MAX_NAME_LENGTH, "%s,%d,%d", rule->app_id,
		rule->iftype, rule->roaming);
	vconf_set_str(RESOURCED_DELETE_LIMIT_PATH, delete_arg);
	_SD("quota for app %s, iftype %d, roaming %d removed\n", rule->app_id,
		rule->iftype, rule->roaming);

out:
	sqlite3_reset(datausage_quota_remove);
	return error_code;
}

API resourced_ret_c remove_datausage_quota_by_iftype(
	const char *app_id, const resourced_iface_type iftype)
{
	struct datausage_quota_reset_rule rule = {
		.app_id = app_id,
		.iftype = iftype,
		.roaming = RESOURCED_ROAMING_UNKNOWN,
	};

	return remove_datausage_quota(&rule);
}

static int _is_valid_datausage_quota_params(const char *app_id,
					const data_usage_quota *quota)
{
	if (!app_id) {
		_SE("Empty appid! Please provide valid appid.");
		return 0;
	}

	if (!quota) {
		_E("Empty quota! Please provide valid quota.");
		return 0;
	}

	if (quota->iftype >= RESOURCED_IFACE_LAST_ELEM) {
		_E("Not valid value for iftype! See resourced_iface_type!");
		return 0;
	}

	return 1;
}

static time_t _get_datausage_start_time(const time_t *quota_start_time)
{
	return quota_start_time ? *quota_start_time : time(0);
}

static inline int _get_threshold_part(int time_period)
{
	if (time_period < RESOURCED_PERIOD_DAY)
		return WARNING_THRESHOLD_PART_20;

	if (time_period < RESOURCED_PERIOD_WEEK)
		return WARNING_THRESHOLD_PART_15;

	if (time_period < RESOURCED_PERIOD_MONTH)
		return WARNING_THRESHOLD_PART_10;

	return WARNING_THRESHOLD_DEFAULT_PART;
}

static inline int64_t get_quota_ceiling(const int64_t quota)
{
	return quota >= QUOTA_CEILING_VALUE ? QUOTA_CEILING_VALUE :
		quota;
}

static inline int _evaluate_warning_threshold(const int64_t quota,
	const int time_period, const int user_threshold)
{
	int threshold_part = WARNING_THRESHOLD_DEFAULT_PART;

	if (user_threshold != WARNING_THRESHOLD_DEFAULT)
		return user_threshold;

	threshold_part = _get_threshold_part(time_period);

	return (get_quota_ceiling(quota) / 100 ) * threshold_part;
}

API resourced_ret_c set_datausage_quota(const char *app_id,
					const data_usage_quota *quota)
{
	/* support old behaviour undefined iftype mean all iftype */
	const resourced_iface_type iftype =
		(quota->iftype == RESOURCED_IFACE_UNKNOWN) ?
			RESOURCED_IFACE_ALL : quota->iftype;
	char add_arg[MAX_NAME_LENGTH];
	time_t start_time = 0;
	const int snd_warning_threshold = _evaluate_warning_threshold(
			quota->snd_quota, quota->time_period,
			quota->snd_warning_threshold);
	const int rcv_warning_threshold = _evaluate_warning_threshold(
			quota->rcv_quota, quota->time_period,
			quota->rcv_warning_threshold);
	resourced_ret_c error_code = RESOURCED_ERROR_NONE;

	if (!_is_valid_datausage_quota_params(app_id, quota))
		return RESOURCED_ERROR_INVALID_PARAMETER;

	start_time = _get_datausage_start_time(quota->start_time);
	libresourced_db_initialize_once();

	if (init_datausage_quota_insert(resourced_get_database()) != SQLITE_OK) {
		_D("Failed to initialize data usage quota statements: %s\n",
		   sqlite3_errmsg(resourced_get_database()));
		return RESOURCED_ERROR_DB_FAILED;
	}

	if (sqlite3_bind_text(datausage_quota_insert, 1, app_id, -1,
		SQLITE_STATIC) != SQLITE_OK) {
		_SE("Can not bind app_id: %s for prepearing statement", app_id);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 2,
		quota->snd_quota) != SQLITE_OK) {
		_E("Can not bind snd_quota: %lld for prepearing statement",
			quota->snd_quota);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 3,
		quota->rcv_quota) != SQLITE_OK) {
		_E("Can not bind rcv_quota: %lld for prepearing statement",
			quota->rcv_quota);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 4,
		snd_warning_threshold) != SQLITE_OK) {
		_E("Can not bind snd_warning_threshold: %d for prepearing statement",
			snd_warning_threshold);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 5,
		rcv_warning_threshold) != SQLITE_OK) {
		_E("Can not bind rcv_warning_threshold: %d for prepearing statement",
			rcv_warning_threshold);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int64(datausage_quota_insert, 6,
		quota->time_period) != SQLITE_OK) {
		_E("Can not bind time_period: %d for prepearing statement",
			quota->time_period);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_insert, 7,
		start_time) != SQLITE_OK) {
		_E("Can not bind start_time: %lld for prepearing statement",
			(long long int)start_time);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_insert, 8,
		iftype) != SQLITE_OK) {
		_E("Can not bind iftype: %d for prepearing statement",
			quota->iftype);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_bind_int(datausage_quota_insert, 9,
		quota->roaming_type) != SQLITE_OK) {
		_E("Can not bind start_time: %lld for prepearing statement",
			(long long int)start_time);
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	if (sqlite3_step(datausage_quota_insert) != SQLITE_DONE) {
		_E("Failed to record quota %s.",
			sqlite3_errmsg(resourced_get_database()));
		error_code = RESOURCED_ERROR_DB_FAILED;
		goto out;
	}

	snprintf(add_arg, MAX_NAME_LENGTH, "%s,%d,%d,%ld,%d", app_id, iftype,
	         quota->roaming_type, start_time, quota->time_period);
	vconf_set_str(RESOURCED_NEW_LIMIT_PATH, add_arg);
	_SD("quota for app %s set", app_id);

out:
	sqlite3_reset(datausage_quota_insert);
	return error_code;
}

void finalize_datausage_quota(void)
{
	if (datausage_quota_insert) {
		sqlite3_finalize(datausage_quota_insert);
		datausage_quota_insert = NULL;
	}

	if (datausage_quota_remove) {
		sqlite3_finalize(datausage_quota_remove);
		datausage_quota_remove = NULL;
	}
}

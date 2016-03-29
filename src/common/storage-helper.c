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
 */

/*
 *  @file: storage-helper.c
 *  @desc: Helper functions to get storage details
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "storage-helper.h"
#include "trace.h"
#include <mntent.h>
#include <storage.h>

#define PATH_MAX	256
#define INTERNAL_MEMORY_PATH	 "/opt/usr"
#define EXTERNAL_MEMORY_PATH	 RD_SYS_STORAGE"/sdcard"

bool is_mounted(const char* path)
{
	int ret = false;
	struct mntent* mnt;
	const char* table = "/etc/mtab";
	FILE* fp;

	fp = setmntent(table, "r");
	if (!fp)
		return ret;
	while ((mnt = getmntent(fp))) {
		if (!strncmp(mnt->mnt_dir, path, strlen(path)+1)) {
			ret = true;
			break;
		}
	}
	endmntent(fp);
	return ret;
}

struct rd_storage {
	int id;
	int type;
};

static bool get_storage_id(int sid, storage_type_e type, storage_state_e state,
		const char *path, void *userData)
{
	struct rd_storage *target = (struct rd_storage*)userData;

	if (type == target->type && state == STORAGE_STATE_MOUNTED) {
		target->id = sid;
		return false;
	}
	return true;
}

resourced_ret_c get_storage_root_path(int type, char **path)
{
	struct rd_storage target;

	_I("Start getting %s root path",
			(type == INTERNAL ? "internal" : "external"));

	/* TODO : set user name according to current user */
	if (type == INTERNAL) {
		target.type = STORAGE_TYPE_INTERNAL;
		strncpy(*path, "/home/owner/content", 20);
		_I("Root path = %s", *path);
		return RESOURCED_ERROR_NONE;
	}
	else if (type == EXTERNAL)
		target.type = STORAGE_TYPE_EXTERNAL;
	else {
		_E("Invalid storage type");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	target.id = -1;
	if (storage_foreach_device_supported(get_storage_id,
				&target) != STORAGE_ERROR_NONE) {
		_E("Failed to get storage ID");
		return RESOURCED_ERROR_FAIL;
	}

	if(target.id == -1) {
		_E("There is no %s storage",
				(type == INTERNAL ? "internal" : "external"));
		return RESOURCED_ERROR_FAIL;
	}

	if (storage_get_root_directory(target.id, path)
			!= STORAGE_ERROR_NONE) {
		_E("Failed to get root path of storage");
		return RESOURCED_ERROR_FAIL;
	}

	_I("Root path = %s", *path);
	return RESOURCED_ERROR_NONE;
}

resourced_ret_c storage_get_size(int type, struct statvfs *buf)
{
	int ret;
	char *path;
	char errbuf[PATH_MAX];

	if (get_storage_root_path(type, &path) != RESOURCED_ERROR_NONE) {
		_E("Failed to get storage path");
		goto fail;
	}

	_I("Path:%s", path);
	if (type == EXTERNAL) {
		if (!is_mounted(path)) {
			memset(buf, 0, sizeof(struct statvfs));
			goto success;
		}
	}

	ret = statvfs(path, buf);
	if (ret) {
		_E("statvfs() failed. Path:%s err:%s", path, strerror_r(errno, errbuf, sizeof(errbuf)));
		goto fail;
	}
	goto success;

fail:
	free(path);
	return RESOURCED_ERROR_FAIL;

success:
	free(path);
	return RESOURCED_ERROR_NONE;
}

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

#define BUF_MAX	256

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

resourced_ret_c get_storage_root_paths(int type, GSList **paths)
{
	struct rd_storage target;
	DIR *dp;
	struct dirent dentry;
	struct dirent *result;
	char *root_path;
	char buf[BUF_MAX];

	switch (type) {
	case INTERNAL:
		_D("Start finding internal root path of all users");
		dp = opendir("/home");
		if (!dp) {
			_E("Fail to open /home");
			return RESOURCED_ERROR_FAIL;
		}

		while (!readdir_r(dp, &dentry, &result) && result != NULL) {
			if(dentry.d_name[0] == '.')
				continue;
			if(snprintf(buf, BUF_MAX, "/home/%s/content", dentry.d_name) < 0) {
				_D("Fail to make root path of %s. This path will not be included", dentry.d_name);
				continue;
			}
			if (!opendir(buf)) {
				_D("User %s doesn't have content path", dentry.d_name);
				continue;
			}
			root_path = strdup(buf);
			_D("Find new root path : %s", root_path);
			*paths = g_slist_append(*paths, root_path);
		}
		break;
	case EXTERNAL:
		_D("Start finding external root path");
		target.type = STORAGE_TYPE_EXTERNAL;
		target.id = -1;
		if (storage_foreach_device_supported(get_storage_id,
					&target) != STORAGE_ERROR_NONE) {
			_E("Failed to get storage ID");
			return RESOURCED_ERROR_FAIL;
		}

		if(target.id >= 0) {
			if (storage_get_root_directory(target.id, &root_path)
					!= STORAGE_ERROR_NONE) {
				_E("Failed to get root path of storage");
				return RESOURCED_ERROR_FAIL;
			}
			_D("External root path = %s", root_path);
			*paths = g_slist_append(*paths, root_path);
		}
		break;
	default:
		_E("Invalid storage type");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	};

	if (g_slist_length(*paths) < 1) {
		_E("There is no %s storage",
				(type == INTERNAL ? "internal" : "external"));
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}

void add_size(gpointer elem, gpointer acc_size)
{
	struct statvfs buf;
	struct storage_size *ssp = (struct storage_size*)acc_size;
	char *path = (char*)(((GSList*)elem)->data);
	int ret = statvfs(path, &buf);
	if (ret) {
		_E("statvfs() about %s failed (%d)", path, errno);
		return;
	}

	ssp->total_size = ((double)buf.f_frsize * buf.f_blocks) / KB;
	ssp->free_size = ((double)buf.f_bsize * buf.f_bavail) / KB;
}

resourced_ret_c storage_get_size(int type, struct storage_size *size)
{
	GSList *paths = NULL;

	if (get_storage_root_paths(type, &paths) != RESOURCED_ERROR_NONE) {
		_E("Failed to get storage path");
		goto fail;
	}

	memset(size, 0x00, sizeof(struct storage_size));
	g_slist_foreach(paths, add_size, size);

	if (type == INTERNAL && size->total_size <= 0) {
		_E("Failed to get internal storage size");
		goto fail;
	}
	goto success;

fail:
	g_slist_free(paths);
	return RESOURCED_ERROR_FAIL;

success:
	g_slist_free(paths);
	return RESOURCED_ERROR_NONE;
}

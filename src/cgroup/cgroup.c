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
 * Cgroup creation implementation
 */

#include "appid-helper.h"
#include "cgroup.h"
#include "const.h"
#include "macro.h"
#include "resourced.h"
#include "trace.h"
#include "transmission.h"
#include "file-helper.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>		/*mkdirat */
#include <glib.h>
#include <limits.h>
#include <sys/stat.h>		/*mkdirat */
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>		/*time function */
#include <unistd.h>

/*TODO move to another place*/
static const char *cur_classid_path = "/tmp/cur_classid";

void fill_net_cgroup_path(const char *pkg_name, const int pkg_name_len,
	char *cgroup_path, const int cgroup_path_len)
{
	strncpy(cgroup_path, PATH_TO_NET_CGROUP_DIR, cgroup_path_len);
	strncpy(cgroup_path + sizeof(PATH_TO_NET_CGROUP_DIR) - 1, pkg_name,
		pkg_name_len);
}

static int is_cgroup_exists(const DIR *dir, const char *cgroup_name_buf)
{
	/* TODO drop cycle and use stat or _chdir */
	struct dirent *entry = 0;

	while ((entry = readdir((DIR *) dir)) != 0) {
		if (entry->d_type != DT_DIR || entry->d_name[0] == '.')
			continue;

		if (strcmp(entry->d_name, cgroup_name_buf) == 0)
			return 1;
	}
	return 0;
}

static int get_fd(DIR *dir)
{
	if (!dir)
		return -EINVAL;

	return dirfd((DIR *) dir);
}

static int create_cgroup(DIR *dir, const char *cgroup_name_buf)
{
	int dirfd;
	dirfd = get_fd(dir);

	if (dirfd < 0)
		return dirfd;

	if (mkdirat
	    (dirfd, cgroup_name_buf,
	     S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IXOTH) < 0)
		return -errno;

	return 0;
}

#if 0
/*
 * @desc place pid to cgroup.procs file
 * @return 0 in case of success, errno value in case of failure
 */
static resourced_ret_c _place_pid_to_cgroup_by_procs(const char *cgroup_name_buf,
	const int pid)
{
	char task_name_buf[MAX_PATH_LENGTH] = { 0 };
	int ret;

	snprintf(task_name_buf, sizeof(task_name_buf), "%s%s",
		cgroup_name_buf, CGROUP_FILE_NAME);

	_SD("file_name_buf %s, pid %d\n", task_name_buf, pid);
	ret = fwrite_int(task_name_buf, pid);
	if (ret < 0) {
		ETRACE_RET_ERRCODE_MSG(ret, "Failed place all pid to cgroup %s",
			task_name_buf);
		DTRACE_RET_ERRCODE(ret);
		return RESOURCED_ERROR_FAIL;
	}
	return RESOURCED_ERROR_NONE;

}
#endif

static int _place_pid_to_cgroup_by_task(const char *cgroup_name_buf, const int pid)
{
	char task_name_buf[MAX_PATH_LENGTH] = { 0 };

	snprintf(task_name_buf, sizeof(task_name_buf), "%s%s",
		cgroup_name_buf, TASK_FILE_NAME);

	_SD("file_name_buf %s, pid %d\n", task_name_buf, pid);
	return fwrite_int(task_name_buf, pid);
}

static u_int32_t get_classid(void)
{
	u_int32_t classid = RESOURCED_RESERVED_CLASSID_MAX;
	int ret = fread_int(cur_classid_path, &classid);
	if (ret < 0)
		ETRACE_RET_ERRCODE_MSG(ret, "Can not read current classid");
	ret = fwrite_uint(cur_classid_path, ++classid);
	if (ret < 0)
		ETRACE_RET_ERRCODE_MSG(ret, "Can not write classid");

	return classid;
}

static int place_classid_to_cgroup(const char *file_name_buf)
{
	u_int32_t classid = get_classid();
	return fwrite_uint(file_name_buf, classid);
}

static u_int32_t get_classid_from_cgroup(const char *file_name_buf)
{
	u_int32_t classid = 0;
	int ret = fread_int(file_name_buf, &classid);
	if (ret < 0)
		ETRACE_RET_ERRCODE_MSG(ret, "Cant read classid from file %s",
			file_name_buf);
	return classid;
}

API resourced_ret_c make_net_cls_cgroup_with_pid(const int pid, const char *pkg_name)
{
	DIR *dir = 0;
	int error_code = 0;
	size_t cgroup_name_len = 0;
	char file_name_buf[MAX_PATH_LENGTH], cgroup_name_buf[MAX_NAME_LENGTH];
	int cgroup_exists = 0;

	if (pkg_name == NULL) {
		_E("package name must be not empty");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	_SD("pkg: %s; pid: %d\n", pkg_name, pid);

	cgroup_name_len = strlen(pkg_name);
	if (sizeof(cgroup_name_buf) <= cgroup_name_len ||
		sizeof(file_name_buf) <= sizeof(PATH_TO_NET_CGROUP_DIR) + cgroup_name_len) {
		_SE("not enought buffer size for %s\n", pkg_name);
		goto handle_error;
	}

	STRING_SAVE_COPY(cgroup_name_buf, pkg_name);

	dir = opendir(PATH_TO_NET_CGROUP_DIR);

	if (!dir) {
		error_code = -errno;
		goto handle_error;
	}

	cgroup_exists = is_cgroup_exists(dir, cgroup_name_buf);
	if (!cgroup_exists) {
		error_code = create_cgroup(dir, cgroup_name_buf);
		if (error_code < 0)
			goto handle_error;

		snprintf(file_name_buf, sizeof(file_name_buf), "%s%s%s",
			PATH_TO_NET_CGROUP_DIR, cgroup_name_buf, CLASSID_FILE_NAME);

		error_code = place_classid_to_cgroup(file_name_buf);
		if (error_code < 0)
			goto handle_error;
	}

	snprintf(file_name_buf, sizeof(file_name_buf), "%s%s",
		PATH_TO_NET_CGROUP_DIR, cgroup_name_buf);

	error_code = _place_pid_to_cgroup_by_task(file_name_buf, pid);
	if (error_code < 0)
		goto handle_error;

	closedir(dir);

	return 0;

 handle_error:
	if (dir) {
		closedir(dir);
	}
	ETRACE_RET_ERRCODE(error_code);
	/* log and return error due this function is public */
	return error_code;
}

u_int32_t get_classid_by_app_id(const char *app_id, int create)
{
	char pkgname[MAX_PATH_LENGTH];
	extract_pkgname(app_id, pkgname, sizeof(pkgname));
	return get_classid_by_pkg_name(pkgname, create);
}

API u_int32_t get_classid_by_pkg_name(const char *pkg_name, int create)
{
	DIR *dir = 0;
	char file_name_buf[500], cgroup_name_buf[500];
	int cgroup_name_len = 0, error_code = 0;

	if (!strcmp(pkg_name, RESOURCED_ALL_APP))
		return RESOURCED_ALL_APP_CLASSID;

	if (!strcmp(pkg_name, TETHERING_APP_NAME))
		return RESOURCED_TETHERING_APP_CLASSID;

	cgroup_name_len = strlen(pkg_name);
	strncpy(cgroup_name_buf, pkg_name, cgroup_name_len + 1);
	strncpy(file_name_buf, PATH_TO_NET_CGROUP_DIR, sizeof(file_name_buf));
	strncpy(file_name_buf + sizeof(PATH_TO_NET_CGROUP_DIR) - 1, cgroup_name_buf,
		cgroup_name_len);
	strncpy(file_name_buf + sizeof(PATH_TO_NET_CGROUP_DIR) + cgroup_name_len -
		1, CLASSID_FILE_NAME, sizeof(CLASSID_FILE_NAME));

	if (create) {
		dir = opendir(PATH_TO_NET_CGROUP_DIR);

		if (!dir) {
			error_code = -errno;
			goto handle_error;
		}

		if (!is_cgroup_exists(dir, pkg_name)) {
			error_code =
			     create_cgroup(dir, pkg_name);
			if (error_code < 0)
				goto handle_error;

			error_code =
			     place_classid_to_cgroup(file_name_buf);
			if (error_code < 0)
				goto handle_error;
		}

		closedir(dir);
	}

	return get_classid_from_cgroup(file_name_buf);
 handle_error:
	if (dir) {
		closedir(dir);
	}
	ETRACE_RET_ERRCODE(error_code);
	return RESOURCED_UNKNOWN_CLASSID;
}

int cgroup_write_node(const char *cgroup_name,
		const char *file_name, unsigned int value)
{
	char buf[MAX_PATH_LENGTH] = {0, };
	sprintf(buf, "%s%s", cgroup_name, file_name);
	_SD("cgroup_buf %s, value %d\n", buf, value);
	return fwrite_int(buf, value);
}



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
 * @file classid-helper.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "classid-helper.h"
#include "const.h"
#include "errors.h"
#include "macro.h"
#include "trace.h"
#include "resourced.h"

#include <dirent.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>

struct task_classid {
	GArray *pids;
	int pid_count;
	u_int32_t classid;
	char cgroup_name[255];	/*in combination it's package name */
};

typedef GArray task_classid_array;
static task_classid_array *tasks_classids;

static sig_atomic_t is_update_class_id;

/* settler accessor */
void raise_update_classid(void)
{
	is_update_class_id = 1;
}

void reduce_udpate_classid(void)
{
	is_update_class_id = 0;
}

int is_update_classid(void)
{
	return is_update_class_id;
}

static int read_uint(FILE *handler, u_int32_t *out)
{
	return fscanf(handler, "%u", out);
}

static int read_int(FILE *handler, int *out)
{
	return fscanf(handler, "%d", out);
}

static void
read_task_classid(const char *dir_name_buf, size_t dir_name_buf_len,
		  const char *cgroup_name_buf,
		  task_classid_array **tasks_classids_list)
{
	char file_name_buf[500];
	FILE *handler = 0;
	struct task_classid tc;
	memset(&tc, 0, sizeof(struct task_classid));
	tc.pids = g_array_new(FALSE, FALSE, sizeof(pid_t));
	pid_t pid_for_read = 0;

	/* first part of path */
	snprintf(file_name_buf, sizeof(file_name_buf), "%s/%s", dir_name_buf,
		CLASSID_FILE_NAME);
	handler = fopen(file_name_buf, "r");

	if (!handler) {
		_D("can't open %s file\n", file_name_buf);
		return;
	}

	if (sizeof(tc.cgroup_name) < strlen(cgroup_name_buf))
		_SD("not enought buffer for %s", cgroup_name_buf);
	else
		strcpy(tc.cgroup_name, cgroup_name_buf);

	if (read_uint(handler, &tc.classid) < 0)
		_D("can't read classid from file %s\n", file_name_buf);

	fclose(handler);

	strncpy(file_name_buf + dir_name_buf_len, TASK_FILE_NAME,
		dir_name_buf_len + sizeof(TASK_FILE_NAME));

	handler = fopen(file_name_buf, "r");

	if (!handler) {
		_D("can't open %s file\n", file_name_buf);
		return;
	}

	while (read_int(handler, &pid_for_read) >= 0) {
		tc.pids = g_array_append_val(tc.pids, pid_for_read);
		++tc.pid_count;
	}
	*tasks_classids_list = g_array_append_val(*tasks_classids_list, tc);

	fclose(handler);
}

int update_classids(void)
{
	DIR *dir;
	struct dirent *entry;

	char file_name_buf[256];
	size_t path_to_cgroup_dir_len =
	    sizeof(PATH_TO_NET_CGROUP_DIR) - 1, file_name_len;
	strncpy(file_name_buf, PATH_TO_NET_CGROUP_DIR, sizeof(file_name_buf));

	if (tasks_classids) {
		array_foreach(tc, struct task_classid, tasks_classids) {
			g_array_free(tc->pids, TRUE);
		}
		g_array_free(tasks_classids, TRUE);
	}

	tasks_classids = g_array_new(FALSE, FALSE, sizeof(struct task_classid));

	dir = opendir(file_name_buf);

	if (!dir)
		return ERROR_UPDATE_CLASSIDS_LIST;

	while ((entry = readdir(dir)) != 0) {
		if (entry->d_type != DT_DIR || entry->d_name[0] == '.')
			continue;

		file_name_len = strlen(entry->d_name);
		if (file_name_len + path_to_cgroup_dir_len >
		    sizeof(file_name_buf)) {
			_D("not enought buffer size\n");
			continue;
		}

		strncpy(file_name_buf + path_to_cgroup_dir_len, entry->d_name,
			file_name_len + 1);

		read_task_classid(file_name_buf,
				  path_to_cgroup_dir_len + file_name_len,
				  entry->d_name, &tasks_classids);
	}
	closedir(dir);
	_D("class id table updated");
	return 0;
}

int_array *get_monitored_pids(void)
{
	int_array *result = g_array_new(FALSE, FALSE, sizeof(pid_t));

	if (!result) {
		_D("Out of memory\n");
		return 0;
	}

	array_foreach(tc, struct task_classid, tasks_classids) {
		int i = 0;

		for (; i < tc->pid_count; ++i) {
			result = g_array_append_val(result,
				g_array_index(tc->pids, int, i));
		}
	}
	return result;
}

static char *get_app_id_by_classid_local(const u_int32_t classid)
{
	if (classid == RESOURCED_TETHERING_APP_CLASSID)
		return strdup(TETHERING_APP_NAME);
	array_foreach(tc, struct task_classid, tasks_classids)
		if (classid == tc->classid)
			return strdup(tc->cgroup_name);
	return 0;
}

char *get_app_id_by_classid(const u_int32_t classid, const bool update_state)
{
	int ret;
	char *appid = get_app_id_by_classid_local(classid);

	if (appid)
		return appid;

	_D("can't resolve app id");
	if (!update_state)
		return 0;

	ret = update_classids();
	ret_value_msg_if(ret, 0, "Can't get appid for %d", classid);

	return get_app_id_by_classid_local(classid);
}

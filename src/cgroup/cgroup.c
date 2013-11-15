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

#include "cgroup.h"
#include "macro.h"
#include "resourced.h"
#include "trace.h"
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

#define MAX_PATH_LENGTH 512
#define TASK_FILE_NAME  "/tasks"

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

static int _place_pid_to_cgroup_by_task(const char *cgroup_name_buf, const int pid)
{
	char task_name_buf[MAX_PATH_LENGTH] = { 0 };

	snprintf(task_name_buf, sizeof(task_name_buf), "%s%s",
		cgroup_name_buf, TASK_FILE_NAME);

	_SD("file_name_buf %s, pid %d\n", task_name_buf, pid);
	return fwrite_int(task_name_buf, pid);
}

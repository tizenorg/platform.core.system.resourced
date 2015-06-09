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
 * @file logging-memory.c
 *
 * @desc start memory logging system for resourced
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <linux/limits.h>

#include <ctype.h>
#include <stddef.h>

#include <dirent.h>
#include <sys/utsname.h>
#include <systemd/sd-journal.h>

#include "resourced.h"
#include "trace.h"
#include "file-helper.h"
#include "module.h"
#include "macro.h"
#include "proc-process.h"
#include "logging.h"
#include "smaps-helper.h"

#define	MEM_NAME "memory"
#define	MEM_COMMIT_INTERVAL		30*60	/* 30 min */

#define	MEM_MAX_INTERVAL		10*60	/* 10 min */
#define	MEM_INIT_INTERVAL		8*60	/* 8 min */
#define MEM_FOREGRD_INTERVAL		5*60	/* 5 min */
#define MEM_BACKGRD_INTERVAL		10*60	/* 10 min */
#define MEM_BACKGRD_OLD_INTERVAL	15*60	/* 15 min */

struct logging_memory_info {
	unsigned avg_pss;
	unsigned max_pss;
	unsigned avg_uss;
	unsigned max_uss;
	unsigned sampling_count;
	bool last_commited;
	time_t last_log_time;
	time_t log_interval;
	pid_t current_pid;
};

static void update_log_interval(struct logging_memory_info *loginfo, int oom,
	int always)
{
	if (!always && (oom < OOMADJ_FOREGRD_LOCKED))
		return;

	switch (oom) {
	case OOMADJ_DISABLE:
	case OOMADJ_SERVICE_MIN:
	case OOMADJ_SU:
		loginfo->log_interval = MEM_MAX_INTERVAL;
		break;
	case OOMADJ_INIT:
		loginfo->log_interval = MEM_INIT_INTERVAL;
		break;
	case OOMADJ_FOREGRD_LOCKED:
	case OOMADJ_FOREGRD_UNLOCKED:
	case OOMADJ_BACKGRD_LOCKED:
		loginfo->log_interval = MEM_FOREGRD_INTERVAL;
		break;
	case OOMADJ_BACKGRD_UNLOCKED:
		loginfo->log_interval = MEM_BACKGRD_INTERVAL;
		break;
	default:
		if (oom > OOMADJ_BACKGRD_UNLOCKED)
			loginfo->log_interval = MEM_BACKGRD_OLD_INTERVAL;
		break;
	}
}

static int init_memory_info(void **pl, pid_t pid, int oom, time_t now)
{
	struct logging_memory_info *info;

	info = (struct logging_memory_info *)
			malloc(sizeof(struct logging_memory_info));
	if (!info) {
		_E("malloc for logging_memory_info is failed");
		return RESOURCED_ERROR_FAIL;
	}
	info->current_pid = 0;
	info->avg_pss = 0;
	info->max_pss = 0;
	info->avg_uss = 0;
	info->max_uss = 0;
	info->last_log_time = now;
	info->sampling_count = 0;
	info->last_commited = false;

	update_log_interval(info, oom, 1);
	*pl = (void *)info;
	return RESOURCED_ERROR_NONE;
}

/* pss_interval should be adjusted depending on app type */
static int update_memory_info(void *pl, pid_t pid, int oom,
	time_t now, unsigned always)
{
	int ret = RESOURCED_ERROR_NONE;
	struct logging_memory_info *loginfo = (struct logging_memory_info *)pl;
	unsigned pss = 0, uss = 0;

	if (!always)
		if (now < loginfo->last_log_time + loginfo->log_interval)
			return ret;

	ret = smaps_helper_get_pss(pid, &pss, &uss);

	if (ret != RESOURCED_ERROR_NONE)
		return ret;

	loginfo->avg_pss = (loginfo->avg_pss * loginfo->sampling_count +
			pss)/(loginfo->sampling_count + 1);
	loginfo->avg_uss = (loginfo->avg_uss * loginfo->sampling_count +
			uss)/(loginfo->sampling_count + 1);
	if (pss > loginfo->max_pss)
		loginfo->max_pss = pss;
	if (uss > loginfo->max_uss)
		loginfo->max_uss = uss;

	loginfo->sampling_count++;
	loginfo->last_log_time = now;
	loginfo->last_commited = false;
	update_log_interval(loginfo, oom, 0);

	return ret;
}

static int write_memory_info(char *name, struct logging_infos *infos,
	int ss_index)
{
	struct logging_memory_info *mi = infos->stats[ss_index];

	if (!infos->running && mi->last_commited)
		return RESOURCED_ERROR_NONE;

	sd_journal_send("NAME=memory",
		"TIME=%ld", mi->last_log_time,
		"PNAME=%s", name,
		"AVG_PSS=%lu", mi->avg_pss,
		"MAX_PSS=%lu", mi->max_pss,
		"AVG_USS=%lu", mi->avg_uss,
		"MAX_USS=%lu", mi->max_uss,
		NULL);

	mi->last_commited = true;

	return RESOURCED_ERROR_NONE;
}

static struct logging_info_ops memory_info_ops = {
	.update	= update_memory_info,
	.write	= write_memory_info,
	.init	= init_memory_info,
};

static int logging_memory_init(void *data)
{
	int ret;
	ret = smaps_helper_init();
	if (ret != RESOURCED_ERROR_NONE) {
			_E("smaps helper failed");
			return RESOURCED_ERROR_FAIL;
	}

	ret = register_logging_subsystem(MEM_NAME, &memory_info_ops);
	if(ret != RESOURCED_ERROR_NONE) {
		_E("register logging subsystem failed");
		smaps_helper_free();
		return RESOURCED_ERROR_FAIL;
	}
	ret = update_commit_interval(MEM_NAME, MEM_COMMIT_INTERVAL);
	if(ret != RESOURCED_ERROR_NONE) {
		_E("update commit interval logging subsystem failed");
		smaps_helper_free();
		return RESOURCED_ERROR_FAIL;
	}

	_D("logging memory init finished");
	return RESOURCED_ERROR_NONE;
}

static int logging_memory_exit(void *data)
{
	_D("logging memory finalize");
	smaps_helper_free();
	return RESOURCED_ERROR_NONE;
}

static struct module_ops logging_memory_ops = {
	.priority	= MODULE_PRIORITY_NORMAL,
	.name		= "logging_memory",
	.init		= logging_memory_init,
	.exit		= logging_memory_exit,
};

MODULE_REGISTER(&logging_memory_ops)

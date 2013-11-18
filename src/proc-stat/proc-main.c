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
 * @file proc-main.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include <Ecore.h>
#include <resourced.h>
#include <Ecore_File.h>

#include "lowmem-handler.h"
#include "lowmem-process.h"
#include "proc-main.h"
#include "proc-noti.h"
#include "trace.h"
#include "proc-winstate.h"
#include "proc-handler.h"
#include "proc-monitor.h"
#include "module.h"

int resourced_proc_init(void)
{
	int ret;

	proc_noti_init( );

	proc_win_status_init();

	ret = proc_monitor_init();
	if (ret)
		_E("proc_monitor_init failed : %d", ret);

	return ret;
}

int resourced_proc_exit(void)
{
	return RESOURCED_ERROR_NONE;
}

int resourced_proc_active_action(int type, pid_t pid)
{
	int ret = 0, oom_score_adj = 0;
	if (get_proc_oom_score_adj(pid, &oom_score_adj) < 0) {
		_E("Empty pid or process not exists. %d", pid);
		return RESOURCED_ERROR_FAIL;
	}
	_SD("pid %d, type %d \n", pid, type);
	switch (type) {
	case PROC_CGROUP_SET_ACTIVE:
		ret = lowmem_set_active(pid, oom_score_adj);
		if (ret != RESOURCED_ERROR_OK)
			break;
	case PROC_CGROUP_SET_INACTIVE:
		ret = lowmem_set_inactive(pid, oom_score_adj);
		break;
	}
	return RESOURCED_ERROR_NONE;
}

int resourced_proc_action(int type, int argnum, char **arg)
{
	int pid;
	int ret = 0, oom_score_adj = 0;
	char *pidbuf = NULL, *cgroup_name = NULL;

	if (argnum < 1) {
		_E("Unsupported number of arguments!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	pidbuf = arg[0];
	if ((pid = atoi(pidbuf)) < 0) {
		_E("Invalid pid argument!");
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}

	/* Getting appid */
	if (argnum > 1) {
		/* It's possible to get appid from arg */
		cgroup_name = arg[1];
	}

	if (pid && (get_proc_oom_score_adj(pid, &oom_score_adj) < 0)) {
		_E("Empty pid or process not exists. %d", pid);
		return RESOURCED_ERROR_FAIL;
	}

	_SD("appid %s, pid %d, type %d \n", cgroup_name, pid, type);

	switch (type) {
	case PROC_CGROUP_SET_FOREGRD:
		dbus_proc_handler(PREDEF_FOREGRD, pidbuf);
		ret = lowmem_set_foregrd(pid, oom_score_adj);
		if (ret != 0)
			_E("Failed to handle lowmem foreground action!");
		break;
	case PROC_CGROUP_SET_LAUNCH_REQUEST:
		/* join_app_performance legacy name for
			creating net_cls cgroup */
		_SD("launch request %s, %d", cgroup_name, pid);

		/* init oom score adj value for preventing killing application during launching */
		set_proc_oom_score_adj(pid, OOMADJ_INIT);
		break;
	case PROC_CGROUP_SET_RESUME_REQUEST:
		/* init oom_score_value */
		if (oom_score_adj >= OOMADJ_BACKGRD_UNLOCKED)
			set_proc_oom_score_adj(pid, OOMADJ_INIT);
		break;
	case PROC_CGROUP_SET_TERMINATE_REQUEST:
		break;
	case PROC_CGROUP_SET_ACTIVE:
		ret = lowmem_set_active(pid, oom_score_adj);
		break;
	case PROC_CGROUP_SET_BACKGRD:
		dbus_proc_handler(PREDEF_BACKGRD, pidbuf);
		ret = lowmem_set_backgrd(pid, oom_score_adj);
		break;
	case PROC_CGROUP_SET_INACTIVE:
		ret = lowmem_set_inactive(pid, oom_score_adj);
		break;
	case PROC_CGROUP_GET_MEMSWEEP:
		ret = lowmem_sweep_memory(pid);
		break;
	case PROC_CGROUP_SET_NOTI_REQUEST:
		break;
	case PROC_CGROUP_SET_PROC_EXCLUDE_REQUEST:
		break;
	default:
		ret = RESOURCED_ERROR_INVALID_PARAMETER;
	}
	return ret;
}

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
 *
 */

/**
 * @file  resourced_dummy_process.c
 * @desc  util program to run dummy process for a infinite time
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define MEMORY_BAIT -1
#define ACTIVE_PROCESS 1

#define MBtoB(bytes) (bytes << 20)

/* Utility to start a dummy process (does nothing) which runs
 * for infinite time (sleeps for 5 seconds on each iteration
 * of an infinite loop)
 * Usage: resourced_dummy_process [oom_score_adj]
 *		oom_score_adj: optional argument
 *			OOM score of the started process is set
 *			to the value provided (if provided)
 */
int main(int argc, char *argv[])
{
	int oom_score_adj, oom_score_flag;
	FILE *oom_fp;
	char buf[256];

	if (argc < 1)
		oom_score_flag = 0;
	else {
		oom_score_flag = 1;
		oom_score_adj = atoi(argv[1]);
	}

	printf("Resourced tester: dummy process\n\n");

	/* Set oom score adj if it is provided as argument */
	if (oom_score_flag) {
		snprintf(buf, sizeof(buf), "/proc/%d/oom_score_adj", getpid());
		oom_fp = fopen(buf, "w");
		if (oom_fp) {
			printf("not able to write oom_score_adj (%d). please write it manually\n", oom_score_adj);
		} else {
			printf("writing oom_score_adj(%d) for dummy process", oom_score_adj);
			fprintf(oom_fp, "%d\n", oom_score_adj);
			fclose(oom_fp);
		}
	} else
		printf("oom_score_adj is not being written into. no args provided\n");

	printf("resourced_tester: dummy process %d running on empty loop\n", getpid());
	while (1)
		sleep(5);
	return 0;
}

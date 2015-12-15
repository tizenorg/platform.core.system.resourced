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
 * @file  resourced_memory_hog.c
 * @desc  util program to run memory hogging process for a given time
 **/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define MBtoB(mb) (mb << 20)
#define KBtoB(kb) (kb << 10)

/* Utility to start memory hogging process which runs for a given time
 * The oom score adj of the process started is -900 (important process)
 * Can be used to create memory pressure situations on the target
 * Usage: resourced_memory_hog <mem-size> <sleep-time>
 *		mem-size: Needed argument.
 *			Process allocates this memory (in MB)
 *		sleep-time: Needed argument.
 *			Process sleeps for this time (in seconds)
 *			before terminating
 */
int main(int argc, char *argv[])
{
	int memory_size, memory_alloted, page_size, sleep_time;
	char *memory_bait;
	FILE *fp;
	char buf[256];

	printf("Resourced tester: dummy process\n\n");

	if (argc < 2) {
		printf("resourced_tester: Memory hog process needs 2 arguments memory-size(in MB) and the time to sleep in seconds\n");
		return 0;
	}

	snprintf(buf, sizeof(buf), "/proc/%d/oom_adj", getpid());
	fp = fopen(buf, "w");
	if (!fp) {
		printf("resourced_tester: error in opening oom_score file\n");
		return 0;
	}
	fprintf(fp, "-17\n");
	fclose(fp);

	/* Set oom score adj to -900 to make it important process */
	snprintf(buf, sizeof(buf), "/proc/%d/oom_score_adj", getpid());
	fp = fopen(buf, "w");
	if (!fp) {
		printf("resourced_tester: error in opening oom_score_adj file\n");
		return 0;
	}
	fprintf(fp, "-900\n");
	fclose(fp);


	memory_size = MBtoB(atoi(argv[1]));
	sleep_time = atoi(argv[2]);
	page_size = KBtoB(4);
	memory_alloted = 0;
	printf("resourced_tester: dummy process %d running as memory hogger, taking %dB\n", getpid(), memory_size);

	/* Allocate memory in pages (till target size is reached)
	 * Use this memory so that kmalloc is actually called (pages are
	 * actually allocated). Sleep for given time after that.
	 */
	while (memory_alloted < memory_size) {
		memory_bait = (char *)malloc(page_size);
		memory_alloted += page_size;
		memory_bait[0] = memory_alloted%128;
	}
	sleep(sleep_time);
	return 0;
}

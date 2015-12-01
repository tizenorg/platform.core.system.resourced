
/*
   Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <linux/input.h>

#ifdef RESOURCED_BUILD
#include "util.h"
#else
static inline void closep(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}

static inline void fclosep(FILE **f)
{
	if (*f)
		fclose(*f);
}

static inline void pclosep(FILE **f)
{
	if (*f)
		pclose(*f);
}

#define _cleanup_close_ __attribute__((cleanup(closep)))
#define _cleanup_fclose_ __attribute__((cleanup(fclosep)))
#define _cleanup_pclose_ __attribute__((cleanup(pclosep)))
#endif

#define MAX_ORDER	11
#define CMD_EXTFRAG	"cat /sys/kernel/debug/extfrag/unusable_index"
#define CMD_KILL_COUNT	"grep -i 'we killed' /var/log/resourced.log | wc | awk '{print $1}'"
#define CMD_VMSTAT  	"vmstat | tail -n 1"

/* Various Logs file used */
#define LOG_FILENAME	"sluggish-test.log"
#define LOG_MEMPS	"memps.log"
#define LOG_KILLED_APP	"killedapps.log"
#define LOG_MEMORY	"memorystats.log"
#define LOG_ION		"ion_memory.log"
#define LOG_DMESG	"dmesg.log"
#define MARKER_LINE	"#########################################################"

#define APPLIST_FILENAME	"/etc/resourced/sluggish-test.conf"

#define KEY_INPUT_DEVICE	"/dev/input/event0"

#define SWAP(a,b)	do { \
				int t; \
				t = a; \
				a = b; \
				b = t; \
			} while (0)


#define ADD_EVENT(t, c, v) 	{ \
				.type = t, \
				.code = c, \
				.value = v, \
				}

#define MAX_APP		128

static int num_app;
static char applist[MAX_APP+1][128];

struct input_event events[] = {
        ADD_EVENT(1, 0x00, 0x01),
        ADD_EVENT(0, 0x00, 0x00),
        ADD_EVENT(1, 0x00, 0x00),
        ADD_EVENT(0, 0x00, 0x00),
};

struct vmstat_field {
	unsigned long r;
	unsigned long b;
	unsigned long swapused;
	unsigned long memfree;
	unsigned long membuf;
	unsigned long memcached;
	unsigned long si;
	unsigned long so;
	unsigned long bi;
	unsigned long bo;
	unsigned long in;
	unsigned long cs;
	unsigned long us;
	unsigned long sy;
	unsigned long id;
	unsigned long wa;
	unsigned long st;
};

static void send_key_event(int keycode)
{
	int i;
	int ret;
	_cleanup_close_ int fd = -1;

	fd = open(KEY_INPUT_DEVICE, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "%s: Failed to open: %s : \n",
			KEY_INPUT_DEVICE, strerror(errno));
		return;
	}
	for (i = 0; i < 4; i++)
		memset(&events[i].time, 0x0, sizeof(struct timeval));

	events[0].code = keycode;
	events[2].code = keycode;

	for (i = 0; i < 4; i++) {
		ret = write(fd, &events[i], sizeof(struct input_event));
		if (ret < 0)
			return;
	}
}

static int get_kill_count(void)
{
	FILE *fp = NULL;
	char output[32];
	int count = 0;

	fp = popen(CMD_KILL_COUNT, "r");
	if (fp == NULL) {
		fprintf(stderr, "[%s]: ERROR: popen failed: %s\n",
				__func__, strerror(errno));
		return -1;
	}
	if (fgets(output, sizeof(output), fp) != NULL) {
		count = atoi(output);
	}
	pclose(fp);
	return count;
}

static float get_average_fraglevel(const char *zone)
{
	int i;
	_cleanup_pclose_ FILE *fp = NULL;
	float tmp_fraglevel, fraglevel = 0.00F;
	char discard[256], zonename[8];

	fp = popen(CMD_EXTFRAG, "r");
	if (fp == NULL) {
		fprintf(stderr, "ERROR: %s: Not present!\n", CMD_EXTFRAG);
		return -1;
	}
	while (fscanf(fp, "%*s %*s %*s %s", zonename) == 1) {
		if (strcmp(zonename, zone) != 0) {
			char *ret;
			ret = fgets(discard, sizeof(discard), fp);
			if (ret == NULL)
				return 0.00F;

			continue;
		}

		fraglevel = 0.00F;
		for (i = 0; i < MAX_ORDER; i++) {
			if (fscanf(fp, "%f", &tmp_fraglevel) == 1)
				fraglevel += tmp_fraglevel;
			else
				return 0.00F;
		}
	}

	/* Convert to summary percent value */
	fraglevel = (fraglevel * 100) / MAX_ORDER;

	return fraglevel;
}

static void get_vmstat_data(struct vmstat_field *vmstat)
{
	int ret;
	FILE *fp = NULL;
	char output[256];

	if (vmstat == NULL) {
		fprintf(stderr, "[%s]: ERROR: vmstat is NULL! \n", __func__);
		return;
	}
	memset(output, 0, sizeof(output));

	fp = popen(CMD_VMSTAT, "r");
	if (fp == NULL) {
		fprintf(stderr, "[%s]: ERROR: popen failed: %s\n",
				__func__, strerror(errno));
		return;
	}
	while (fgets(output, sizeof(output), fp) != NULL) {
		ret = sscanf(output, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
			&vmstat->r,&vmstat->b,&vmstat->swapused,&vmstat->memfree,&vmstat->membuf,
			&vmstat->memcached,&vmstat->si,&vmstat->so,&vmstat->bi,&vmstat->bo,&vmstat->in,
			&vmstat->cs,&vmstat->us,&vmstat->sy,&vmstat->id,&vmstat->wa,&vmstat->st);
		if (ret < 17) {
			fprintf(stderr, "[%s]: ERROR: can't get full vmstat "
					"output! \n", __func__);
			pclose(fp);
			return;
		}
	}
	pclose(fp);
}


static void generate_random_array(int *arr)
{
	int i,j;
	int visited[MAX_APP+1] = {0,};
	static int random = 3;

	srand(random);
	random = rand() % num_app;
	j=1;
	for (i=0; i<num_app; i++) {
		int a,b;
		a = arr[i];
		b = arr[(i + j*random) % num_app];
		if (visited[a] || visited[b]) continue;
		SWAP(arr[a], arr[b]);
		visited[a] = visited[b] = 1;
		j++;
	}
}

static void print_date_in_logs(const char *logname)
{
	char cmdline[128] = {0,};
	char format[64] = {0,};
	int ret;
	time_t t;
	struct tm *tmt;

	t = time(NULL);
	tmt = localtime(&t);
	strftime(format, sizeof(format), "%a %d/%b/%Y %T", tmt);

	sprintf(cmdline, "echo \"START TIME: %s\" >> %s", format, logname);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline, "echo \"======================================\" >> %s", logname);
	ret = system(cmdline);
	if (ret < 0)
		return;
}

static void dump_logs(void)
{
	int ret;
	char cmdline[256];

	memset(cmdline, 0, sizeof(cmdline));

	print_date_in_logs(LOG_MEMORY);
	sprintf(cmdline,"free -tm >> %s", LOG_MEMORY);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline,"cat /proc/buddyinfo >> %s", LOG_MEMORY);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline,"cat /proc/meminfo >> %s", LOG_MEMORY);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline,"cat /proc/vmstat >> %s", LOG_MEMORY);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline,"cat /sys/kernel/debug/extfrag/unusable_index >> %s", LOG_MEMORY);
	ret = system(cmdline);
	if (ret < 0)
		return;

	print_date_in_logs(LOG_MEMPS);
	sprintf(cmdline,"memps -a >> %s", LOG_MEMPS);
	ret = system(cmdline);
	if (ret < 0)
		return;

	print_date_in_logs(LOG_ION);
	sprintf(cmdline,"cat /sys/kernel/debug/ion/heaps/ion_heap_cma_overlay >> %s", LOG_ION);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline,"cat /sys/kernel/debug/ion/heaps/ion_heap_system >> %s", LOG_ION);
	ret = system(cmdline);
	if (ret < 0)
		return;

	print_date_in_logs(LOG_DMESG);
	sprintf(cmdline,"dmesg -c >> %s", LOG_DMESG);
	ret = system(cmdline);
	if (ret < 0)
		return;

	/* Add beginning marker in all log files */
	sprintf(cmdline, "echo \"%s\" >> %s", MARKER_LINE, LOG_MEMORY);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline, "echo \"%s\" >> %s", MARKER_LINE, LOG_MEMPS);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline, "echo \"%s\" >> %s", MARKER_LINE, LOG_ION);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline, "echo \"%s\" >> %s", MARKER_LINE, LOG_DMESG);
	ret = system(cmdline);
	if (ret < 0)
		return;
	sprintf(cmdline, "echo \"%s\" >> %s", MARKER_LINE, LOG_KILLED_APP);
	ret = system(cmdline);
	if (ret < 0)
		return;
}

static void copy_files_to_storage(void)
{
	int ret;

	ret = system("cp -rf /opt/usr/media/Images/* /opt/storage/sdcard/");
	if (ret < 0)
		return;
}

void populate_applist(void)
{
	_cleanup_fclose_ FILE *fp = NULL;
	char appid[128];

	fp = fopen(APPLIST_FILENAME, "r");
	if (fp == NULL) {
		fprintf(stderr, "ERROR: could not open %s: %s\n",
				APPLIST_FILENAME, strerror(errno));
		return;
	}
	while (fgets(appid, sizeof(appid), fp) != NULL) {
		int len = strlen(appid);

		appid[len-1] = '\0';
		strncpy(applist[num_app++], appid, len);
	}
}

int get_launch_status(char *cmdline)
{
	FILE *fp;
	char output[32];

	memset(output, '\0', sizeof(output));
	fp = popen(cmdline, "r");
	if (fp == NULL) {
		fprintf(stderr, "%s: Failed to open: %s : %s\n",
				__func__, cmdline, strerror(errno));
		return -1;
	}
	if (fgets(output, sizeof(output), fp) != NULL) {
		if (strstr(output, "failed") != NULL) {
			pclose(fp);
			return -1;
		}
	}
	pclose(fp);
	return 0;
}

int main(int argc, char *argv[])
{
	int i = 0;
	int count = 1;
	int ret;
	time_t t;
	struct tm *tmt;
	int index[128] = {0,};
	int totalkillcount = 0;
	char *ptr = NULL;
	int loop_count = 0;
	_cleanup_fclose_ FILE *fp = NULL;

	if (argc < 2) {
		fprintf(stderr, "ERROR: Usage: %s <loop count>\n", argv[0]);
		return -1;
	}
	ptr = argv[1];
	for (ptr = argv[1]; *ptr != '\0'; ptr++) {
		if (!isdigit(*ptr)) {
			fprintf(stderr, "ERROR: Usage: <loop count is not integer>\n");
			return -1;
		}
	}
	loop_count = atoi(argv[1]);
	num_app = 0;

	/* Populate the applist array, by reading appid from text file */
	populate_applist();
	if (num_app == 0) {
		fprintf(stderr, "ERROR: Failed to populate applist\n");
		return -1;
	}

	/* Remove all logs before starting the test */
	ret = system("/bin/rm -rf *.log");
	if (ret < 0)
		return -1;
	ret = system("/bin/dmesg -C");
	if (ret < 0)
		return -1;
	ret = system("/bin/echo "" > /var/log/resourced.log");
	if (ret < 0)
		return -1;

	fp = fopen(LOG_FILENAME, "w");
	if (fp == NULL) {
		fprintf(stderr, "%s: Failed to open: %s : %s\n",
				argv[0], LOG_FILENAME, strerror(errno));
		return -1;
	}

	/* Initialize random array */
	for (i = 0; i < num_app; i++)
		index[i] = i;

	while (count <= loop_count) {
		int i = 0;
		char cmdline[128];
		int prevkillcount = 0;

		memset(cmdline, 0, sizeof(cmdline));

		ret = system("echo "" > /var/log/resourced.log");
		if (ret < 0)
			return -1;

		dump_logs();
		t = time(NULL);
		tmt = localtime(&t);
		strftime(cmdline, sizeof(cmdline), "%a %d/%b/%Y %T", tmt);
		fprintf(fp, "\nLOOP#%d, START TIME: %s\n", count, cmdline);
		fprintf(fp, "==============================================\n");

		fflush(fp);
		fprintf(fp, "Process						CPU_Usage(%%)	ActualFree(MB)	Reclaimable(MB)	SwapUsed(MB)	Fragmentation(%%)	Kill Count\n");
		fprintf(fp, "---------------------------------------------	------------	--------------	--------------	-----------	-----------------	----------\n");

		for (i = 0; i < num_app; i++) {
			unsigned long actualfree=0;
			unsigned long reclaimable=0;
			unsigned long swapused = 0;
			float fraglevel = 0.00F;
			float cpu_usage = 0.00F;
			struct vmstat_field vmstat;
			int rindex = 0;
			int killcount = 0;

			memset(cmdline, 0, sizeof(cmdline));
			memset(&vmstat, 0, sizeof(vmstat));
			rindex = index[i];
			sprintf(cmdline,"aul_test launch %s | grep failed", applist[rindex]);
			ret = system(cmdline);
			if (ret < 0)
				return -1;
			sleep(3);
			/* Check app launch status for failure */
			ret = get_launch_status(cmdline);
			if (ret != 0) {
				fprintf(stderr, "App Launch Failed: <%s>\n", applist[rindex]);
				continue;
			}
			/* get CPU usage after 3 second of launching */
			get_vmstat_data(&vmstat);
			cpu_usage = (vmstat.us + vmstat.sy);

			if (strstr(applist[rindex], "camera") != NULL) {
				sleep(2);
				/* Use VOLUME-DOWN key for camera capture */
				send_key_event(115);
				sleep(2);
			}
			sleep(10);
			memset(&vmstat, 0, sizeof(vmstat));
			/* get memory status after 10 seconds of launching */
			get_vmstat_data(&vmstat);
			actualfree = vmstat.memfree/1024;
			reclaimable = (vmstat.membuf + vmstat.memcached)/1024;
			swapused = vmstat.swapused/1024;
			/* Check for fragmentation level, only for Normal zone */
			fraglevel = get_average_fraglevel("Normal");
			killcount = get_kill_count();
			if (killcount > prevkillcount)
				totalkillcount += (killcount - prevkillcount);
			prevkillcount = killcount;
			fprintf(fp, "%d) %-34s\t\t%5.2f\t\t%6lu\t\t%8lu\t%4lu\t\t%5.2f\t%20d\n",
				rindex,applist[rindex],cpu_usage,actualfree,reclaimable,swapused,fraglevel,totalkillcount);
			sleep(5);
			/* Wait for 5 more seconds before dumping logs and minimizing */
			dump_logs();
			/* Trigger Home key press event, to minimize the app */
			send_key_event(139);
			/* Wait for 2 seconds for Home screen to appear */
			sleep(2);
			fflush(fp);
		}
		/* Suffle elements in the index array, randomly */
		generate_random_array(index);
		/* Copy few files to internal/external storage, or SD card */
		copy_files_to_storage();
		sprintf(cmdline, "grep -i 'we killed' /var/log/resourced.log >> %s", LOG_KILLED_APP);
		ret = system(cmdline);
		if (ret < 0)
			return -1;
		count++;
		sleep(10);
	}
	return 0;
}


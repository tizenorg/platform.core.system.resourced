/*
   Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.

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
#include <math.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <linux/limits.h>

#include <ctype.h>
#include <stddef.h>

#include <dirent.h>
#include <sys/utsname.h>

#include <getopt.h>

#include "file-helper.h"
#include "smaps.h"
#include "procfs.h"
#include "util.h"
#include "trace.h"
#include "cgroup.h"

#define STR_SGX_PATH	"/dev/pvrsrvkm"
#define STR_3D_PATH1	"/dev/mali"
#define STR_3D_PATH2	"/dev/kgsl-3d0"
#define STR_DRM_PATH1	"/drm mm object (deleted)"
#define STR_DRM_PATH2	"/dev/dri/card0"
#define MEMCG_PATH	"/sys/fs/cgroup/memory"
#define ZRAM_USED_PATH	"/sys/block/zram0/mem_used_total"

#define BUF_MAX         (BUFSIZ)            /* most optimal for libc::stdio */
#define BUF_INC_SIZE    (512 << 10)        /* maximal SMAPS I saw 2 MB     */

typedef struct geminfo geminfo;
typedef struct trib_mapinfo trib_mapinfo;

/* classify normal, graphic and other devices memory */
struct trib_mapinfo {
	unsigned shared_clean;
	unsigned shared_dirty;
	unsigned private_clean;
	unsigned private_dirty;
	unsigned shared_clean_pss;
	unsigned shared_dirty_pss;
	unsigned swap;
	unsigned rss;
	unsigned pss;
	unsigned size;
	unsigned graphic_3d;
	unsigned gem_rss;
	unsigned gem_pss;
	unsigned peak_rss;
	unsigned other_devices;
	unsigned gem_mmap;
};

struct geminfo {
	geminfo *next;
	unsigned int tgid;
	unsigned rss_size;
	unsigned pss_size;
	unsigned hcount;
};

static bool arg_sum = false;
static bool arg_all = false;
static bool arg_rss = false;
static bool arg_verbose = false;
static char *arg_file = NULL;


static unsigned get_peak_rss(unsigned int pid)
{
	static const char field[] = "VmHWM:";
	char tmp[128];
	char* line;
	char* value;

	snprintf(tmp, sizeof(tmp), "/proc/%d/status", pid);
	line = cread(tmp);
	if (line == NULL) {
		_E("cannot open %s", tmp);
		return 0;
	}

	value = strstr(line, field);
	if (value) {
		value += sizeof(field);
		return strtoul(value, NULL, 10);
	}

	return 0;
}
#define NUM_GEM_FIELD 6

static geminfo *read_geminfo(FILE *fp)
{
	geminfo *tgeminfo;
	char line[BUF_MAX];
	unsigned int pid, tgid, handle, refcount, hcount;
	unsigned gem_size;

	if (fgets(line, BUF_MAX, fp) == NULL)
		return NULL;

	if (sscanf(line, "%d %d %d %d %d 0x%x", &pid, &tgid,
	    &handle, &refcount, &hcount, &gem_size) != NUM_GEM_FIELD)
		return NULL;

	if (hcount == 0)
		return NULL;

	tgeminfo = malloc(sizeof(geminfo));
	if (tgeminfo == NULL)
		return NULL;

	tgeminfo->tgid = tgid;
	tgeminfo->hcount = hcount;
	tgeminfo->rss_size = BYTE_TO_KBYTE(gem_size);
	tgeminfo->pss_size = BYTE_TO_KBYTE(gem_size/tgeminfo->hcount);

	return tgeminfo;
}


static geminfo *load_geminfo(void)
{
	geminfo *ginfo;
	geminfo *gilist = NULL;
	_cleanup_fclose_ FILE *drm_fp = NULL;
	char line[BUF_MAX];

	drm_fp = fopen("/sys/kernel/debug/dri/0/gem_info", "r");

	if (drm_fp == NULL) {
		_E("cannot open /sys/kernel/debug/dri/0/gem_info");
		return NULL;
	}

	if (fgets(line, BUF_MAX, drm_fp) == NULL)
		return NULL;
	else {
		/* we should count a number of whitespace separated fields */
		int 	 in_field = (line[0] && !isblank(line[0]));
		unsigned int size = (unsigned)in_field;
		const char*  ptr  = &line[1];

		/* sscanf() was used in original code, so number of fields */
		/* in string is expected to be at least NUM_GEM_FIELD      */
		while (*ptr && size < NUM_GEM_FIELD) {
			if (isblank(*ptr++)) {
				if (in_field) {
					/* end of field */
					in_field = 0;
				}
			} else {
				if (!in_field) {
					/* next field started */
					in_field = 1;
					size++;
				}
			}
		} /* while */

		if (size != NUM_GEM_FIELD)
			return NULL;
	}

	while ((ginfo = read_geminfo(drm_fp)) != NULL) {
		if (gilist && ginfo->tgid == gilist->tgid) {
			gilist->pss_size += ginfo->pss_size;
			gilist->rss_size += ginfo->rss_size;
			free(ginfo);
			continue;
		}
		ginfo->next = gilist;
		gilist = ginfo;
	}

	return gilist;
}

static unsigned total_gem_memory(void)
{
	_cleanup_fclose_ FILE *gem_fp = NULL;
	unsigned total_gem_mem = 0;
	unsigned name, size, handles, refcount;
	char line[BUF_MAX];

	gem_fp = fopen("/proc/dri/0/gem_names", "r");
	if(gem_fp == NULL) {
		_E("cannot open /proc/dir/0/gem_names");
		return 0;
	}

	if (fgets(line, BUF_MAX, gem_fp) == NULL)
		return 0;

	while (fgets(line, BUF_MAX, gem_fp) != NULL)
		if (sscanf(line, "%d %d %d %d\n",
		    &name, &size, &handles, &refcount) == 4)
			total_gem_mem += size;

	return total_gem_mem;
}

/**
 * @desc Provides usage in bytes for provided memory cgroup. Works
 * with/without swap accounting.
 *
 * @param memcg_path[in] Full path to memory cgroup
 * @param swap[in] Boolean value for deciding if account usage with swap
 * @return current cgroup usage in bytes or 0 on error
 */
static unsigned int get_memcg_usage(const char *memcg_path, bool swap)
{
	int ret;
	unsigned int usage;

	if (swap) {
		ret = cgroup_read_node(memcg_path,
				"/memory.memsw.usage_in_bytes", &usage);
	} else {
		ret = cgroup_read_node(memcg_path, "/memory.usage_in_bytes",
				&usage);
	}

	if (ret != RESOURCED_ERROR_NONE)
		usage = 0;

	return usage;
}

static void get_memcg_info(void)
{
	char buf[PATH_MAX];
	_cleanup_closedir_ DIR *pdir = NULL;
	struct dirent entry;
	struct dirent *result;
	struct stat path_stat;
	long usage_swap;
	unsigned long usage, usage_with_swap;
	int ret;

	_I("====================================================================");
	_I("MEMORY CGROUPS USAGE INFO");

	pdir = opendir(MEMCG_PATH);
	if (pdir == NULL) {
		_E("cannot read directory %s", MEMCG_PATH);
		return;
	}

	while (!(ret = readdir_r(pdir, &entry, &result)) && result != NULL) {
		snprintf(buf, sizeof(buf), "%s/%s", MEMCG_PATH, entry.d_name);
		/* If can't stat then ignore */
		if (stat(buf, &path_stat) != 0)
			continue;

		/* If it's not directory or it's parent path then ignore */
		if (!(S_ISDIR(path_stat.st_mode) &&
			strncmp(entry.d_name, "..", 3)))
			continue;

		usage = get_memcg_usage(buf, false);
		usage_with_swap = get_memcg_usage(buf, true);
		/* It is posible by rounding errors to get negative value */
		usage_swap = usage_with_swap - usage;
		if (usage_swap < 0)
			usage_swap = 0;

		/* Case of root cgroup in hierarchy */
		if (!strncmp(entry.d_name, ".", 2))
			_I("%13s Mem %3ld MB (%6ld kB), Mem+Swap %3ld MB (%6ld kB), Swap %3ld MB (%6ld kB) \n",
				MEMCG_PATH, BYTE_TO_MBYTE(usage),
				BYTE_TO_KBYTE(usage),
				BYTE_TO_MBYTE(usage_with_swap),
				BYTE_TO_KBYTE(usage_with_swap),
				BYTE_TO_MBYTE(usage_swap),
				BYTE_TO_KBYTE(usage_swap));
		else
			_I("memcg: %13s  Mem %3ld MB (%6ld kB), Mem+Swap %3ld MB (%6ld kB), Swap %3ld MB (%6ld kB)",
				entry.d_name, BYTE_TO_MBYTE(usage),
				BYTE_TO_KBYTE(usage),
				BYTE_TO_MBYTE(usage_with_swap),
				BYTE_TO_KBYTE(usage_with_swap),
				BYTE_TO_MBYTE(usage_swap),
				BYTE_TO_KBYTE(usage_swap));

	}
}

static void get_mem_info(void)
{
	struct meminfo mi;
	int r;

	unsigned int free = 0;
	unsigned int total_mem = 0, available = 0, used;
	unsigned int swap_total = 0, swap_free = 0, zram_used, swap_used;
	unsigned int used_ratio;

	r = proc_get_meminfo(&mi,
			     (MEMINFO_MASK_MEM_TOTAL |
			      MEMINFO_MASK_MEM_FREE |
			      MEMINFO_MASK_MEM_AVAILABLE |
			      MEMINFO_MASK_CACHED |
			      MEMINFO_MASK_SWAP_TOTAL |
			      MEMINFO_MASK_SWAP_FREE));
	if (r < 0) {
		_E("Failed to get meminfo");
		return;
	}

	total_mem = mi.value[MEMINFO_ID_MEM_TOTAL];
	free = mi.value[MEMINFO_ID_MEM_FREE];
	available = mi.value[MEMINFO_ID_MEM_AVAILABLE];
	swap_total = mi.value[MEMINFO_ID_SWAP_TOTAL];
	swap_free = mi.value[MEMINFO_ID_SWAP_FREE];

	if (total_mem == 0)
		return;

	used = total_mem - available;
	used_ratio = used * 100 / total_mem;
	swap_used = swap_total - swap_free;

	if (fread_uint(ZRAM_USED_PATH, &zram_used) != RESOURCED_ERROR_NONE)
		zram_used = 0;

	_I("====================================================================");


	_I( "Total RAM size: \t%15d MB( %6d kB)",
	    KBYTE_TO_MBYTE(total_mem), total_mem);

	_I( "Used (Mem+Reclaimable): %15d MB( %6d kB)",
	    KBYTE_TO_MBYTE(total_mem - free), total_mem - free);

	_I( "Used (Mem+Swap): \t%15d MB( %6d kB)",
	    KBYTE_TO_MBYTE(used), used);

	_I( "Used (Mem):  \t\t%15d MB( %6d kB)",
	    KBYTE_TO_MBYTE(used), used);

	_I( "Used (Swap): \t\t%15d MB( %6d kB)",
	    KBYTE_TO_MBYTE(swap_used), swap_used);

	_I( "Used (Zram block device): %13d MB( %6d kB)",
	    BYTE_TO_MBYTE(zram_used), BYTE_TO_KBYTE(zram_used));

	_I( "Used Ratio: \t\t%15d  %%", used_ratio);

	_I( "Mem Free:\t\t%15d MB( %6d kB)",
	    KBYTE_TO_MBYTE(free), free);

	_I( "Available (Free+Reclaimable):%10d MB( %6d kB)",
	    KBYTE_TO_MBYTE(available), available);
}

static int get_tmpfs_info(void)
{
	_cleanup_fclose_ FILE *fp = NULL;
	char line[BUF_MAX];
	char tmpfs_mp[NAME_MAX];	/* tmpfs mount point */
	struct statfs tmpfs_info;

	fp = fopen("/etc/mtab", "r");
	if (fp == NULL)
		return -1;

	_I("====================================================================");
	_I( "TMPFS INFO");

	while (fgets(line, BUF_MAX, fp) != NULL) {
		if (sscanf(line, "tmpfs %s tmpfs", tmpfs_mp) == 1) {
			statfs(tmpfs_mp, &tmpfs_info);
			_I("tmpfs %16s  Total %8ld KB, Used %8ld, Avail %8ld",
			   tmpfs_mp,
			   /* 1 block is 4 KB */
			   tmpfs_info.f_blocks * 4,
			   (tmpfs_info.f_blocks - tmpfs_info.f_bfree) * 4,
			   tmpfs_info.f_bfree * 4);
		}
	}

	return 0;
}

static geminfo *find_geminfo(unsigned int tgid, geminfo *gilist)
{
	geminfo *gi;
	for (gi = gilist; gi; ) {
		if (gi->tgid == tgid)
			return gi;

		gi = gi->next;
	}
	return NULL;
}

static void init_trib_mapinfo(trib_mapinfo *tmi)
{
	if (!tmi)
		return;
	tmi->shared_clean = 0;
	tmi->shared_dirty = 0;
	tmi->private_clean = 0;
	tmi->private_dirty = 0;
	tmi->swap = 0;
	tmi->shared_clean_pss = 0;
	tmi->shared_dirty_pss = 0;
	tmi->rss = 0;
	tmi->pss = 0;
	tmi->size = 0;
	tmi->graphic_3d = 0;
	tmi->gem_rss = 0;
	tmi->gem_pss = 0;
	tmi->peak_rss = 0;
	tmi->other_devices = 0;
	tmi->gem_mmap = 0;
}

static int
get_trib_mapinfo(unsigned int tgid, struct smaps *maps,
		 geminfo *gilist, trib_mapinfo *result)

{
	geminfo *gi;

	int i;

	if (!result)
		return -EINVAL;

	init_trib_mapinfo(result);

	for (i = 0; i < maps->n_map; i++) {
		if (strstr(maps->maps[i]->name, STR_SGX_PATH)) {
			result->graphic_3d += maps->maps[i]->value[SMAPS_ID_PSS];
		} else if (strstr(maps->maps[i]->name, STR_3D_PATH1) ||
			strstr(maps->maps[i]->name, STR_3D_PATH2)) {
			result->graphic_3d += maps->maps[i]->value[SMAPS_ID_SIZE];
		} else if (maps->maps[i]->value[SMAPS_ID_RSS] != 0 &&
			   maps->maps[i]->value[SMAPS_ID_PSS] == 0 &&
			   maps->maps[i]->value[SMAPS_ID_SHARED_CLEAN] == 0 &&
			   maps->maps[i]->value[SMAPS_ID_SHARED_DIRTY] == 0 &&
			   maps->maps[i]->value[SMAPS_ID_PRIVATE_CLEAN] == 0 &&
			   maps->maps[i]->value[SMAPS_ID_PRIVATE_DIRTY] == 0 &&
			   maps->maps[i]->value[SMAPS_ID_SWAP] == 0) {
			result->other_devices += maps->maps[i]->value[SMAPS_ID_SIZE];
		} else if (!strncmp(maps->maps[i]->name, STR_DRM_PATH1, sizeof(STR_DRM_PATH1)) ||
			   !strncmp(maps->maps[i]->name, STR_DRM_PATH2, sizeof(STR_DRM_PATH2))) {
			result->gem_mmap += maps->maps[i]->value[SMAPS_ID_RSS];
		} else {
			result->shared_clean += maps->maps[i]->value[SMAPS_ID_SHARED_CLEAN];
			result->shared_dirty += maps->maps[i]->value[SMAPS_ID_SHARED_DIRTY];
			result->private_clean += maps->maps[i]->value[SMAPS_ID_PRIVATE_CLEAN];
			result->private_dirty += maps->maps[i]->value[SMAPS_ID_PRIVATE_DIRTY];
			result->swap += maps->maps[i]->value[SMAPS_ID_SWAP];
			result->rss += maps->maps[i]->value[SMAPS_ID_RSS];
			result->pss += maps->maps[i]->value[SMAPS_ID_PSS];
			result->size += maps->maps[i]->value[SMAPS_ID_SIZE];

			if(maps->maps[i]->value[SMAPS_ID_SHARED_CLEAN] != 0)
				result->shared_clean_pss += maps->maps[i]->value[SMAPS_ID_PSS];
			else if (maps->maps[i]->value[SMAPS_ID_SHARED_DIRTY] != 0)
				result->shared_dirty_pss += maps->maps[i]->value[SMAPS_ID_PSS];
		}
	}

	result->peak_rss = get_peak_rss(tgid);
	if (result->peak_rss < result->rss)
		result->peak_rss = result->rss;
	if (result->gem_mmap > 0)
		result->peak_rss -= result->gem_mmap;

	gi = find_geminfo(tgid, gilist);
	if (gi != NULL) {
		result->gem_rss = gi->rss_size;
		result->gem_pss = gi->pss_size;
	}

	return 0;
}

static int get_cmdline(unsigned int pid, char *cmdline)
{
	_cleanup_fclose_ FILE *fp = NULL;
	char buf[NAME_MAX] = {0, };

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	fp = fopen(buf, "r");
	if (fp == 0) {
		_E("cannot file open %s", buf);
		return RESOURCED_ERROR_FAIL;
	}

	return fscanf(fp, "%4096s", cmdline);
}

static int get_oomscoreadj(unsigned int pid)
{
	_cleanup_fclose_ FILE *fp = NULL;
	char tmp[256];
	int oomadj_val;

	snprintf(tmp, sizeof(tmp), "/proc/%d/oom_score_adj", pid);
	fp = fopen(tmp, "r");

	if (fp == NULL) {
		oomadj_val = -50;
		return oomadj_val;
	}
	if (fgets(tmp, sizeof(tmp), fp) == NULL) {
		oomadj_val = -100;
		return oomadj_val;
	}

	oomadj_val = atoi(tmp);

	return oomadj_val;
}

static void get_rss(pid_t pid, unsigned int *result)
{
	_cleanup_fclose_ FILE *fp = NULL;
	char proc_path[PATH_MAX];
	int rss = 0;

	*result = 0;

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/statm", pid);
	fp = fopen(proc_path, "r");
	if (fp == NULL)
		return;

	if (fscanf(fp, "%*s %d", &rss) < 1)
		return;

	/* convert page to Kb */
	*result = rss * 4;
	return;
}

static void show_rss(void)
{
	_cleanup_closedir_ DIR *pDir = NULL;
	struct dirent curdir;
	struct dirent *result;
	pid_t pid;
	char cmdline[PATH_MAX];
	_cleanup_fclose_ FILE *output_file = NULL;
	int oom_score_adj;
	unsigned int rss;
	int ret;

	pDir = opendir("/proc");
	if (pDir == NULL) {
		_E("cannot read directory /proc.");
		return;
	}

	_I("     PID    RSS    OOM_SCORE    COMMAND");

	while (!(ret = readdir_r(pDir, &curdir, &result)) && result != NULL) {
		pid = atoi(curdir.d_name);
		if (pid < 1 || pid > 32768 || pid == getpid())
			continue;

		if (get_cmdline(pid, cmdline) < 0)
			continue;
		get_rss(pid, &rss);
		oom_score_adj = get_oomscoreadj(pid);

		_I("%8d %8u %8d          %s",
		   pid,
		   rss,
		   oom_score_adj,
		   cmdline);


	} /* end of while */

	get_tmpfs_info();
	get_mem_info();

	return;
}

static int show_map_all_new(void)
{
	_cleanup_closedir_ DIR *pDir = NULL;
	struct dirent curdir;
	struct dirent *result;
	unsigned int pid;
	_cleanup_free_ geminfo *glist = NULL;
	unsigned total_pss = 0;
	unsigned total_private = 0;
	unsigned total_private_code = 0;
	unsigned total_private_data = 0;
	unsigned total_shared_code = 0;
	unsigned total_shared_data = 0;
	unsigned total_shared_code_pss = 0;
	unsigned total_shared_data_pss = 0;
	unsigned total_swap = 0;
	unsigned total_rss = 0;
	unsigned total_graphic_3d = 0;
	unsigned total_gem_rss = 0;
	unsigned total_gem_pss = 0;
	unsigned total_peak_rss = 0;
	unsigned total_allocated_gem = 0;
	trib_mapinfo tmi;
	char cmdline[PATH_MAX];
	_cleanup_fclose_ FILE *output_file = NULL;

	int r;

	pDir = opendir("/proc");
	if (pDir == NULL) {
		_E("cannot read directory /proc.");
		return 0;
	}

	glist = load_geminfo();

	if (!arg_sum) {
		if (arg_verbose)
			_I("     PID  S(CODE)  S(DATA)  P(CODE)  P(DATA)"
			   "     PEAK      PSS       3D"
			   "     GEM(PSS)  GEM(RSS)    SWAP"
			   "     OOM_SCORE_ADJ    COMMAND");
		else
			_I("     PID     CODE     DATA     PEAK     PSS"
			   "     3D      GEM(PSS)      SWAP      COMMAND");
	}

	while (!(r = readdir_r(pDir, &curdir, &result)) && result != NULL) {
		_cleanup_smaps_free_ struct smaps *maps = NULL;
		char *base_name = NULL;

		pid = atoi(curdir.d_name);
		if (pid < 1 || pid > 32768 || pid == getpid())
			continue;

		if (get_cmdline(pid, cmdline) < 0)
			continue;

		base_name = basename(cmdline);
		if (base_name && !strncmp(base_name, "mem-stress", strlen("mem-stress")+1))
			continue;

		r = smaps_get(pid, &maps, SMAPS_MASK_DEFAULT);
		if (r < 0) {
			_E("cannot get smaps of pid %d", pid);
			continue;
		}

		/* get classified map info */
		get_trib_mapinfo(pid, maps, glist, &tmi);

		if (!arg_sum) {
			if (arg_verbose)
				_I("%8d %8d %8d %8d %8d %8d %8d %8d %8d %8d %8d"
				   " %8d \t\t%s",
				   pid,
				   tmi.shared_clean, tmi.shared_dirty,
				   tmi.private_clean, tmi.private_dirty,
				   tmi.peak_rss, tmi.pss, tmi.graphic_3d,
				   tmi.gem_pss, tmi.gem_rss, tmi.swap,
				   get_oomscoreadj(pid), cmdline);
			else
				_I("%8d %8d %8d %8d %8d %8d %8d %8d      %s",
				   pid,
				   tmi.shared_clean +
				   tmi.private_clean,
				   tmi.shared_dirty + tmi.private_dirty,
				   tmi.peak_rss,
				   tmi.pss,
				   tmi.graphic_3d,
				   tmi.gem_pss,
				   tmi.swap, cmdline);

			if (tmi.other_devices != 0)
				_I("%s(%d) %d KB may mapped by device(s).",
				   cmdline, pid, tmi.other_devices);
		}

		total_private += (tmi.private_clean + tmi.private_dirty);
		total_pss += tmi.pss;
		total_rss += tmi.rss;
		total_graphic_3d += tmi.graphic_3d;
		total_gem_rss += tmi.gem_rss;
		total_gem_pss += tmi.gem_pss;
		total_private_code += tmi.private_clean;
		total_private_data += tmi.private_dirty;
		total_swap += tmi.swap;
		total_shared_code += tmi.shared_clean;
		total_shared_data += tmi.shared_dirty;
		total_peak_rss += tmi.peak_rss;

		total_shared_code_pss += tmi.shared_clean_pss;
		total_shared_data_pss += tmi.shared_dirty_pss;

	} /* end of while */

	total_allocated_gem = BYTE_TO_KBYTE(total_gem_memory());
	_I("==============================================="
	   "===============================================");
	if (arg_verbose) {
		_I("TOTAL:      S(CODE) S(DATA) P(CODE)  P(DATA)"
		   "    PEAK     PSS       3D    "
		   "GEM(PSS) GEM(RSS) GEM(ALLOC) SWAP TOTAL(KB)");
		_I("         %8d %8d %8d %8d %8d %8d %8d"
		   " %8d %8d %8d %8d %8d",
		   total_shared_code, total_shared_data,
		   total_private_code, total_private_data,
		   total_peak_rss,	total_pss, total_graphic_3d,
		   total_gem_pss, total_gem_rss,
		   total_allocated_gem, total_swap,
		   total_pss + total_graphic_3d +
		   total_allocated_gem);
	} else {
		_I("TOTAL:        CODE     DATA    PEAK     PSS     "
		   "3D    GEM(PSS) GEM(ALLOC)     TOTAL(KB)");
		_I("         %8d %8d %8d %8d %8d %8d %7d %8d %8d",
		   total_shared_code + total_private_code,
		   total_shared_data + total_private_data,
		   total_peak_rss, total_pss,
		   total_graphic_3d, total_gem_pss,
		   total_allocated_gem, total_swap,
		   total_pss + total_graphic_3d +
		   total_allocated_gem);

	}

	if (arg_verbose)
		_I("* S(CODE): shared clean memory, it includes"
		   " duplicated memory\n"
		   "* S(DATA): shared dirty memory, it includes"
		   " duplicated memory\n"
		   "* P(CODE): private clean memory\n"
		   "* P(DATA): private dirty memory\n"
		   "* PEAK: peak memory usage of S(CODE) + S(DATA)"
		   " + P(CODE) + P(DATA)\n"
		   "* PSS: Proportional Set Size\n"
		   "* 3D: memory allocated by GPU driver\n"
		   "* GEM(PSS): GEM memory devided by # of sharers\n"
		   "* GEM(RSS): GEM memory including duplicated memory\n"
		   "* GEM(ALLOC): sum of unique gem memory in the system\n"
		   "* TOTAL: PSS + 3D + GEM(ALLOC)");
	else
		_I("* CODE: shared and private clean memory\n"
		   "* DATA: shared and private dirty memory\n"
		   "* PEAK: peak memory usage of CODE + DATA\n"
		   "* PSS: Proportional Set Size\n"
		   "* 3D: memory allocated by GPU driver\n"
		   "* GEM(PSS): GEM memory deviced by # of sharers\n"
		   "* GEM(ALLOC): sum of unique GEM memory in the system\n"
		   "* TOTAL: PSS + 3D + GEM(ALLOC)");

	get_tmpfs_info();
	get_memcg_info();
	get_mem_info();

	return 1;
}

static int show_map_new(int pid)
{
	_cleanup_smaps_free_ struct smaps *maps = NULL;
	int r, i;

	maps = new0(struct smaps, 1);
	if (!maps)
		return -ENOMEM;

	r = smaps_get(pid, &maps, SMAPS_MASK_DEFAULT);
	if (r < 0) {
		_E("cannot get smaps of pid %d", pid);
		return r;
	}

	if (arg_sum) {
		_I(" S(CODE)  S(DATA)  P(CODE)  P(DATA)  PSS");
		_I("-------- -------- -------------------"
		   "------------------");

		_I("%8d %8d %8d %8d %8d %18d",
		   maps->sum[SMAPS_ID_SHARED_CLEAN],
		   maps->sum[SMAPS_ID_SHARED_DIRTY],
		   maps->sum[SMAPS_ID_PRIVATE_CLEAN],
		   maps->sum[SMAPS_ID_PRIVATE_DIRTY],
		   maps->sum[SMAPS_ID_SWAP],
		   maps->sum[SMAPS_ID_PSS]);
	} else {
		_I(" S(CODE)  S(DATA)  P(CODE)  P(DATA)  ADDR(start-end)"
		   "OBJECT NAME");
		_I("-------- -------- -------- -------- -----------------"
		   "------------------------------");
		for (i = 0; i < maps->n_map; i++)
			_I("%8d %8d %8d %8d %08x-%08x %s",
			   maps->maps[i]->value[SMAPS_ID_SHARED_CLEAN],
			   maps->maps[i]->value[SMAPS_ID_SHARED_DIRTY],
			   maps->maps[i]->value[SMAPS_ID_PRIVATE_CLEAN],
			   maps->maps[i]->value[SMAPS_ID_PRIVATE_DIRTY],
			   maps->maps[i]->start,
			   maps->maps[i]->end,
			   maps->maps[i]->name);
	}

	return 1;
}

static void memps_show_help(void)
{
	_E("memps [-a] | [-v] | [-s] <pid> | [-f] <output file full path>\n"
	   "\t-s = sum (show only sum of each)\n"
	   "\t-f = all (show all processes via output file)\n"
	   "\t-a = all (show all processes)\n"
	   "\t-v = verbos (show all processes in detail)");
}

static int memps_parse_args(int argc, char *argv[])
{
	static const struct option long_options[] = {
		{"sum",			no_argument,		NULL,	's'		},
		{"file",		required_argument,	NULL,	'f'		},
		{"all",			no_argument,		NULL,	'a'		},
		{"rss",			no_argument,		NULL,	'r'		},
		{"verbose",		no_argument,		NULL,	'v'		},
		{"help",		no_argument,		NULL,	'h'		},
		{0, 0, 0, 0}
	};
	int c = 0;

	while (c != -1) {
		c = getopt_long(argc, argv, "sf:arv", long_options, NULL);

		switch (c) {
		case 's':
			arg_sum = true;
			break;
		case 'f':
			arg_file = optarg;
			break;
		case 'a':
			arg_all = true;
			break;
		case 'r':
			arg_rss = true;
			break;
		case 'v':
			arg_verbose = true;
			break;
		case 'h':
			break;
		case '?':
			return -EINVAL;
		}
	}

	if (arg_all || arg_file || arg_verbose || arg_rss) {
		if ( optind != argc) {
			_E("Invalid arguments");
			return -EINVAL;
		}
	} else {
		if (optind + 1 != argc) {
			_E("Invalid arguments");
			return -EINVAL;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int r;

	r = memps_parse_args(argc, argv);
	if (r < 0) {
		memps_show_help();
		return EXIT_FAILURE;
	}

	if (arg_file)
		log_open(LOG_TYPE_FILE, arg_file);
	else
		log_open(LOG_TYPE_STANDARD, NULL);

	if (arg_all || arg_verbose)
		show_map_all_new();
	else if (arg_rss)
		show_rss();
	else
		show_map_new(atoi(argv[optind]));

	log_close();

	return 0;
}

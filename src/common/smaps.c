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

/*
 * @file smaps.c
 * @desc get smaps info of process
 */

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

#include "util.h"
#include "smaps.h"

static const char* const smaps_string_lookup[SMAPS_ID_MAX] = {
	[SMAPS_ID_ANON_HUGE_PAGES]	= "AnonHugePages",
	[SMAPS_ID_ANONYMOUS]		= "Anonymous",
	[SMAPS_ID_KERNEL_PAGE_SIZE]	= "KernelPageSize",
	[SMAPS_ID_LOCKED]		= "Locked",
	[SMAPS_ID_MMU_PAGE_SIZE]	= "MMUPageSize",
	[SMAPS_ID_PSWAP]		= "PSwap",
	[SMAPS_ID_PRIVATE_CLEAN]	= "Private_Clean",
	[SMAPS_ID_PRIVATE_DIRTY]	= "Private_Dirty",
	[SMAPS_ID_PSS]			= "Pss",
	[SMAPS_ID_REFERENCED]		= "Referenced",
	[SMAPS_ID_RSS]			= "Rss",
	[SMAPS_ID_SHARED_CLEAN]		= "Shared_Clean",
	[SMAPS_ID_SHARED_DIRTY]		= "Shared_Dirty",
	[SMAPS_ID_SIZE]			= "Size",
	[SMAPS_ID_SWAP]			= "Swap",
};

static void smap_free(struct smap *map)
{
	if (!map)
		return;

	if (map->mode)
		free(map->mode);

	if (map->name)
		free(map->name);

	free(map);
}

void smaps_free(struct smaps *maps)
{
	int i;

	if (!maps)
		return;

	for (i = 0; i < maps->n_map; i++)
		smap_free(maps->maps[i]);

	free(maps->maps);
	free(maps);
}

const char *smap_id_to_string(enum smap_id id)
{
	assert(id >= 0 && id < SMAPS_ID_MAX);

	return smaps_string_lookup[id];
}

static int add_smap_to_smaps(struct smaps *maps, struct smap *map)
{
	int i;

	assert(maps);
	assert(map);

	maps->n_map++;

	maps->maps = (struct smap **)realloc(
		maps->maps,
		sizeof(struct smap *) * maps->n_map);
	if (!maps->maps)
		return -ENOMEM;

	maps->maps[maps->n_map - 1] = map;

	for (i = 0; i < SMAPS_ID_MAX; i++)
		maps->sum[i] += map->value[i];

	return 0;
}

int smaps_get(pid_t pid, struct smaps **maps, enum smap_mask mask)
{
	_cleanup_free_ char *path = NULL;
	_cleanup_fclose_ FILE *f = NULL;
	struct smaps *m = NULL;
	char buf[LINE_MAX];
	bool get_line = true;
	int r;

	assert(maps);

	r = asprintf(&path, "/proc/%d/smaps", pid);
	if (r < 0)
		return -ENOMEM;

	r = access(path, F_OK);
	if (r < 0)
		return -errno;

	f = fopen(path, "re");
	if (!f)
		return -errno;

	m = new0(struct smaps, 1);
	if (!m)
		return -ENOMEM;

	for (;;) {
		struct smap *map = NULL;
		int n;

		if (get_line && !fgets(buf, sizeof(buf), f)) {
			if (ferror(f)) {
				r = -errno;
				goto on_error;
			}
			break;
		} else
			get_line = true;

		map = new0(struct smap, 1);
		if (!map) {
			r = -errno;
			goto on_error;
		}

		n = sscanf(buf, "%x-%x %ms %*s %*s %*s %ms",
			   &map->start, &map->end, &map->mode, &map->name);

		if (n == 3 && !map->name)
			map->name = strdup("[anon]");
		else if (n != 4) {
			free(map);
			r = -EINVAL;
			goto on_error;
		}

		for (;;) {
			_cleanup_free_ char *k = NULL;
			unsigned int v = 0;
			enum smap_id id;
			size_t l;

			if (!fgets(buf, sizeof(buf), f)) {
				if (ferror(f)) {
					r = -errno;
					goto on_error;
				}
				break;
			}

			if ((*buf >= '0' && *buf <= '9') ||
			    (*buf >= 'a' && *buf <= 'f')) {
				get_line = false;
				break;
			}

			l = strcspn(buf, ":");
			if (!l)
				break;

			k = strndup(buf, l);
			if (!k) {
				r = -ENOMEM;
				smap_free(map);
				goto on_error;
			}

			id = smap_string_to_id(k);
			if (id < 0 || id >= SMAPS_ID_MAX)
				continue;

			if (!(mask & (1 << id)))
				continue;

			if (sscanf(buf + l + 1, "%d kB", &v) != 1)
				break;

			map->value[id] = v;
		}

		r = add_smap_to_smaps(m, map);
		if (r < 0)
			goto on_error;
	}

	*maps = m;

	return 0;

on_error:
	smaps_free(m);
	return r;
}

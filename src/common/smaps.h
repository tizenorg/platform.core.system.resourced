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
 * @file smaps.h
 * @desc /proc/{PID}/smaps info loopup util
 */

#ifndef _RESOURCED_SMAPS_H_
#define _RESOURCED_SMAPS_H_

#include <assert.h>
#include <string.h>

#include "util.h"

enum smap_id {
	SMAPS_ID_INVALID = -1,
	SMAPS_ID_ANON_HUGE_PAGES = 0,
	SMAPS_ID_ANONYMOUS,
	SMAPS_ID_KERNEL_PAGE_SIZE,
	SMAPS_ID_LOCKED,
	SMAPS_ID_MMU_PAGE_SIZE,
	SMAPS_ID_PSWAP,
	SMAPS_ID_PRIVATE_CLEAN,
	SMAPS_ID_PRIVATE_DIRTY,
	SMAPS_ID_PSS,
	SMAPS_ID_REFERENCED,
	SMAPS_ID_RSS,
	SMAPS_ID_SHARED_CLEAN,
	SMAPS_ID_SHARED_DIRTY,
	SMAPS_ID_SIZE,
	SMAPS_ID_SWAP,
	SMAPS_ID_MAX,
};

enum smap_mask {
	SMAPS_MASK_ANON_HUGE_PAGES	= 1 << SMAPS_ID_ANON_HUGE_PAGES,
	SMAPS_MASK_ANONYMOUS		= 1 << SMAPS_ID_ANONYMOUS,
	SMAPS_MASK_KERNEL_PAGE_SIZE	= 1 << SMAPS_ID_KERNEL_PAGE_SIZE,
	SMAPS_MASK_LOCKED		= 1 << SMAPS_ID_LOCKED,
	SMAPS_MASK_MMU_PAGE_SIZE	= 1 << SMAPS_ID_MMU_PAGE_SIZE,
	SMAPS_MASK_PSWAP		= 1 << SMAPS_ID_PSWAP,
	SMAPS_MASK_PRIVATE_CLEAN	= 1 << SMAPS_ID_PRIVATE_CLEAN,
	SMAPS_MASK_PRIVATE_DIRTY	= 1 << SMAPS_ID_PRIVATE_DIRTY,
	SMAPS_MASK_PSS			= 1 << SMAPS_ID_PSS,
	SMAPS_MASK_REFERENCED		= 1 << SMAPS_ID_REFERENCED,
	SMAPS_MASK_RSS			= 1 << SMAPS_ID_RSS,
	SMAPS_MASK_SHARED_CLEAN		= 1 << SMAPS_ID_SHARED_CLEAN,
	SMAPS_MASK_SHARED_DIRTY		= 1 << SMAPS_ID_SHARED_DIRTY,
	SMAPS_MASK_SIZE			= 1 << SMAPS_ID_SIZE,
	SMAPS_MASK_SWAP			= 1 << SMAPS_ID_SWAP,
	SMAPS_MASK_ALL			= (1 << SMAPS_ID_MAX) - 1,
};

#define SMAPS_MASK_DEFAULT			\
	(SMAPS_MASK_SIZE |			\
	 SMAPS_MASK_RSS |			\
	 SMAPS_MASK_PSS |			\
	 SMAPS_MASK_SHARED_CLEAN |		\
	 SMAPS_MASK_SHARED_DIRTY |		\
	 SMAPS_MASK_PRIVATE_CLEAN |		\
	 SMAPS_MASK_PRIVATE_DIRTY |		\
	 SMAPS_MASK_SWAP |			\
	 SMAPS_MASK_PSWAP)

struct smap_mapping {
	const char* name;
	enum smap_id id;
};
typedef struct smap_mapping smap_mapping;

const smap_mapping *smap_mapping_lookup(const char *str, unsigned int len);

static inline enum smap_id smap_string_to_id(const char *str)
{
	const struct smap_mapping *m;

	assert(str);
	m = smap_mapping_lookup(str,
				strlen(str));
	return m ? m->id : SMAPS_ID_INVALID;
}

const char *smap_id_to_string(enum smap_id);

struct smap {
	unsigned int start;
	unsigned int end;
	char *mode;
	char *name;
	unsigned int value[SMAPS_ID_MAX];
};

struct smaps {
	unsigned int sum[SMAPS_ID_MAX];
	int n_map;
	struct smap **maps;
};

void smaps_free(struct smaps *maps);
int smaps_get(pid_t pid, struct smaps **maps, enum smap_mask mask);

static inline void smaps_freep(struct smaps **maps)
{
	if (*maps)
		smaps_free(*maps);
}

#define _cleanup_smaps_free_ _cleanup_ (smaps_freep)

#endif  /* _RESOURCED_SMAPS_H_ */

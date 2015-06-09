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
 *
 */

/**
 * @file memcontrol.h
 * @desc header file for handling memory cgroups
 **/

#ifndef __MEMCONTROL_H__
#define __MEMCONTROL_H__

#include <glib.h>
#include "lowmem-handler.h"
#include "const.h"

/* number of memory cgroups */
#define MEMCG_DEFAULT_NUM_SUBCGROUP		0
#define MEMCG_DEFAULT_EVENT_LEVEL		"medium"
#define MEMCG_DEFAULT_USE_HIERARCHY		0

#define MEMCG_LOW_RATIO			0.8
#define MEMCG_MEDIUM_RATIO		0.96
#define MEMCG_FOREGROUND_LEAVE_RATIO	0.25

struct memcg_info_t {
	/* name of memory cgroup */
	char name[MAX_PATH_LENGTH];
	/* id for sub cgroup. 0 if no hierarchy, 0 ~ MAX if use hierarchy */
	int id;
	/* limit ratio, if don't want to set limit, use NO_LIMIT*/
	float limit_ratio;
	unsigned int limit;
	/* leave memory usage */
	unsigned int oomleave;
	/* thresholds, normal, swap, low, medium, and leave */
	unsigned int threshold[LOWMEM_MAX_LEVEL];
	unsigned int threshold_leave;
	/* vmpressure event string. If don't want to register event, use null */
	char event_level[MAX_NAME_LENGTH];
	int evfd;
};

struct memcg_t {
	/* number of sub cgroups */
	int num_subcgroup;
	/* parent cgroup */
	struct memcg_info_t *info;
	/* set when using multiple sub cgroups */
	int use_hierarchy;
	/* list of child cgroups when using multi groups */
	GSList *cgroups;
};

void memcg_info_set_limit(struct memcg_info_t *memcg_info, float ratio,
	unsigned int totalram);
void memcg_info_init(struct memcg_info_t *memcg_info, const char *name);
void memcg_init(struct memcg_t *memcg);
void memcg_show(struct memcg_t *memcg);
int memcg_add_cgroups(struct memcg_t *memcg, int num);

#endif /*__MEMCONTROL_H__*/

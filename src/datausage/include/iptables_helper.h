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

/**
 * @file iptables_helpter.h
 *
 * @desc Helper functions for iptables
 */

#ifndef _RESOURCED_DATAUSAGE_IPTABLES_HELPER_H
#define _RESOURCED_DATAUSAGE_IPTABLES_HELPER_H

#include "counter.h"

/**
 * @desc Creates base chains and rules needed for traffic statistic collecting.
 * @return 0 on success, otherwise error code
 */
int SetupChains();

/**
 * @desc Creates a pair of rules * one for ingoing and one for outgoing traffic,
 * for a given cgroup number.
 * @param cgroup_num - number of cgroup (for '--cgroup' parameter of rule).
 * @return 0 on success, otherwise error code
 */
int AddRuleForCgroup(int cgroup_num);

/**
 * @desc Reads counters from dedicated iptables rules.
 * @param cargs - a pointer to a struct that contains
 * two GTree fields, for ingoing and outgoing traffic.
 * @return 0 on success, otherwise error code
 */
int GetCgroupCounters( struct counter_arg *carg);

/**
 * @desc Resets counters in dedicated iptables rules.
 * @return 0 on success, otherwise error code
 */
int ZeroCounters();

#endif /* _RESOURCED_DATAUSAGE_IPTABLES_HELPER_H */

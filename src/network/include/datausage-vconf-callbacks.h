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
 */

/*
 *  @file: datausage-vconf-callbacks.h
 *
 *  @desc Add datausage callback functions to vconf
 *
 */

#ifndef _RESOURCED_DATAUSAGE_VCONF_CALLBACKS_H
#define _RESOURCED_DATAUSAGE_VCONF_CALLBACKS_H

#include "counter.h"

void resourced_add_vconf_datausage_cb(struct counter_arg *carg);

void resourced_remove_vconf_datausage_cb(void);

#endif /* _RESOURCED_DATAUSAGE_VCONF_CALLBACKS_H */

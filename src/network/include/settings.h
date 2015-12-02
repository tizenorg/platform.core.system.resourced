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
 *
 * @file settings.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef TRESOURCED_LIBS_LOAD_OPTIONS_H_
#define TRESOURCED_LIBS_LOAD_OPTIONS_H_

#include "data_usage.h"

#define RESOURCED_WIFI_STATISTICS_PATH "db/resourced/wifi_statistics"
#define RESOURCED_DATACALL_PATH "db/resourced/datacall"
#define RESOURCED_DATAUSAGE_TIMER_PATH "db/resourced/datausage_timer"
#define RESOURCED_DATACALL_LOGGING_PATH "db/resourced/datacall_logging"

int load_vconf_net_options(resourced_options *options);

#endif /*TRESOURCED_LIBS_LOAD_OPTIONS_H_*/

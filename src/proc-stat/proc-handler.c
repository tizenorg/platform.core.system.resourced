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
 * @file proc-handler.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "trace.h"
#include "edbus-handler.h"

#define SIGNAL_NAME_OOMADJ_SET		"OomadjSet"

void dbus_proc_handler(char* type, char *buf)
{
	char *pa[3];
	int ret;

	pa[0] = type;
	pa[1] = "1";
	pa[2] = buf;

	ret = broadcast_edbus_signal_str(DEVICED_PATH_PROCESS, DEVICED_INTERFACE_PROCESS,
			SIGNAL_NAME_OOMADJ_SET, "sis", pa);
	if (ret < 0)
		_E("Fail to send dbus signal to deviced!!");
}

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
 */

/**
 * @file swap-common.c
 *
 * @desc Swap state definition for resourced
 */

#include "swap-common.h"
#include "module-data.h"
#include "trace.h"
#include "macro.h"

enum swap_state swap_get_state(void)
{
        struct shared_modules_data *modules_data = get_shared_modules_data();

        ret_value_msg_if(modules_data == NULL, RESOURCED_ERROR_FAIL,
                         "Invalid shared modules data\n");

        return modules_data->swap_data.swap_state;
}

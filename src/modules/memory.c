/*
 * resourced
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 * @file memory.c
 *
 * @desc Memory module
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "lowmem-handler.h"
#include "macro.h"
#include "module.h"
#include "resourced.h"
#include "trace.h"

static int resourced_memory_init(void *data)
{
	return lowmem_init();
}

static int resourced_memory_finalize(void *data)
{
	return RESOURCED_ERROR_NONE;
}

static struct module_ops memory_modules_ops = {
	.priority = MODULE_PRIORITY_NORMAL,
	.name = "memory",
	.init = resourced_memory_init,
	.exit = resourced_memory_finalize
};

MODULE_REGISTER(&memory_modules_ops)

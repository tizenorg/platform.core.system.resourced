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

#include <stdlib.h>
#include <stdio.h>

#include "util.h"
#include "procfs.h"

int main(int argc, char *argv[])
{

	int ret;
	struct meminfo mitc1, mitc2;
	unsigned int swap_free;
	unsigned int mem_available;

	printf("# proc_get_mem_available \n");
	mem_available = proc_get_mem_available();
	printf("MemAvailable: %u MB ( %u KB)\n",
	       mem_available, KBYTE_TO_BYTE(mem_available));

	printf("# proc_get_swap_free \n");
	swap_free = proc_get_swap_free();
	printf("SwapFree: %u KB ( %u B)\n",
	       swap_free, KBYTE_TO_BYTE(swap_free));

	printf("# proc_get_meminfo (3 bit mask) \n");
	ret = proc_get_meminfo(&mitc1, MEMINFO_MASK_MEM_TOTAL|MEMINFO_MASK_SWAP_TOTAL|MEMINFO_MASK_VMALLOC_CHUNK);
	if (ret < 0)
		printf("Error from proc_get_meminfo error: %d \n", ret);

	printf("MemTotal: %u KB \nSwapTotal: %u KB \nVmallocChunk: %u KB \n",
		mitc1.value[MEMINFO_ID_MEM_TOTAL],
		mitc1.value[MEMINFO_ID_SWAP_TOTAL],
		mitc1.value[MEMINFO_ID_VMALLOC_CHUNK]);

	printf("# proc_get_meminfo (mask all) \n");
	ret = proc_get_meminfo(&mitc2, MEMINFO_MASK_ALL);
	if (ret < 0)
		printf("Error from proc_get_meminfo error: %d \n", ret);

	printf("MemTotal: %u KB \nBuffers: %u KB \nSwapTotal: %u KB \nPageTables: %u KB \nCommitLimit: %u KB \nVmallocChunk: %u KB \n",
		mitc2.value[MEMINFO_ID_MEM_TOTAL],
		mitc2.value[MEMINFO_ID_BUFFERS],
		mitc2.value[MEMINFO_ID_SWAP_TOTAL],
		mitc2.value[MEMINFO_ID_PAGE_TABLES],
		mitc2.value[MEMINFO_ID_COMMIT_LIMIT],
		mitc2.value[MEMINFO_ID_VMALLOC_CHUNK]);

	return 0;
}

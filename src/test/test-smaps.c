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

#include "smaps.h"

int main(int argc, char *argv[])
{
	_cleanup_smaps_free_ struct smaps *maps;
	int i, j;
	int r;

	r = smaps_get(atoi(argv[1]), &maps, SMAPS_MASK_ALL);
	if (r < 0) {
		fprintf(stderr, "failed\n");
		goto exit;
	}


	for (i = 0; i < maps->n_map; i++) {
		fprintf(stdout, "%x-%-15x %-10s %s\n",
			maps->maps[i]->start,
			maps->maps[i]->end,
			maps->maps[i]->mode,
			maps->maps[i]->name);

		for (j = 0; j < SMAPS_ID_MAX; j++) {
			fprintf(stdout, "%-23s: %u\n",
				smap_id_to_string(j),
				maps->maps[i]->value[j]);
		}
	}

exit:
	return r < 0 ? EXIT_FAILURE :  EXIT_SUCCESS;
}

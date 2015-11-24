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

/**
 * @file iptables-test.c
 *
 */

#include "iptables-rule.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

enum iptables_test_cmd {
	CMD_INSERT,
	CMD_APPEND,
	CMD_DELETE,
};

int main(int argc, char *argv[])
{
	int i;
	char *opt, *parse;
	const char *pattern = "c%s_seth_w0"; /* "c4_1_7_seth_w0" */
	struct ipt_context iptc = {0};
	struct nfacct_rule rule;
	enum iptables_test_cmd cmd;

	if (argc <= 2) {
		puts(" Usage: \n");
		puts("iptables-test i|a|d counter1 counter2 counter 3 ... ");
		exit(1);
	}

	if (strcmp(argv[1], "i") == 0) {
		cmd = CMD_INSERT;
	} else if (strcmp(argv[1], "a") == 0) {
		cmd = CMD_APPEND;
	} else if (strcmp(argv[1], "d") == 0) {
		cmd = CMD_DELETE;
	} else {
		printf("Unknown command %s", argv[1]);
		exit(1);
	}

	memset(&rule, 0, sizeof(struct nfacct_rule));
	strcpy(rule.ifname, "seth_w0");
	resourced_ipt_begin(&iptc);

	resourced_ipt_dump(&iptc);

	for (i = 2; i < argc; ++i) {
		opt = argv[i];

		sprintf(rule.name, pattern, opt);
		parse = strtok(opt, "_");
		rule.iotype = atoi(parse);
		parse = strtok(NULL, "_");
		rule.iftype = atoi(parse);
		parse = strtok(NULL, "_");
		rule.classid = atoi(parse);

		if (cmd == CMD_INSERT)
			resourced_ipt_prepend(&rule, &iptc);
		else if (cmd == CMD_APPEND)
			resourced_ipt_append(&rule, &iptc);
		else if (cmd == CMD_DELETE)
			resourced_ipt_remove(&rule, &iptc);
	}

	return resourced_ipt_commit(&iptc);
}

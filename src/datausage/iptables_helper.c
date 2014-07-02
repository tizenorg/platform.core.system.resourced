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
 * @file iptables_helper.c
 *
 * @desc Helper functions for iptables
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <errno.h>
#include <data_usage.h>
#include <glib.h>
#include <sys/socket.h> /*for netlink.h*/
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Ecore.h>

#include "classid-helper.h"
#include "const.h"
#include "generic-netlink.h"
#include "genl.h"
#include "iface.h"
#include "macro.h"
#include "trace.h"
#include "transmission.h"

#define MAX_OUTPUT_LINE 1024
#define MAX_TOKENS 9
#define COUNTER_TOKEN 0
#define CHAIN_NAME_TOKEN 2
#define CGROUP_TXT_TOKEN 4
#define CGROUP_ID_TOKEN 6
#define COUNTER_SEPARATOR (int)':'

char * iptables_cmd = "/sbin/iptables";
char * iptables_save_cmd = "/sbin/iptables-save";
char * out_chain = "OUTPUT";
char * in_chain = "INPUT";
char * resourced_output_chain = "RESD_OUTPUT";
char * resourced_input_chain = "RESD_INPUT";
char * cgroup_rule_name = "cgroup";

typedef struct
{
	int cgroup;
	long int packets;
	long int bytes;
} tCgroupCounters;

static const char * StrNChr(const char * s, int c, size_t n)
{
	while(n && (*s))
	{
		if ((*s) == (char)c)
			return s;
		s++;
		n--;
	}
	return NULL;
}

static int SkipSpace(char ** txt)
{
	if ((!txt)||(!(*txt)))
		return -1;

	while ((**txt) && isspace(**txt))
	{
		(*txt)++;
	}
	if (*txt)
		return 1;
	else
		return 0;
}

static int SkipNspace(char ** txt)
{
	if ((!txt)||(!(*txt)))
		return -1;

	while ((**txt) && !isspace(**txt))
	{
		(*txt)++;
	}
	if (*txt)
		return 1;
	else
		return 0;
}

static int GetTokens(char * txt, int tok_num, int * tok_rd, char * * tok_bg, char * * tok_en)
{
	/* it is simpler, faster and more convenient than strtok */
	int tok_cnt, ret;

	if (!txt || !tok_num || !tok_bg || !tok_en )
		return -1;

	memset(tok_bg, 0, sizeof(char *) * tok_num);
	memset(tok_en, 0, sizeof(char *) * tok_num);
	tok_cnt = 0;

	while(1)
	{
		ret = SkipSpace(&txt);
		if(ret < 1)
			break;
		tok_bg[tok_cnt] = txt;
		ret = SkipNspace(&txt);
		tok_en[tok_cnt] = txt;
		tok_cnt++;
		if(tok_cnt == tok_num)
		{
			ret = 1;
			break;
		}
		if(ret < 1)
			break;
	}
	if(tok_rd)
		*tok_rd = tok_cnt;
	return ret;
}

int SetupChains()
{
	int ret;
	char cmd_buf[PATH_MAX+64];

	/* output traffic */
	ret = snprintf(cmd_buf, sizeof(cmd_buf),
			"%s -N %s", iptables_cmd, resourced_output_chain);
	if (ret >= sizeof(cmd_buf))
	{
		_D("buffer too small\n");
		return -1;
	}
	ret = system(cmd_buf);
	if (WEXITSTATUS(ret))
	{
		_D("error in adding iptables chains\n");
		return -1;
	}
	ret = snprintf(cmd_buf, sizeof(cmd_buf),
			"%s -A %s -j %s", iptables_cmd, out_chain, resourced_output_chain);
	if (ret >= sizeof(cmd_buf))
	{
		_D("buffer too small\n");
		return -1;
	}
	ret = system(cmd_buf);
	if (WEXITSTATUS(ret))
	{
		_D("error in adding iptables rules\n");
		return -1;
	}

	/* input traffic */
	ret = snprintf(cmd_buf, sizeof(cmd_buf),
			"%s -N %s", iptables_cmd, resourced_input_chain);
	if (ret >= sizeof(cmd_buf))
	{
		_D("buffer too small\n");
		return -1;
	}
	ret = system(cmd_buf);
	if (WEXITSTATUS(ret))
	{
		_D("error in adding iptables chains\n");
		return -1;
	}
	ret = snprintf(cmd_buf, sizeof(cmd_buf),
			"%s -A %s -j %s", iptables_cmd, in_chain, resourced_input_chain);
	if (ret >= sizeof(cmd_buf))
	{
		_D("buffer too small\n");
		return -1;
	}
	ret = system(cmd_buf);
	if (WEXITSTATUS(ret))
	{
		_D("error in adding iptables rules\n");
		return -1;
	}
	return 0;
}

int AddRuleForCgroup(int cgroup_num)
{
	int ret;
	char cmd_buf[PATH_MAX+64];

	/* output traffic */
	ret = snprintf(cmd_buf, sizeof(cmd_buf),
					"%s -A %s -m cgroup --cgroup %d -j RETURN",
					iptables_cmd, resourced_output_chain, cgroup_num);
	if (ret >= sizeof(cmd_buf))
	{
		_D("buffer too small\n");
		return -1;
	}
	ret = system(cmd_buf);
	if (WEXITSTATUS(ret))
	{
		_D("error in adding iptables rules\n");
		return -1;
	}

	/* input traffic */
	ret = snprintf(cmd_buf, sizeof(cmd_buf),
			"%s -A %s -m cgroup --cgroup %d -j RETURN",
			iptables_cmd, resourced_input_chain, cgroup_num);
	if (ret >= sizeof(cmd_buf))
	{
		_D("buffer too small\n");
		return -1;
	}
	ret = system(cmd_buf);
	if (WEXITSTATUS(ret))
	{
		_D("error in adding iptables rules\n");
		return -1;
	}
	return 0;
}


int GetCgroupCounters(struct counter_arg *carg)
{
	int ret;
	FILE * iptables_out;
	char cmd_buf[PATH_MAX+64];

	ret = snprintf(cmd_buf, sizeof(cmd_buf),
			"%s -t filter -c ", iptables_save_cmd);
	if (ret >= sizeof(cmd_buf))
	{
		_D("buffer too small\n");
		return -1;
	}
	iptables_out = popen(cmd_buf, "r");
	if (!iptables_out)
	{
		_D("popen error\n");
		return -1;
	}
	{
		char iptables_buf[MAX_OUTPUT_LINE];
		char * tok_bg[MAX_TOKENS], * tok_en[MAX_TOKENS];
		const char * pcounter;
		int tok_rd, out_chain = 0, in_chain = 0;
		struct classid_iftype_key *key;
		struct traffic_stat *val;

		while(fgets(iptables_buf, sizeof(iptables_buf), iptables_out))
		{
			_D("iptables gave us: %s\n\n", iptables_buf);
			ret = GetTokens(iptables_buf, MAX_TOKENS, &tok_rd, tok_bg, tok_en);
			if(tok_rd == MAX_TOKENS)
			{
				if (tok_en[CHAIN_NAME_TOKEN] > tok_bg[CHAIN_NAME_TOKEN])
				{
					in_chain = !strncmp(resourced_input_chain, tok_bg[CHAIN_NAME_TOKEN],
									(int)(tok_en[CHAIN_NAME_TOKEN] - tok_bg[CHAIN_NAME_TOKEN]));
					if (!in_chain)
					{
						out_chain = !strncmp(resourced_output_chain, tok_bg[CHAIN_NAME_TOKEN],
										(int)(tok_en[CHAIN_NAME_TOKEN] - tok_bg[CHAIN_NAME_TOKEN]));
					}
					else
						out_chain = 0;
				}

				if ((in_chain || out_chain)
					&& (tok_en[CGROUP_TXT_TOKEN] > tok_bg[CGROUP_TXT_TOKEN])
					&& (!strncmp(cgroup_rule_name, tok_bg[CGROUP_TXT_TOKEN],
							 (int)(tok_en[CGROUP_TXT_TOKEN] - tok_bg[CGROUP_TXT_TOKEN]))))
				{
					pcounter = StrNChr(tok_bg[COUNTER_TOKEN], COUNTER_SEPARATOR,
										(size_t)(tok_en[COUNTER_TOKEN] - tok_bg[COUNTER_TOKEN]));
					if (pcounter)
					{
						pcounter++;

						val = g_new(struct traffic_stat, 1);
						if (!val) {
							_D("Can't allocate memory\n");
							return -1;
						}

						key = g_new(struct classid_iftype_key, 1);
						if (!key) {
							_D("Can't allocate memory\n");
							g_free((gpointer)val);
							return -1;
						}

						val->bytes = atol(pcounter);
						val->ifindex = 0;
						key->classid = atoi(tok_bg[CGROUP_ID_TOKEN]);
						_D("classid: %d bytes:%lu\n\n", key->classid, val->bytes);

						if(!(key->classid))
						{
							key->classid = RSML_UNKNOWN_CLASSID;
						}
						key->iftype = 0;
						if (in_chain)
						{
							g_tree_insert((GTree *) (carg->in_tree), (gpointer)key, val);
						}
						else
						{
							g_tree_insert((GTree *) (carg->out_tree), (gpointer)key, val);
						}
					}
				}
			}
		}
	}
	pclose(iptables_out);
	return 0;
}

int ZeroCounters()
{
	int ret;
	char cmd_buf[PATH_MAX+64];

	/* output traffic */
	ret = snprintf(cmd_buf, sizeof(cmd_buf),
			"%s -Z %s ", iptables_cmd, resourced_output_chain);
	if (ret >= sizeof(cmd_buf))
	{
		_D("buffer too small\n");
		return -1;
	}
	ret = system(cmd_buf);
	if (WEXITSTATUS(ret))
	{
		_D("error in clearing iptables counters\n");
		return -1;
	}

	/* input traffic */
	ret = snprintf(cmd_buf, sizeof(cmd_buf),
			"%s -Z %s ", iptables_cmd, resourced_input_chain);
	if (ret >= sizeof(cmd_buf))
	{
		_D("buffer too small\n");
		return -1;
	}
	ret = system(cmd_buf);
	if (WEXITSTATUS(ret))
	{
		_D("error in clearing iptables counters\n");
		return -1;
	}
	return 0;
}

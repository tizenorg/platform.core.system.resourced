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
 * @file iptables-rule.h
 *
 * @desc Datausage module. This is iptables serialization implemenetation,
 * intended to be lightweight to support batch operations.
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#ifndef _IPTABLES_RULE_H
#define _IPTABLES_RULE_H

#include <glib.h>
#include <resourced.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

#include "config.h"
#include "nfacct-rule.h"

struct ipt_context;

enum ipt_verdict_type {
	IPT_R_STANDARD,		/* standard target (ACCEPT, ...) */
	IPT_R_MODULE,		/* extension module (SNAT, ...) */
	IPT_R_FALLTHROUGH,	/* fallthrough rule */
	IPT_R_JUMP,		/* jump to other chain */
};

struct ipt_chain {
	char name[XT_FUNCTION_MAXNAMELEN];
	/*
	 * resourced representation,
	 * in term of iptables it's entries
	 * list of resourced_iptables_entry
	 * */
	GList *rules;
	unsigned int num_rules;		/* number of rules in list */

	unsigned int head_offset;	/* offset in rule blob */
	unsigned int foot_offset;	/* offset in rule blob */
	unsigned int hooknum;		/* hook number+1 if builtin */

	int builtin;
	int verdict;			/* verdict if builtin,
					   for none builtin XT_RETURN will be chosen */

};

#define MAX_CHAIN_INDEX 32
struct ipt_chain_idx {
	int foot;
	int head;
	struct ipt_chain *chain;
};

struct ipt_context {
	char *name;
	int sock;

	/*
	 * Structure from netfilter_ipv4/ip_tables.h
	 * */
	struct ipt_getinfo *info;
	struct ipt_get_entries *blob_entries;

	/*
	 * information about original entries
	 * */
	size_t old_entries;

	/*
	 * list of chains, INPUT/OUTPUT/FORWARD/user chains here as well
	 * each chain contains list of rules
	 */
	GList *chains;

	size_t num_chains;
	struct ipt_chain_idx chain_idx[MAX_CHAIN_INDEX];
	/*
	 * number of entries
	 */
	size_t num_entries;

	/*
	 * size in memory
	 */
	size_t size;

	unsigned int underflow[NF_INET_NUMHOOKS];

	/*
	 * hook_entry[ID] offset to the chain start
	 */
	unsigned int hook_entry[NF_INET_NUMHOOKS];

	/* original iptables doing the same way */
	struct ipt_chain* chain_cursor;

	/* was insertion/deletion ? */
	bool modified;
};

enum resourced_rule_type {
	RESOURCED_UNKNOWN_IPT_RULE,
	RESOURCED_NEW_IPT_RULE, /* rule which was added/allocated */
	RESOURCED_OLD_IPT_RULE, /* rule which existed */
	RESOURCED_RULE_LAST_ELEM,
};

struct resourced_iptables_entry {

	/*
	 * NULL means we are dealing not with nfacct rule,
	 * it's not "our" rule, don't touch it.
	 * TODO: it's possible to grab it from entry,
	 * but need dificult parsing
	 */
	char nfacct_name[MAX_NAME_LENGTH];

	/*
	 * Structure from netfilter_ipv4/ip_tables.h
	 * This structure defines each of the firewall rules.  Consists of 3
	 * parts which are 1) general IP header stuff 2) match specific
	 * stuff 3) the target to perform if the rule matches
	 * It should be just a pointer to blob_entries
	 * */
	struct ipt_entry *entry;

	/*
	 * entry could chump to chain,
	 * user defined chains e.g. tethering chains
	 */
	struct ipt_chain *jump;
	enum ipt_verdict_type verdict_type;
	int verdict;

	unsigned int offset; /* calculated entry offset in new table */
	enum resourced_rule_type rule_type;
};

/* Necessary operations INSERT/DELETE/COMMIT */

/* ipt_start();
 * ipt_add();/ipt_del() or opt_ops  use nfacct_rule_action as part of interface
 * ipt_commit();
 */

/*
 * @desc Start new session. This function obtains list of
 * rule per table and fill it into ipt context
 * @param ipt - out parameter, context with list of rules
 * @param table_name - table name to operate
 * return RESOURCED_ERROR_NONE in case of success
 * */
resourced_ret_c resourced_ipt_begin(struct ipt_context *iptc);

/*
 * @desc Apply changes to kernel
 *
 * */
resourced_ret_c resourced_ipt_commit(struct ipt_context *iptc);

/*
 * insert to the begining
 * */
resourced_ret_c resourced_ipt_prepend(struct nfacct_rule *rule,
				  struct ipt_context *iptc);

/*
 * insert at the end
 * */
resourced_ret_c resourced_ipt_append(struct nfacct_rule *rule,
				  struct ipt_context *iptc);

/*
 * remove nfacct rule, rule will be found by cgroup and
 * nfacct_name match
 */
resourced_ret_c resourced_ipt_remove(struct nfacct_rule *rule,
				     struct ipt_context *iptc);

#ifdef NETWORK_DEBUG_ENABLED
resourced_ret_c resourced_ipt_dump(struct ipt_context *iptc);
#endif

#endif /* _IPTABLES_RULE_H */

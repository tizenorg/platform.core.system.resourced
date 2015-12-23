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
 * @file iptables-rule.c
 *
 * @desc Implementation of iptables seriailzation protocol
 * for nfacct_rule.
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

#include "datausage-common.h"
#include "iptables-rule.h"
#include "macro.h"
#include "trace.h"

#include <resourced.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>

/* from kernel-headers package */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/if.h> /* iptables.h requires IFNAMSIZ*/
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
/* end from kernel-headers package */


/*
 * XTABLES PART
 * this part is provided only by iptables package
 */

#define IPT_MIN_IPT_ALIGN (__alignof__(struct ipt_entry))

#define IPT_ALIGN(s) (((s) + ((IPT_MIN_IPT_ALIGN)-1)) & ~((IPT_MIN_IPT_ALIGN)-1))

struct nf_acct;

/*
 * neither xt_cgroup.h nor xt_nfacct.h is
 * not placed into iptables-devel package
 */

struct xt_nfacct_match_info {
	char		name[NFACCT_NAME_MAX];
	struct nf_acct	*nfacct;
};

struct xt_cgroup_info {
	__u32 id;
	__u32 invert;
};

/* END OF XTABLES PART */


#define TABLE_NAME "filter" /* default table name, but it's necessary to specify it */
#define NFACCT_MATCH_NAME "nfacct"
#define CGROUP_MATCH_NAME "cgroup"

#define XT_CGROUP_MATCH_SIZE (IPT_ALIGN(sizeof(struct xt_entry_match)) + IPT_ALIGN(sizeof(struct xt_cgroup_info)))
#define XT_NFACCT_MATCH_SIZE (IPT_ALIGN(sizeof(struct xt_entry_match)) + IPT_ALIGN(sizeof(struct xt_nfacct_match_info)))

#define IPTC_ENTRY_ERROR_TARGET_SIZE (sizeof(struct ipt_entry) + IPT_ALIGN(sizeof(struct xt_error_target)))
#define IPTC_ENTRY_STANDARD_TARGET_SIZE (sizeof(struct ipt_entry) + IPT_ALIGN(sizeof(struct xt_standard_target)))

#define NFACCT_RULE_SIZE IPT_ALIGN ((sizeof(struct ipt_entry)) + XT_CGROUP_MATCH_SIZE + \
	XT_NFACCT_MATCH_SIZE + IPT_ALIGN(sizeof(struct xt_standard_target)))

enum ipt_insert_type {
	IPT_INSERT_APPEND,
	IPT_INSERT_PREPEND,
};

static const char *builtin_chains[] = {
	[NF_IP_PRE_ROUTING]	= "PREROUTING",
	[NF_IP_LOCAL_IN]	= "INPUT",
	[NF_IP_FORWARD]		= "FORWARD",
	[NF_IP_LOCAL_OUT]	= "OUTPUT",
	[NF_IP_POST_ROUTING]	= "POSTROUTING",
};

struct resourced_ipt_entry_info {
	struct ipt_entry *entry;
	const char *chain_name;
	const char *nfacct_name;

	enum resourced_rule_type rule_type;
	unsigned int hook;
	size_t size;
	int builtin;
	int offset; /* offset in original table */
};

static struct ipt_entry *get_entry(struct ipt_context *iptc,
					unsigned int offset)
{
	return (struct ipt_entry *)((char *)iptc->blob_entries->entrytable +
									offset);
}

/* Returns 0 if not hook entry, else hooknumber + 1 */
static inline unsigned int
resourced_is_hook_entry(struct ipt_entry *e, struct ipt_context *iptc)
{
	unsigned int i;

	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		if ((iptc->info->valid_hooks & (1 << i))
		    && get_entry(iptc, iptc->info->hook_entry[i]) == e)
			return i + 1;
	}
	return 0;
}

static resourced_ret_c receive_ipt_items(struct ipt_context *iptc)
{
	socklen_t entry_size = sizeof(struct ipt_get_entries) + iptc->info->size;

	int err = getsockopt(iptc->sock, IPPROTO_IP, IPT_SO_GET_ENTRIES,
				iptc->blob_entries, &entry_size);
	ret_value_msg_if(err < 0, RESOURCED_ERROR_FAIL, "Failed to obtain iptables entries");

	return RESOURCED_ERROR_NONE;
}

/* if no chain with given name, create new one */
static struct ipt_chain *ipt_select_chain(struct ipt_context *iptc,
					  const char *chain_name,
					  int hook_number)
{
	GList *iter = NULL;
	struct ipt_chain *found_chain = NULL;

	if (chain_name == NULL || hook_number == 0) {
		_D("Couldn't find proper chain");
		return NULL;
	}
	for (iter = iptc->chains; iter; iter = iter->next) {
		struct ipt_chain *chain = iter->data;
		if (!strncmp(chain->name, chain_name, strlen(chain_name)+1)) {
			found_chain = chain;
			break;
		}
	}

	if (found_chain == NULL) {
		found_chain = (struct ipt_chain *)malloc(sizeof(struct ipt_chain));
		ret_value_msg_if(found_chain == NULL, NULL, "Not enough memory!");
		memset(found_chain, 0, sizeof(struct ipt_chain));
		strncpy(found_chain->name, sizeof(found_chain->name) - 1, chain_name);
		found_chain->hooknum = hook_number;
		iptc->chains = g_list_append(iptc->chains,
				found_chain);
	}

	return found_chain;
}

static void recalculate_verdict(struct ipt_chain *chain,
				struct resourced_iptables_entry *ipt_entry,
				int *verdict)
{
	struct xt_standard_target *t;

	/*
	 * recalculation is necessary only in cases of IPTCC_R_JUMP &&
	 * IPTCC_R_FALLTHROUGH
	 */
	if (ipt_entry->verdict_type != IPT_R_JUMP &&
		ipt_entry->verdict_type != IPT_R_FALLTHROUGH)
		return;

	t = (struct xt_standard_target *)ipt_get_target(ipt_entry->entry);
	if (ipt_entry->verdict_type == IPT_R_JUMP) {
		ret_msg_if(ipt_entry->jump == NULL, "Need to find jump destination.");

		memset(t->target.u.user.name, 0, XT_EXTENSION_MAXNAMELEN);
		strncpy(t->target.u.user.name, XT_STANDARD_TARGET, XT_EXTENSION_MAXNAMELEN - 1);
		/*
		 * Jumps can only happen in builtin chains, so we
		 * can safely assume that they always have a header
		 */
		t->verdict = ipt_entry->jump->head_offset + IPTC_ENTRY_ERROR_TARGET_SIZE;
		ipt_entry->verdict = t->verdict;
	} else if (ipt_entry->verdict_type == IPT_R_FALLTHROUGH) {
		t->verdict = ipt_entry->offset + ipt_entry->entry->next_offset;
	}
}

static struct ipt_chain *find_jump_chain(int offset, struct ipt_context *iptc)
{
	int pivot = iptc->num_chains/2;
	int step = 0;
	while (true) {
		/* head is lesser than foot */
		if (iptc->chain_idx[pivot].head <= offset &&
		    offset <= iptc->chain_idx[pivot].foot) {
			return iptc->chain_idx[pivot].chain;
		}

		if (pivot == 0 || pivot == iptc->num_chains - 1)
			break;
		step = (float)pivot/2 < 1 ? 1 : pivot/2;
		if (offset < iptc->chain_idx[pivot].head)
			pivot -= step;
		if (offset > iptc->chain_idx[pivot].foot)
			pivot += step;
	}

	return NULL;
}

/* find jumps, chain->head_offset/chain->foot_offset should be already calculated */
static void recalculate_verdicts(struct ipt_context *iptc)
{
	struct ipt_chain *chain;
	struct resourced_iptables_entry *ipt_entry;
	struct xt_standard_target *std_target;
	GList *cur_chain, *cur_rule;

	for (cur_chain = iptc->chains; cur_chain; cur_chain = cur_chain->next) {
		chain = cur_chain->data;
		for (cur_rule = chain->rules; cur_rule; cur_rule = cur_rule->next) {
			ipt_entry = cur_rule->data;
			if (ipt_entry->verdict_type == IPT_R_JUMP) {
				ipt_entry->jump = find_jump_chain(ipt_entry->verdict, iptc);
			}

			std_target = (struct xt_standard_target *)ipt_get_target(ipt_entry->entry);
			recalculate_verdict(chain, ipt_entry, &std_target->verdict);
		}
	}
}

/*
 * We have many insertions and at last stage need to recalculate
 * head/foot_offset it will be used to populate underflow/hook_entry
 * arrays
 */
static void build_offset_index(struct ipt_context *ipt)
{
	struct ipt_chain *chain;
	GList *cur_chain, *cur_rule;
	struct resourced_iptables_entry *ipt_entry;
	int offset = 0;

	for (cur_chain = ipt->chains; cur_chain; cur_chain = cur_chain->next) {
		chain = cur_chain->data;
		chain->head_offset = offset;
		for (cur_rule = chain->rules; cur_rule; cur_rule = cur_rule->next) {
			ipt_entry = cur_rule->data;
			ipt_entry->offset = offset;
			offset += ipt_entry->entry->next_offset;
		}
		/* need take into account removed auxilary entry */
		if (!chain->builtin) {
			offset += IPTC_ENTRY_ERROR_TARGET_SIZE;
		}
		chain->foot_offset = offset;
		ipt->chain_idx[ipt->num_chains].chain = chain;
		/* TODO think maybe keep just chain pointer */
		ipt->chain_idx[ipt->num_chains].head = chain->head_offset;
		ipt->chain_idx[ipt->num_chains].foot = chain->foot_offset;

		ipt->num_chains++;
		if (ipt->num_chains == MAX_CHAIN_INDEX) {
			_E("Unsupported number of chains. Could not calculate offsets!");
			return;
		}
		offset += sizeof(struct ipt_entry) + IPT_ALIGN(sizeof(struct xt_standard_target));
	}
}

/*
 * need recalculate, every time  when new entry is inserted or
 * removed or once in prepare_replace
 */
static void recalculate_final_offset(struct ipt_context *ipt)
{
	struct ipt_chain *chain;
	GList *cur_chain, *cur_rule;
	struct resourced_iptables_entry *ipt_entry;
	int offset = 0;

	for (cur_chain = ipt->chains; cur_chain; cur_chain = cur_chain->next) {
		chain = cur_chain->data;
		chain->head_offset = offset;
		for (cur_rule = chain->rules; cur_rule; cur_rule = cur_rule->next) {
			ipt_entry = cur_rule->data;
			ipt_entry->offset = offset;
			offset += ipt_entry->entry->next_offset;
		}
		/* need take into account removed auxilary entry */
		if (!chain->builtin) {
			offset += IPTC_ENTRY_ERROR_TARGET_SIZE;
		}
		chain->foot_offset = offset;

		offset += sizeof(struct ipt_entry) + IPT_ALIGN(sizeof(struct xt_standard_target));
	}
}

static resourced_ret_c ipt_populate_entry(struct ipt_context *iptc,
			      struct ipt_entry *entry,
			      const char *nfacct_name,
			      const char *chain_name,
			      const enum resourced_rule_type rule_type,
			      const enum ipt_insert_type insert_type,
			      const int hook_number,
			      const int builtin,
			      const enum ipt_verdict_type verdict_type,
			      const bool is_auxilary)
{
	struct resourced_iptables_entry *e = NULL;
	struct xt_standard_target *std_target = (struct xt_standard_target *)
			ipt_get_target(entry);

	struct ipt_chain *chain;

	ret_value_msg_if(iptc == NULL ||
			(chain_name == NULL && hook_number == 0), RESOURCED_ERROR_INVALID_PARAMETER,
			"Invalid parameter");

	chain = ipt_select_chain(iptc, chain_name, hook_number);

	if (chain == NULL) {
		_E("There is no chain with name %s", chain_name);
		return RESOURCED_ERROR_FAIL;
	}

	/* move chain cursor */
	if (chain != iptc->chain_cursor) {
		iptc->chain_cursor = chain;
	}
	/*
	 * chain's builtin couldn't be overwriten, due it was already filled,
	 * by builtin entry
	 */
	if (!chain->builtin) {
		chain->builtin = builtin;
	}

	iptc->num_entries++;
	iptc->size += entry->next_offset;

	/* it's footer, don't store it */
	if (is_auxilary) {
		_D("It's footer entry");

		/*
		 * we need obtain & save verdict from target,
		 * due we no longer keep it
		*/
		chain->verdict = std_target->verdict;
		free(entry);
		return RESOURCED_ERROR_NONE;
	}

	e = (struct resourced_iptables_entry *)malloc(sizeof(struct resourced_iptables_entry));
	ret_value_msg_if(e == NULL, RESOURCED_ERROR_FAIL,
			"Not enough memory");
	e->entry = entry;
	e->rule_type = rule_type;

	if (rule_type == RESOURCED_NEW_IPT_RULE)
		iptc->modified = true;

	if (verdict_type == IPT_R_JUMP) {
		e->verdict = std_target->verdict;
	}

	/* it means not nfacct entry */
	if (nfacct_name)
		strncpy(e->nfacct_name, nfacct_name, sizeof(e->nfacct_name) - 1);
	else
		strncpy(e->nfacct_name, "not nfacct entry", sizeof(e->nfacct_name) - 1); /* for debug purpose only */
	e->nfacct_name[sizeof(e->nfacct_name) - 1] = 0;

	e->verdict_type = verdict_type;
	if (insert_type == IPT_INSERT_APPEND)
		chain->rules = g_list_append(chain->rules, e);
	else if (insert_type == IPT_INSERT_PREPEND)
		chain->rules = g_list_prepend(chain->rules, e);
	else
		_E("Unknown insert type");

	return RESOURCED_ERROR_NONE;
}

static const char *define_chain_name(struct ipt_context *table,
			       int entry_offset, int *hook_number)
{
	unsigned int i;
	for (i = 1; i < NF_INET_NUMHOOKS; i++) {
		if (table->hook_entry[i] <= entry_offset &&
		    table->underflow[i] >= entry_offset) {
			*hook_number = i;
			break;
		}
	}

	if (i == NF_INET_NUMHOOKS) {
		_D("entry %d not in range", entry_offset);
		/*
		 * it could be user defined chain,
		 * get from current chain
		 */
		if (table->chain_cursor)
			return table->chain_cursor->name;

		return NULL;
	}

	return builtin_chains[i];
}

enum ipt_verdict_type reverse_target_type(int offset, struct ipt_entry *e)
{
	struct xt_standard_target *t = (struct xt_standard_target *)ipt_get_target(e);

	if (!strncmp(t->target.u.user.name, XT_STANDARD_TARGET, strlen(XT_STANDARD_TARGET)+1)) {
		if (t->target.u.target_size
		    != IPT_ALIGN(sizeof(struct xt_standard_target))) {
			_E("Mismatch target size for standard target!");
			return IPT_R_STANDARD;
		}

		if (t->verdict < 0) {
			_D("standard, verdict=%d\n", t->verdict);
			return IPT_R_STANDARD;
		} else if (t->verdict == offset + e->next_offset) {
			_D("fallthrough\n");
			return IPT_R_FALLTHROUGH;
		} else {
			_D("jump, target=%u\n", t->verdict);
			return IPT_R_JUMP;
			/* Jump target fixup has to be deferred
			 * until second pass, since we migh not
			 * yet have parsed the target */
		}
	}

	_D("module, target=%s\n", t->target.u.user.name);
	return IPT_R_MODULE;
}

/* works only for incoming blob */
static inline bool is_last_entry(struct ipt_context *t, struct ipt_entry *e)
{
	return (void *)e - (void *)t->blob_entries->entrytable + e->next_offset ==
		t->blob_entries->size;
}

static inline bool is_error_target(struct xt_error_target *t)
{
	return strncmp(t->target.u.user.name, XT_ERROR_TARGET, strlen(XT_ERROR_TARGET)+1) == 0;
}

static void clear_user_chain(struct ipt_context *table)
{
	GList *last;
	if (table->chain_cursor == NULL || table->chain_cursor->builtin)
		return;

	last = g_list_last(table->chain_cursor->rules);
	table->chain_cursor->rules = g_list_remove_link(table->chain_cursor->rules,
			last);
	free(last->data);
}

static resourced_cb_ret populate_entry(struct resourced_ipt_entry_info *info,
				       void *user_data)
{
	resourced_ret_c ret;
	struct ipt_context *table = user_data;
	int hook_number = NF_IP_NUMHOOKS;
	struct xt_error_target *t = NULL;
	const char *chain_name;
	bool is_auxilary_entry = false;
	int entry_offset;
	struct ipt_entry *new_entry;

	/*
	 * Last entry is always ERROR TARGET,
	 * which is created by ourself in
	 * prepare_replace
	 */
	if (is_last_entry(table, info->entry)) {
		/*
		 * need to remove last entry in none builtin chain,
		 * because it's imposible to determine is it last
		 * for user defined chains
		 */
		clear_user_chain(table);
		return RESOURCED_ERROR_NONE;
	}
	/*
	 *  info->entry should be from table->blobentries->entrytable,
	 *  for newly created entry chain name should be predefined by iotype
	 */
	entry_offset = (int)info->entry - (int)table->blob_entries->entrytable;
	t = (struct xt_error_target *)ipt_get_target(info->entry);

	/*
	 * not last and it's error target,
	 * so it's new user chain :)
	 */
	if (is_error_target(t)) {
		chain_name = (const char *)t->target.data;
		is_auxilary_entry = true;
	} else {
		chain_name = define_chain_name(table, entry_offset, &hook_number);
		is_auxilary_entry = strncmp(t->target.u.user.name, XT_STANDARD_TARGET, strlen(XT_STANDARD_TARGET)+1) == 0 &&
			info->entry->target_offset == sizeof(struct ipt_entry) &&
			info->entry->next_offset == IPTC_ENTRY_STANDARD_TARGET_SIZE &&
			(hook_number < NF_IP_NUMHOOKS && entry_offset == table->underflow[hook_number]);

	}

#ifdef NETWORK_DEBUG_ENABLED
	/* just for debug of verdict */
	if (is_auxilary_entry) {
		/* trace it */
		struct xt_standard_target *std_t = (struct xt_standard_target *)t;
		_D("footer entry->next_offset %d, verdict %d, %s",
		   info->entry->next_offset, std_t->verdict, "AUXILARY ENTRY");
	}
#endif /* NETWORK_DEBUG_ENABLED */

	new_entry = (struct ipt_entry *)malloc(info->entry->next_offset);

	ret_value_msg_if(new_entry == NULL, RESOURCED_ERROR_FAIL,
			"Not enough memory");

	memcpy(new_entry, info->entry, info->entry->next_offset);

	/*
	 * define jump/verdict type,
	 * definition should be based on existing kernel's entry
	 */
	ret = ipt_populate_entry(table, new_entry, info->nfacct_name, chain_name,
				 info->rule_type, IPT_INSERT_APPEND, hook_number,
				 info->builtin,
				 reverse_target_type(entry_offset, info->entry),
				 is_auxilary_entry);
	if (ret != RESOURCED_ERROR_NONE) {
		free(new_entry);
		return RESOURCED_CANCEL;
	}
	return RESOURCED_CONTINUE;
}

typedef resourced_cb_ret (*iterate_entries_cb)(struct resourced_ipt_entry_info *info, void *user_data);

static int find_nfacct_name (const struct xt_entry_match *match,
			char **found_name)
{
	if (match && !strncmp(match->u.user.name, NFACCT_MATCH_NAME, strlen(NFACCT_MATCH_NAME)+1)) {
		struct xt_nfacct_match_info *info = (struct xt_nfacct_match_info *)match->data;
		*found_name = info ? info->name: NULL;
		return  1; /* means stop */
	}
	return 0; /* means continue */
}

/* that function doen't allocate memory */
static char* extract_nfacct_name(struct ipt_entry *entry)
{
	char *found_nfacct_result = NULL;
	IPT_MATCH_ITERATE(entry, find_nfacct_name, &found_nfacct_result);
	return found_nfacct_result;
}

static resourced_ret_c ipt_foreach(struct ipt_context *iptc, iterate_entries_cb cb,
		       void *user_data)
{
	struct ipt_entry *entries = iptc->blob_entries->entrytable;
	/* unsigned int valid_hooks = iptc->info->valid_hooks; */
	unsigned int *underflow = iptc->info->underflow;
	unsigned int *hook_entry = iptc->info->hook_entry;

	struct resourced_ipt_entry_info info = {
		.entry = entries,
		.size = iptc->blob_entries->size,
	};

	resourced_cb_ret ret;

	int hook = 0; /* current hook defined by range hook_entry and underflow */

	for (info.offset = 0; info.offset < info.size;
	     info.offset += info.entry->next_offset) {
		info.rule_type = RESOURCED_OLD_IPT_RULE; /* TODO use enum */
		info.entry = (void *)entries + info.offset;

		for (;hook < NF_IP_NUMHOOKS; ++hook) {
			if (hook_entry[hook] <= info.offset &&
			    underflow[hook] > info.offset) {
				info.hook = hook;
				break;
			}
		}
		info.nfacct_name = extract_nfacct_name(info.entry);

		info.builtin = resourced_is_hook_entry(info.entry, iptc);
		if (info.builtin != 0) {
			_D("built in entry %s", builtin_chains[info.builtin - 1]);
		}

		ret = cb(&info, iptc);
		if (ret == RESOURCED_CANCEL)
			return RESOURCED_ERROR_NONE;
	}

	return RESOURCED_ERROR_NONE;
}

API resourced_ret_c resourced_ipt_begin(struct ipt_context *iptc)
{
	int ret;
	char error_buf[256];

	socklen_t s = sizeof(*iptc->info);
	ret_value_msg_if(iptc == NULL, RESOURCED_ERROR_INVALID_PARAMETER,
			"Please provide iptc handle");
	if (iptc->sock == 0) {
		iptc->sock = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
		ret_value_msg_if(iptc->sock < 0, RESOURCED_ERROR_FAIL, "Can't create iptables socket");
	}

	if (iptc->info == NULL) {
		iptc->info = (struct ipt_getinfo *)malloc(sizeof(struct ipt_getinfo));
		if (iptc->info == NULL) {
			_E("Not enough memory!");
			goto release_sock;
		}
	}

	snprintf(iptc->info->name,  sizeof(iptc->info->name), "%s", TABLE_NAME);
	ret = getsockopt(iptc->sock, IPPROTO_IP, IPT_SO_GET_INFO,
			 iptc->info, &s);

	if(ret < 0) {
		_E("iptables support missing error %d (%s)", errno,
			strerror_r(errno, error_buf, sizeof(error_buf)));
		goto release_info;
	}

	/* assume it's second usage and we need realloc */
	if (iptc->blob_entries) {
		iptc->blob_entries = (struct ipt_get_entries *)realloc(iptc->blob_entries,
				sizeof(struct ipt_get_entries) + iptc->info->size);
	} else {
		iptc->blob_entries = (struct ipt_get_entries *)malloc(
				sizeof(struct ipt_get_entries) + iptc->info->size);
	}

	if (!iptc->blob_entries) {
		_E("Not enough memory!");
		goto release_info;
	}

	memset(iptc->blob_entries, 0, sizeof(struct ipt_get_entries) + iptc->info->size);
	stpcpy(iptc->blob_entries->name, TABLE_NAME);
	iptc->blob_entries->size = iptc->info->size;

	/* read into context */
	ret = receive_ipt_items(iptc);
	if (ret != RESOURCED_ERROR_NONE) {
		_E("Failed to receive iptables blob!");
		goto release_entries;
	}

	iptc->num_entries = 0;
	iptc->old_entries = iptc->info->num_entries;
	iptc->size = 0;

	memcpy(iptc->underflow, iptc->info->underflow,
				sizeof(iptc->info->underflow));
	memcpy(iptc->hook_entry, iptc->info->hook_entry,
				sizeof(iptc->info->hook_entry));

	/* travers on blob to fill internal representation */
	ipt_foreach(iptc, populate_entry, NULL);

	/*
	 * here, before any insertion/deletion
	 * have occured due it's used by
	 * find_jump_chain which
	 * relays on origintal verdict
	 */
	build_offset_index(iptc);
	return RESOURCED_ERROR_NONE;
release_entries:
	free(iptc->blob_entries);
	iptc->blob_entries = NULL;
release_info:
	free(iptc->info);
	iptc->info = NULL;
release_sock:
	close(iptc->sock);
	iptc->sock = 0;
	return RESOURCED_ERROR_FAIL;
}

static resourced_ret_c send_ipt_items(struct ipt_context *iptc,
			  struct ipt_replace *r)
{
	int err = setsockopt(iptc->sock, IPPROTO_IP, IPT_SO_SET_REPLACE, r,
			sizeof(*r) + r->size);
	char error_buf[256];

	ret_value_msg_if(err < 0, RESOURCED_ERROR_FAIL,
			"Can't send iptables rules! %s [%d]",
			strerror_r(errno, error_buf, sizeof(error_buf)),
			errno);

	return RESOURCED_ERROR_NONE;
}

struct chain_error_placeholder {
	struct ipt_entry e;
	struct xt_error_target t;
};

struct chain_standard_placeholder {
	struct ipt_entry e;
	struct xt_standard_target t;
};

static struct ipt_replace *prepare_replace(struct ipt_context *iptc)
{
	struct ipt_replace *r;
	size_t replace_size = iptc->size + IPTC_ENTRY_ERROR_TARGET_SIZE;

	GList *cur_chain;
	GList *cur_entry;

	struct chain_error_placeholder *head;
	struct chain_error_placeholder *tail;
	struct chain_standard_placeholder *chain_tail;


	struct resourced_iptables_entry *e;
	struct ipt_chain *c;
	unsigned char *entry_index;

	r = (struct ipt_replace *)malloc(sizeof(struct ipt_replace) + replace_size);
	ret_value_msg_if(r == NULL, NULL, "Not enough memory");
	/*
	 * assign iptc->size initial + appended/removed and plus error whole table
	 * footer
	 */
	memset(r, 0, sizeof(struct ipt_replace) + replace_size);

	r->size = replace_size;
	/* xt_counters from linux/netfilter/x_ipts.h */
	r->counters = (struct xt_counters *)malloc(sizeof(struct xt_counters)
				* iptc->old_entries);
	if (!r->counters) {
		free(r);
		_E("Not enough memory");
		return NULL;
	}

	stpcpy(r->name, iptc->info->name);
	/* append one whole table footer */
	r->num_entries = iptc->num_entries + 1;

	r->num_counters = iptc->old_entries;
	r->valid_hooks  = iptc->info->valid_hooks;

	recalculate_final_offset(iptc);
	recalculate_verdicts(iptc);

	entry_index = (unsigned char *)r->entries;
	for (cur_chain = iptc->chains; cur_chain; cur_chain = cur_chain->next) {
		c = cur_chain->data;
		if (!c->builtin) {
			/* put c header in place */
			head = (void *)r->entries + c->head_offset;
			head->e.target_offset = sizeof(struct ipt_entry);
			head->e.next_offset = IPTC_ENTRY_ERROR_TARGET_SIZE;
			strcpy(head->t.target.u.user.name, IPT_ERROR_TARGET);
			head->t.target.u.target_size =
					IPT_ALIGN(sizeof(struct xt_error_target));
			strcpy(head->t.errorname, c->name);
			entry_index += head->e.next_offset;
		} else {
			/* current hook_entry[hook] it's underflow[hook - 1] + last->entry->next_offset */
			r->hook_entry[c->hooknum] = c->head_offset;
			r->underflow[c->hooknum] = c->foot_offset;
		}

		_D("c name %s", c->name);
		for (cur_entry = c->rules; cur_entry; cur_entry = cur_entry->next) {
			e = cur_entry->data;
			/*
			 * copy from whatever it was introduced by us in heap or
			 * obtained and stored in entries_blob
			 * e->entry->next_offset it's
			 *  Size of ipt_entry + matches + target
			 */
			memcpy(entry_index, e->entry, e->entry->next_offset);
			_D("e->entry->next_offset %d, %s", e->entry->next_offset, e->nfacct_name);
			entry_index += e->entry->next_offset;
		}
		/* put chain footer in place */
		chain_tail = (void *)r->entries + c->foot_offset;
		chain_tail->e.target_offset = sizeof(struct ipt_entry);
		chain_tail->e.next_offset = IPTC_ENTRY_STANDARD_TARGET_SIZE;
		strcpy(chain_tail->t.target.u.user.name, XT_STANDARD_TARGET);
		chain_tail->t.target.u.target_size =
					IPT_ALIGN(sizeof(struct xt_standard_target));
		entry_index += chain_tail->e.next_offset;

		/* builtin targets have verdict, others return */
		if (c->builtin)
			chain_tail->t.verdict = c->verdict;
		else
			chain_tail->t.verdict = XT_RETURN;

	}

	/* append error target affter all */
	tail = (void *)(r->entries) + r->size - IPTC_ENTRY_ERROR_TARGET_SIZE;
	tail->e.target_offset = sizeof(struct ipt_entry);
	tail->e.next_offset = IPTC_ENTRY_ERROR_TARGET_SIZE;
	tail->t.target.u.user.target_size =
		IPT_ALIGN(sizeof(struct xt_error_target));
	strcpy((char *)&tail->t.target.u.user.name, XT_ERROR_TARGET);
	strcpy((char *)&tail->t.errorname, XT_ERROR_TARGET);

	return r;
}

static void free_rules(gpointer data)
{
	struct resourced_iptables_entry *entry = (struct resourced_iptables_entry *)data;

	if (!entry)
		return;

	free(entry->entry);
	free(entry);
}

static void free_chains(gpointer data)
{
	struct ipt_chain *chain = (struct ipt_chain *)data;

	if (!chain)
		return;

	g_list_free_full(chain->rules, free_rules);
	free(chain);
}

static void ipt_context_release(struct ipt_context *iptc)
{
	g_list_free_full(iptc->chains, free_chains);

	free(iptc->blob_entries);
	free(iptc->info);
	close(iptc->sock);
}

API resourced_ret_c resourced_ipt_commit(struct ipt_context *iptc)
{
	resourced_ret_c ret_c = RESOURCED_ERROR_NONE;
	/* structure from /linux/netfilter_ipv4/ip_tables.h */
	struct ipt_replace *repl;

	if (iptc->modified) {
		repl = prepare_replace(iptc);

		ret_c = send_ipt_items(iptc, repl);

		free(repl->counters);
		free(repl);
	}

	ipt_context_release(iptc);
	return ret_c;
}

static void fill_builtin_target(struct nfacct_rule *rule, struct ipt_entry *new_entry)
{
	char target_buf[IPT_ALIGN(sizeof(struct xt_standard_target))] = { 0 };

	struct xt_entry_target *entry_target; /* pointer to target area in ipt_entry */

	struct xt_standard_target *res_target = (struct xt_standard_target *)target_buf;

	/*
	 * only builtin target are supported
	 * */
	strcpy(res_target->target.u.user.name, IPT_STANDARD_TARGET);
	res_target->target.u.target_size = sizeof(target_buf);

	/*
	 * this offset defines target start position in entry
	 * */
	new_entry->target_offset = sizeof(struct ipt_entry) + XT_CGROUP_MATCH_SIZE + XT_NFACCT_MATCH_SIZE;

	/*
	 * ipt_get_target makes evaluation based on target_offset
	 * */
	entry_target = ipt_get_target(new_entry);

	/*
	 * plus IPT_ALIGN(res_target->u.target_size) and it will be whole entry size
	 */
	new_entry->next_offset = sizeof(struct ipt_entry) + sizeof(target_buf)+
				XT_CGROUP_MATCH_SIZE + XT_NFACCT_MATCH_SIZE;

	/*
	 * it's not relative it's absolute value,
	 * need to calculate it in build_offset_index
	 */
	if (rule->jump == NFACCT_JUMP_ACCEPT)
		res_target->verdict = -NF_ACCEPT - 1;
	else if (rule->jump == NFACCT_JUMP_REJECT)
		res_target->verdict = -NF_DROP - 1;

	memcpy(entry_target, res_target, res_target->target.u.target_size);
}

static void fill_ipt_entry(struct nfacct_rule *rule, struct ipt_entry *entry)
{
	char match_buf[XT_NFACCT_MATCH_SIZE] = { 0 };
	struct xt_entry_match *match = (struct xt_entry_match *)match_buf;

	struct xt_nfacct_match_info nfacct_info;
	struct xt_cgroup_info cgroup_info = {
		.id = rule->classid,
	};

	char *dest_ifname = NULL;
	unsigned char *dest_ifmask = NULL;
       /* int iface_flag = 0; TODO necessary to support interface inversion */
	size_t iface_len = 0;

	memset(entry, 0, NFACCT_RULE_SIZE);
	if (rule->iotype == NFACCT_COUNTER_IN) {
		dest_ifname = entry->ip.iniface;
		dest_ifmask = entry->ip.iniface_mask;
       /*         iface_flag = IPT_INV_VIA_IN;*/
	}
	else if (rule->iotype == NFACCT_COUNTER_OUT) {
		dest_ifname = entry->ip.outiface;
		dest_ifmask = entry->ip.outiface_mask;
       /*         iface_flag = IPT_INV_VIA_OUT;*/
	}

	iface_len = strlen(rule->ifname);
	if (dest_ifname && iface_len) {
		snprintf(dest_ifname, IFNAMSIZ, "%s", rule->ifname);
		memset(dest_ifmask, 0xff, iface_len + 1);
	}

	snprintf(match->u.user.name, sizeof(match->u.user.name), "%s", CGROUP_MATCH_NAME);
	match->u.user.match_size = XT_CGROUP_MATCH_SIZE;
	memcpy(match->data, &cgroup_info, sizeof(struct xt_cgroup_info));
	memcpy(entry->elems, match,  XT_CGROUP_MATCH_SIZE);

	memset(&nfacct_info, 0, sizeof(struct xt_nfacct_match_info));
	snprintf(nfacct_info.name, sizeof(nfacct_info.name), "%s", rule->name);
	snprintf(match->u.user.name, sizeof(match->u.user.name), "%s", NFACCT_MATCH_NAME);
	match->u.user.match_size = XT_NFACCT_MATCH_SIZE;
	memcpy(match->data, &nfacct_info, sizeof(struct xt_nfacct_match_info));

	memcpy(entry->elems + XT_CGROUP_MATCH_SIZE, match,
	       XT_NFACCT_MATCH_SIZE);

	fill_builtin_target(rule, entry);
}

static int get_hook_by_iotype(struct nfacct_rule *rule)
{
	if (rule->iotype == NFACCT_COUNTER_IN)
		return NF_IP_LOCAL_IN;
	else if(rule->iotype == NFACCT_COUNTER_OUT)
		return NF_IP_LOCAL_OUT;

	return NF_IP_NUMHOOKS;
}

static const char *get_chain_name_by_rule(struct nfacct_rule *rule)
{
	return builtin_chains[get_hook_by_iotype(rule)];
}

static enum ipt_verdict_type get_verdict_type_by_rule(
		const struct nfacct_rule *rule)
{
	if (rule->jump == NFACCT_JUMP_REJECT ||
	    rule->jump == NFACCT_JUMP_ACCEPT)
		return IPT_R_STANDARD;

	return IPT_R_FALLTHROUGH;
}

static bool check_existence(struct nfacct_rule *rule, struct ipt_context *iptc)
{
	struct resourced_iptables_entry *e = NULL;
	struct ipt_chain *chain = NULL;
	GList *cur_chain, *cur_rule;
	for (cur_chain = iptc->chains; cur_chain; cur_chain = cur_chain->next) {
		chain = cur_chain->data;
		for (cur_rule = chain->rules; cur_rule; cur_rule = cur_rule->next) {
			e = cur_rule->data;
			if (strncmp(e->nfacct_name, rule->name, strlen(rule->name)+1) == 0)
				return true;
		}
	}
	return false;
}

static resourced_ret_c resourced_ipt_insert(struct nfacct_rule *rule,
					    struct ipt_context *iptc,
					    enum ipt_insert_type insert_type)
{
	struct ipt_entry *new_entry;

	if (check_existence(rule, iptc)) {
		_D("rule for %s already exists", rule->name);
		return RESOURCED_ERROR_NONE;
	}

	new_entry = (struct ipt_entry *)malloc(NFACCT_RULE_SIZE);;


	ret_value_msg_if(new_entry == NULL, RESOURCED_ERROR_FAIL,
			"Not enough memory");

	/*
	 * each nfacct rule consists of nfacct and cgroup match attribute,
	 * they are represented as xt_entry_match with data of type
	 * xt_cgroup_info and xt_nfacct_info accordingly
	 */
	fill_ipt_entry(rule, new_entry);

	return ipt_populate_entry(iptc, new_entry, rule->name,
			get_chain_name_by_rule(rule), RESOURCED_NEW_IPT_RULE,
			insert_type, get_hook_by_iotype(rule), 1,
			get_verdict_type_by_rule(rule), false);

}

API resourced_ret_c resourced_ipt_append(struct nfacct_rule *rule,
				      struct ipt_context *iptc)
{
	return resourced_ipt_insert(rule, iptc, IPT_INSERT_APPEND);
}

API resourced_ret_c resourced_ipt_prepend(struct nfacct_rule *rule,
				      struct ipt_context *iptc)
{
	return resourced_ipt_insert(rule, iptc, IPT_INSERT_PREPEND);
}

API resourced_ret_c resourced_ipt_remove(struct nfacct_rule *rule, struct ipt_context *iptc)
{
	/*
	 * to delete entry we need:
	 * struct ipt_ip *ip,
	 * const char *chain_name,
	 * const char *target_name,
	 * struct xtables_target *xt_t,
	 * GList *matches,
	 * struct xtables_rule_match *xt_rm
	 */

	/* find entry by rule */
	struct resourced_iptables_entry *e = NULL, *found_entry = NULL;
	GList *iter;

	int hook = get_hook_by_iotype(rule);
	struct ipt_chain *chain = ipt_select_chain(iptc, builtin_chains[hook],
						   hook);
	if (chain == NULL) {
		_E("Can't remove entry for %s", rule->name);
		return RESOURCED_ERROR_INVALID_PARAMETER;
	}
	for (iter = chain->rules; iter; iter = iter->next) {
		e = iter->data;
		if (!strncmp(e->nfacct_name, rule->name, strlen(rule->name)+1)) {
			found_entry = e;
			break;
		}
	}

	if (found_entry == NULL) {
		_D("entry for counter %s not found in chain %s", rule->name,
				chain->name);
		return RESOURCED_ERROR_NONE;
	}

	iptc->num_entries--;
	iptc->size -= found_entry->entry->next_offset;

	chain->rules = g_list_remove(chain->rules, found_entry);

	free(found_entry);
	iptc->modified = true;

	return RESOURCED_ERROR_NONE;
}

#ifdef NETWORK_DEBUG_ENABLED

static int dump_each_match(const struct xt_entry_match *match,
			const struct ipt_ip *ip)
{
	if (!strlen(match->u.user.name))
		return 0;

	_D("\tmatch %s", match->u.user.name);
	return 0;
}

static void dump_match(struct ipt_entry *entry)
{
	if (entry->target_offset) {
		IPT_MATCH_ITERATE(entry, dump_each_match, &entry->ip);
	}
}

static void dump_ip(struct ipt_entry *entry)
{
	struct ipt_ip *ip = &entry->ip;
	char ip_string[INET6_ADDRSTRLEN];
	char ip_mask[INET6_ADDRSTRLEN];

	if (strlen(ip->iniface))
		_D("\tin %s", ip->iniface);

	if (strlen(ip->outiface))
		_D("\tout %s", ip->outiface);

	if (inet_ntop(AF_INET, &ip->src, ip_string, INET6_ADDRSTRLEN) &&
			inet_ntop(AF_INET, &ip->smsk, ip_mask,
				INET6_ADDRSTRLEN))
		_D("\tsrc %s/%s", ip_string, ip_mask);

	if (inet_ntop(AF_INET, &ip->dst, ip_string, INET6_ADDRSTRLEN) &&
			inet_ntop(AF_INET, &ip->dmsk, ip_mask,
				INET6_ADDRSTRLEN))
		_D("\tdst %s/%s", ip_string, ip_mask);
}

static void dump_target(struct ipt_entry *entry)

{
	struct xt_entry_target *target = ipt_get_target(entry);

	if (strncmp(target->u.user.name, IPT_STANDARD_TARGET, strlen(IPT_STANDARD_TARGET)+1) == 0) {
		struct xt_standard_target *t;

		t = (struct xt_standard_target *)target;

		switch (t->verdict) {
		case XT_RETURN:
			_D("\ttarget RETURN");
			break;

		case -NF_ACCEPT - 1:
			_D("\ttarget ACCEPT");
			break;

		case -NF_DROP - 1:
			_D("\ttarget DROP");
			break;

		case -NF_QUEUE - 1:
			_D("\ttarget QUEUE");
			break;

		case -NF_STOP - 1:
			_D("\ttarget STOP");
			break;

		default:
			_D("\tJUMP %u", t->verdict);
			break;
		}
	}
}

static resourced_cb_ret dump_entry(struct resourced_ipt_entry_info *info, void *user_data)
{
	struct xt_entry_target *target = ipt_get_target(info->entry);

	_D("entry %p next_offset %d ", info->entry,
			info->entry->next_offset);

	if (!strncmp(target->u.user.name, IPT_ERROR_TARGET, strlen(IPT_ERROR_TARGET)+1)) {
		_D("\tUSER CHAIN (%s) match %p  target %p",
			target->data, info->entry->elems,
			(char *)info->entry + info->entry->target_offset);

		return 0;
	} else if (info->builtin) {
		_D("\tCHAIN (%s) match %p  target %p",
			info->chain_name, info->entry->elems,
			(char *)info->entry + info->entry->target_offset);
	} else {
		_D("\tRULE  match %p  target %p",
			info->entry->elems,
			(char *)info->entry + info->entry->target_offset);
	}

	dump_match(info->entry);
	dump_target(info->entry);
	dump_ip(info->entry);

	return RESOURCED_CONTINUE;
}

API resourced_ret_c resourced_ipt_dump(struct ipt_context *iptc)
{
	return ipt_foreach(iptc, dump_entry, NULL);
}

#endif /* NETWORK_DEBUG_ENABLED */

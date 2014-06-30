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
 * @file generic-netlink.c
 *
 * @desc User space code for ktgrabber logic
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 */

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

#define NESTED_MCAST_MAX       256
#define MAX_PAYLOAD 1024	/* maximum payload size */

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 */
#define GENLMSG_DATA(glh) ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na) ((void *)((char*)(na) + NLA_HDRLEN))

/**
 * @desc accepts opaque pointer
 * extracts command id
 */
inline int netlink_get_command(struct genl *nl_ans)
{
	return nl_ans->g.cmd;
}

uint32_t netlink_get_family(struct genl *nl_ans)
{
	return nl_ans->n.nlmsg_type;
}

static void fill_traf_stat_list(char *buffer, __u16 count,
			traffic_stat_tree *stats)
{
	struct traffic_event *cur = (struct traffic_event *)buffer;

	while (count) {
		struct traffic_stat *to_insert;
		struct classid_iftype_key *key;

		to_insert = g_new(struct traffic_stat, 1);
		if (!to_insert) {
			_D("Can't allocate %d bytes for traffic_stat\n", sizeof(struct traffic_stat));
			return;
		}

		key = g_new(struct classid_iftype_key, 1);

		if (!key) {
			_D("Can't allocate %d bytes for classid_iftype_key\n", sizeof(struct classid_iftype_key));
			g_free((gpointer)to_insert);
			return;
		}

		to_insert->bytes = cur->bytes;
		to_insert->ifindex = cur->ifindex;
		key->classid = cur->sk_classid ?
			cur->sk_classid : RSML_UNKNOWN_CLASSID;
		key->iftype = get_iftype(cur->ifindex);
		g_tree_insert((GTree *) stats, (gpointer)key, to_insert);
		--count;
		++cur;
	}
}

/**
 * create_netlink(): Create netlink socket and returns it.
 * Returns: Created socket on success and -1 on failure.
 */
int create_netlink(int protocol, uint32_t groups)
{
	/**
	* TODO it's one socket, in future make set of sockets
	* unique for protocol and groups
	*/
	int sock;
	sock = socket(PF_NETLINK, SOCK_RAW, protocol);
	if (sock < 0)
		return -EINVAL;

	struct sockaddr_nl src_addr = { 0, };

	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_groups = groups;

	if (bind(sock, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

/*
 * Send netlink message to kernel
 */
static int send_message(int fd, const char *message, int msg_len)
{
	struct sockaddr_nl nl_addr;
	int ret = 0;

	memset(&nl_addr, 0, sizeof(nl_addr));
	nl_addr.nl_family = AF_NETLINK;

	while ((ret =
		sendto(fd, message, msg_len, 0, (struct sockaddr *)&nl_addr,
		       sizeof(nl_addr))) < msg_len) {
		if (ret <= 0 && errno != EAGAIN)
			return ret;
		else if (errno == EAGAIN)
			continue;

		message += ret;
		msg_len -= ret;
	}
	return 0;
}

/*
 * Probe the controller in genetlink to find the family id
 * for the TRAF_STAT family
 */

uint32_t get_family_id(int sock, pid_t pid,
	char *family_name)
{
	uint32_t family_id = 0;
	uint32_t UNUSED group_id = get_family_group_id(sock, pid, family_name, NULL,
		&family_id);
	return family_id;
}

static void fill_attribute_list(struct rtattr **atb, const int max_len,
	struct rtattr *rt_na, int rt_len)
{
	int i = 0;
	while (RTA_OK(rt_na, rt_len)) {
		if (rt_na->rta_type <= max_len)
			atb[rt_na->rta_type] = rt_na;

		rt_na = RTA_NEXT(rt_na, rt_len);
		++i;
		if (i >= max_len)
			break;
	}
}

static int extract_group_id(const struct rtattr *rt_na, const char *group_name,
	uint32_t *group_id)
{
	struct rtattr *multicast_group_family[__CTRL_ATTR_MCAST_GRP_MAX] = {0};
	char *name;
	struct rtattr *rt_nested;
	int rt_len;

	if (!rt_na)
		return -EINVAL;

	rt_nested = RTA_DATA(rt_na); /* nested */
	rt_len = RTA_PAYLOAD(rt_na);

	fill_attribute_list(multicast_group_family,
		CTRL_ATTR_MCAST_GRP_MAX, rt_nested, rt_len);

	if (!multicast_group_family[CTRL_ATTR_MCAST_GRP_NAME] ||
	    !multicast_group_family[CTRL_ATTR_MCAST_GRP_ID])
		return -EINVAL;

	name = RTA_DATA(multicast_group_family[CTRL_ATTR_MCAST_GRP_NAME]);

	if (strcmp(name, group_name))
		return -EINVAL;

	*group_id = *((__u32 *)RTA_DATA(
		multicast_group_family[CTRL_ATTR_MCAST_GRP_ID]));
	return RESOURCED_ERROR_NONE;
}


/*
 * check subattribute CTRL_ATTR_MCAST_GROUPS
 * if it exists we are dealing with broadcast generic
 * netlink message
 * message format is following
 * CTRL_ATTR_MCAST_GROUPS
 *  ATTR1
 *    CTRL_ATTR_MCAST_GRP_NAME
 *    CTRL_ATTR_MCAST_GRP_ID
 *  ATTR2
 *    CTRL_ATTR_MCAST_GRP_NAME
 *    CTRL_ATTR_MCAST_GRP_ID
 *  ...
 */
static uint32_t get_mcast_group_id(struct rtattr *mc_na, const char *group_name)
{
	struct rtattr *rt_na = RTA_DATA(mc_na); /* nested */
	int rt_len = RTA_PAYLOAD(mc_na);
	int i, ret;
	uint32_t group_id;

	struct rtattr *multicast_general_family[NESTED_MCAST_MAX + 1] = {0};

	fill_attribute_list(multicast_general_family, NESTED_MCAST_MAX,
		            rt_na, rt_len);

	/* for each group */
	for (i = 0; i < NESTED_MCAST_MAX; ++i) {
		/* if this group is valid */
		if (!multicast_general_family[i])
			continue;

		ret = extract_group_id(multicast_general_family[i], group_name,
			&group_id);
		if (ret == RESOURCED_ERROR_NONE)
			return group_id;
	}

	return 0;
}

uint32_t get_family_group_id(int sock, pid_t pid,
	                char *family_name, char *group_name,
			uint32_t *family_id)
{
	struct genl family_req;
	struct genl ans;

	struct nlattr *na = 0;
	int rep_len = 0, ret;
	struct rtattr *general_family[__CTRL_ATTR_MAX] = {0};
	struct rtattr *rt_na;
	static uint32_t seq;

	ret_value_msg_if(sock < 0, 0, "Please provide valid socket!");

	family_req.n.nlmsg_type = GENL_ID_CTRL;
	family_req.n.nlmsg_flags = NLM_F_REQUEST;
	family_req.n.nlmsg_seq = seq++;
	family_req.n.nlmsg_pid = pid;
	family_req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	family_req.g.cmd = CTRL_CMD_GETFAMILY;

	na = (struct nlattr *)GENLMSG_DATA(&family_req);
	na->nla_type = CTRL_ATTR_FAMILY_NAME;

	na->nla_len = strlen(family_name) + 1 + NLA_HDRLEN;
	strcpy(NLA_DATA(na), family_name);

	family_req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	ret = send_message(sock, (char *)&family_req, family_req.n.nlmsg_len);

	ret_value_msg_if(ret < 0, 0, "Failed to send GETFAMILY command");

	rep_len = recv(sock, &ans, sizeof(ans), 0);

	ret_value_msg_if(rep_len < 0, 0,
		"Failed to receive answer for GETFAMILY command");

	/* Validate response message */
	if (!NLMSG_OK((&ans.n), rep_len)) {
		_E("Invalid reply message\n");
		return 0;
	}

	ret_value_msg_if(ans.n.nlmsg_type == NLMSG_ERROR, 0,
		"Invalid netlink message format");

	rt_na = (struct rtattr *)GENLMSG_DATA(&ans);

	fill_attribute_list(general_family, CTRL_ATTR_MAX, rt_na, rep_len);

	/* family id for netlink is 16 bits long for multicast is 32 bit */
	if (general_family[CTRL_ATTR_FAMILY_ID])
		*family_id = *(__u16 *)RTA_DATA(
			general_family[CTRL_ATTR_FAMILY_ID]);

	/* group name wasn't requested */
	if (!group_name)
		return 0;

	if (!general_family[CTRL_ATTR_MCAST_GROUPS])
		return 0;

	return get_mcast_group_id(general_family[CTRL_ATTR_MCAST_GROUPS],
		group_name);
}

#ifdef DEBUG_ENABLED
static void show_result(const struct genl *ans)
{
	/*parse reply message */
	struct nlattr *na = NULL;
	char *result = NULL;

	if (!ans) {
		_D ("Please provide valid argument!");
		return;
	}

	na = (struct nlattr *)GENLMSG_DATA(ans);
	result = (char *)NLA_DATA(na);
	if (result)
		_D("Initialization result: %s\n", result);
	else
		_D("Failed to show initialization result!");
}
#else /* Release build */
static void show_result(const struct genl *ans)
{
}
#endif

static resourced_ret_c send_common_cmd(int sock, const pid_t pid,
	const uint32_t family_id, const __u8 cmd)
{
	struct genl ans;
	int r;

	ret_value_msg_if(sock < 0, RESOURCED_ERROR_NONE,
		"Please provide valid socket!");

	r = send_command(sock, pid, family_id, cmd);

	ret_value_errno_msg_if(r < 0, RESOURCED_ERROR_FAIL,
		"Failed to send command");

	/* Read message from kernel */
	r = recv(sock, &ans, sizeof(ans), MSG_DONTWAIT);

	ret_value_errno_msg_if(r < 0, RESOURCED_ERROR_FAIL,
		"Cant receive message from kernel");

	ret_value_msg_if(ans.n.nlmsg_type == NLMSG_ERROR, RESOURCED_ERROR_FAIL,
		"Netlink format error");

	ret_value_msg_if(!NLMSG_OK((&ans.n), r), RESOURCED_ERROR_FAIL,
		"Invalid reply message received via Netlink");

	show_result(&ans);
	return RESOURCED_ERROR_NONE;
}


resourced_ret_c start_net_activity(void)
{
    return 0;
}

resourced_ret_c stop_net_activity(void)
{
    return 0;
}


void send_start(int sock, const pid_t pid, const int family_id)
{
	send_common_cmd(sock, pid, family_id, TRAF_STAT_C_START);
}

/* read netlink message from socket
 * return opaque pointer to genl structure */
struct genl *netlink_read(int sock)
{
	struct genl *ans;
	int ans_len;

	ans = (typeof(ans)) malloc(sizeof(*ans));
	if (ans == NULL)
		return NULL;

	ans_len = recv(sock, ans, sizeof(*ans), MSG_DONTWAIT);
	if (ans_len < 0)
		goto error;

	if (ans->n.nlmsg_type == NLMSG_ERROR)
		goto error;

	if (!NLMSG_OK((&ans->n), ans_len))
		goto error;

	return ans;

error:
	free(ans);
	return NULL;
}

void process_netlink_answer(struct genl *nl_ans, traffic_stat_tree *stats)
{
	ssize_t remains;
	char *buffer;
	struct nlattr *first_na, *second_na;
	int first_len;
	int count = 0;

	remains = GENLMSG_PAYLOAD(&nl_ans->n);
	if (remains <= 0)
		return;

	/* parse reply message */
	first_na = (struct nlattr *)GENLMSG_DATA(nl_ans);

	/* inline nla_next() */
	first_len = NLA_ALIGN(first_na->nla_len);

	second_na = (struct nlattr *) ((char *) first_na + first_len);
	remains -= first_len;

	/* but we need data_attr->nla_len */
	buffer = (char *) malloc((size_t)remains);
	if (buffer == NULL)
		return;

	if (first_na->nla_type == TRAF_STAT_COUNT) {
		count = *(__u16 *) NLA_DATA(first_na);
		memcpy(buffer, (char *) NLA_DATA(second_na),
		       second_na->nla_len);
	} else {
		_D("Expected attribute %d got %d", TRAF_STAT_COUNT, first_na->nla_type);
	}

	if (count > 0)
		fill_traf_stat_list(buffer, count, stats);
	free(buffer);
}

int send_command(int sock, const pid_t pid, const int family_id, __u8 cmd)
{
	struct genl req;
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	const char *message = "INIT";
	const int mlength = sizeof(message) + 1;

	ret_value_msg_if(sock < 0, RESOURCED_ERROR_NONE,
		"Please provide valid socket!");

	/* Send command needed */
	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type = family_id;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_seq = 60;
	req.n.nlmsg_pid = pid;
	req.g.cmd = cmd;

	/* compose message */
	na = (struct nlattr *)GENLMSG_DATA(&req);
	na->nla_type = 1;
	na->nla_len = mlength + NLA_HDRLEN;	/* message length */
	memcpy(NLA_DATA(na), message, mlength);
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* send message */
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	return sendto(sock, (char *)&req, req.n.nlmsg_len, 0,
		      (struct sockaddr *)&nladdr, sizeof(nladdr));
}

int send_restriction(int sock, const pid_t pid, const int family_id,
		 const u_int32_t classid, const int ifindex,
		 const enum traffic_restriction_type restriction_type,
		 const int send_limit, const int rcv_limit,
		 const int snd_warning_threshold, const int rcv_warning_threshold)
{
	struct genl req;
	struct traffic_restriction rst = {
		.sk_classid = classid,
		.type = restriction_type,
		.ifindex = ifindex,
		.send_limit = send_limit,
		.rcv_limit = rcv_limit,
		.snd_warning_threshold = snd_warning_threshold,
		.rcv_warning_threshold = rcv_warning_threshold,
	};

	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int mlength = 0, r = 0;

	if (sock < 0) {
		_D("Can't use socket\n");
		return -1;
	}

	/* Send command needed */
	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type = family_id;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_seq = 60;
	req.n.nlmsg_pid = pid;
	req.g.cmd = TRAF_STAT_C_SET_RESTRICTIONS;

	/*compose message */
	na = (struct nlattr *)GENLMSG_DATA(&req);
	na->nla_type = TRAF_STAT_DATA_RESTRICTION;
	mlength = sizeof(struct traffic_restriction);	/* * classid_count; */
	na->nla_len = mlength + NLA_HDRLEN;

	memcpy(NLA_DATA(na), &rst, sizeof(struct traffic_restriction));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/*send message */

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	/*use send_message */
	r = sendto(sock, (char *)&req, req.n.nlmsg_len, 0,
		   (struct sockaddr *)&nladdr, sizeof(nladdr));
	_D("Restriction send to kernel, result: %d", r);
	return r;
}

static void _process_answer(struct netlink_serialization_params *params)
{
	process_netlink_answer(params->ans, params->stat_tree);
}

netlink_serialization_command *netlink_create_command(struct genl *ans,
	struct counter_arg *carg)
{
	static netlink_serialization_command command = {0,};
	const int netlink_command = netlink_get_command(ans);

	if (netlink_command == TRAF_STAT_C_GET_CONN_IN) {
		command.deserialize_answer = _process_answer;
		command.params.stat_tree = carg->in_tree;
	} else if (netlink_command == TRAF_STAT_C_GET_PID_OUT) {
		command.deserialize_answer = _process_answer;
		command.params.stat_tree = carg->out_tree;
	} else {
		_E("Unknown command!");
		return NULL;
	}

	command.params.ans = ans;
	return &command;
}

resourced_ret_c process_netlink_restriction_msg(const struct genl *ans,
	struct traffic_restriction *restriction, uint8_t *command)
{
	struct rtattr *na;
	struct rtattr *attr_list[__RESTRICTION_NOTI_A_MAX] = {0};

	int len = GENLMSG_PAYLOAD(&ans->n);

	if (!restriction || !command)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	if (len <= 0)
		return RESOURCED_ERROR_INVALID_PARAMETER;

	*command = ans->g.cmd;

	/* parse reply message */
	na = (struct rtattr *)GENLMSG_DATA(ans);

	fill_attribute_list(attr_list, __RESTRICTION_NOTI_A_MAX - 1,
		na, len);

	ret_value_msg_if(!attr_list[RESTRICTION_A_CLASSID], RESOURCED_ERROR_FAIL,
		"Restriction netlink message doesn't contain mandatory classid.");

	restriction->sk_classid = *(uint32_t *)RTA_DATA(
			attr_list[RESTRICTION_A_CLASSID]);

	if (attr_list[RESTRICTION_A_IFINDEX])
		restriction->ifindex = *(int *)RTA_DATA(
			attr_list[RESTRICTION_A_IFINDEX]);

	return RESOURCED_ERROR_NONE;
}

enum net_activity_recv recv_net_activity(int sock, struct net_activity_info
	*activity_info, const uint32_t net_activity_family_id)
{
	int ans_len, traffic_type;
	struct traffic_event *event;
	struct nlattr *na = 0;
	struct genl ans;
	uint32_t family_id;

	ans_len = recv(sock, &ans, sizeof(ans),
			MSG_DONTWAIT);

	if (ans_len <= 0 || !NLMSG_OK((&ans.n), ans_len)) {
		ETRACE_ERRNO_MSG("Failed to read netlink socket %d",
			ans_len);
		return RESOURCED_NET_ACTIVITY_STOP;
	}

	_D("Reading multicast netlink message len %d", ans_len);

	family_id = netlink_get_family(&ans);

	if (family_id != net_activity_family_id) {
		_D("Received family_id %d", family_id);
		return RESOURCED_NET_ACTIVITY_CONTINUE;
	}

	na = (struct nlattr *)GENLMSG_DATA(&ans);

	traffic_type = na->nla_type;

	event = (struct traffic_event *) NLA_DATA(na);
	activity_info->type = traffic_type;
	activity_info->bytes = event->bytes;
	activity_info->iftype = get_iftype(event->ifindex);
	activity_info->appid = get_app_id_by_classid(event->sk_classid, true);

	return RESOURCED_NET_ACTIVITY_OK;
}

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
 *
 * @file iface.c
 *
 * @desc Utility for working with network interfaces
 */


#include <errno.h>
#include <glib.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iface.h"
#include "macro.h"
#include "trace.h"

static int iface_stat[RESOURCED_IFACE_LAST_ELEM - 1];
static GTree *iftypes; /* holds int key and value of type resourced_iface_type */

static pthread_rwlock_t iftypes_guard = PTHREAD_RWLOCK_INITIALIZER;

static const char *UEVENT_FMT = "/sys/class/net/%s/uevent";
static const char *DEVTYPE_KEY = "DEVTYPE";
static const char *WIRED_VALUE = "gadget";
static const char *WIFI_VALUE = "wlan";
static const char *BLUETOOTH_VALUE = "bluetooth";
static const char *DATACALL_VALUE = "datacall";
static const char *ALL_NET_IFACE_VALUE = "all";
static const char *UEVENT_DELIM = "=\n";

static const char *RMNET_DEVNAME = "rmnet";
static const char *PDP_DEVNAME = "pdp";

static gint compare_ifindex(gconstpointer a, gconstpointer b,
	gpointer UNUSED userdata)
{
	if (a == b)
		return 0;
	else if (a > b)
		return 1;
	return -1;
}

static GTree *create_iftypes_tree(void)
{
	return g_tree_new_full(compare_ifindex,
		NULL, NULL, free);
}

static void set_tree_value(GTree *iftypes_tree, int ifindex, int iftype)
{
	gpointer new_value;

	ret_value_msg_if(!iftypes_tree, , "Please provide valid argument!");
	new_value = (gpointer)malloc(sizeof(int));
	*(int *)new_value = iftype;
	g_tree_replace(iftypes_tree, (gpointer)ifindex, new_value);
}

static resourced_iface_type get_iftype_tree(GTree *iftypes_tree, int ifindex)
{
	resourced_iface_type ret = RESOURCED_IFACE_UNKNOWN;
	gpointer table_value;

	if (!iftypes_tree) {
		_E("Please provide valid argument!");
		return ret;
	}

	pthread_rwlock_rdlock(&iftypes_guard);
	table_value = g_tree_lookup(iftypes_tree, (gpointer)ifindex);
	pthread_rwlock_unlock(&iftypes_guard);
	if (table_value != NULL)
		ret = *(int *)table_value;

	return ret;
}

static void free_iftypes_tree(GTree *iftypes_tree)
{
	g_tree_destroy(iftypes_tree);
}

static void iface_stat_allowance(void)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(iface_stat); ++i)
		iface_stat[i] = 1;
}

static resourced_iface_type read_iftype(const char *iface)
{
	char buffer[UNIX_PATH_MAX];
	char *key_buffer;
	char *value_buffer;
	FILE *uevent;
	resourced_iface_type ret = RESOURCED_IFACE_UNKNOWN;

	snprintf(buffer, UNIX_PATH_MAX, UEVENT_FMT, iface);
	uevent = fopen(buffer, "r");

	if (!uevent)
		return ret;

	while (!feof(uevent)) {
		if (fgets(buffer, UNIX_PATH_MAX, uevent) == NULL)
			break;
		key_buffer = strtok(buffer, UEVENT_DELIM);
		value_buffer = strtok(NULL, UEVENT_DELIM);
		if (strcmp(key_buffer, DEVTYPE_KEY) != 0)
			continue;
		ret = convert_iftype(value_buffer);
		break;
	}

	fclose(uevent);

	/* work around, in case of missing DEVTYPE field */
	if (ret == RESOURCED_IFACE_UNKNOWN &&
	    (strstr(iface, RMNET_DEVNAME) || strstr(iface, PDP_DEVNAME)))
		ret = RESOURCED_IFACE_DATACALL;

	return ret;
}

static void set_new_iftypes(GTree *iftypes_new)
{
	GTree *iftypes_free = iftypes;

	pthread_rwlock_wrlock(&iftypes_guard);
	iftypes = iftypes_new;
	pthread_rwlock_unlock(&iftypes_guard);
	if (iftypes_free)
		free_iftypes_tree(iftypes_free);
}

int init_iftype(void)
{
	int i;
	resourced_iface_type iftype;
	struct if_nameindex *ids = if_nameindex();
	GTree *iftypes_next = create_iftypes_tree();

	if (ids == NULL) {
		_E("Failed to initialize iftype table! errno: %d, %s",
			errno, strerror(errno));
		return RESOURCED_ERROR_FAIL;
	}

	iface_stat_allowance();

	for (i = 0; ids[i].if_index != 0; ++i) {
		iftype = read_iftype(ids[i].if_name);
		set_tree_value(iftypes_next, ids[i].if_index, iftype);
	}

	/* Do not forget to free the memory */
	if_freenameindex(ids);

	set_new_iftypes(iftypes_next);
	return RESOURCED_ERROR_NONE;
}

void finalize_iftypes(void)
{
	set_new_iftypes(NULL);
}

resourced_iface_type convert_iftype(const char *buffer)
{
	if (strcmp(buffer, DATACALL_VALUE) == 0)
		return RESOURCED_IFACE_DATACALL;

	if (strcmp(buffer, WIFI_VALUE) == 0)
		return RESOURCED_IFACE_WIFI;

	if (strcmp(buffer, BLUETOOTH_VALUE) == 0)
		return RESOURCED_IFACE_BLUETOOTH;

	if (strcmp(buffer, WIRED_VALUE) == 0)
		return RESOURCED_IFACE_WIRED;
	if (strcmp(buffer, ALL_NET_IFACE_VALUE) == 0)
		return RESOURCED_IFACE_ALL;
	return RESOURCED_IFACE_UNKNOWN;
}

int is_allowed_ifindex(int ifindex)
{
	return iface_stat[get_iftype(ifindex)];
}

resourced_iface_type get_iftype(int ifindex)
{
	return get_iftype_tree(iftypes, ifindex);
}

void for_each_ifindex(ifindex_iterator iter, void *data)
{
	pthread_rwlock_rdlock(&iftypes_guard);
	g_tree_foreach(iftypes, (GTraverseFunc)iter, data);
	pthread_rwlock_unlock(&iftypes_guard);
}

void set_wifi_allowance(const resourced_option_state wifi_option)
{
	iface_stat[RESOURCED_IFACE_WIFI] = wifi_option == RESOURCED_OPTION_ENABLE ? 1 : 0;
}

void set_datacall_allowance(const resourced_option_state datacall_option)
{
	iface_stat[RESOURCED_IFACE_DATACALL] = datacall_option == RESOURCED_OPTION_ENABLE ? 1 : 0;
}

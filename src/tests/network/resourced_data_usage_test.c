/*
   Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License
*/

/* @author: Prajwal A N
 * @file: data-usage.c
 * @desc: Tests for data-usage APIs in resourced
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <data_usage.h>

#include "resourced_tests.h"

struct data_usage_test_t {
	char name[STRING_MAX];
	int (*test_func)(void);
};

int data_usage_test_set_resourced_options()
{
	return set_resourced_options(NULL);
}

int data_usage_test_get_resourced_options()
{
	return get_resourced_options(NULL);
}
 
int data_usage_test_set_net_restriction()
{
	return set_net_restriction(NULL, NULL);
}

int data_usage_test_restrictions_foreach()
{
	return restrictions_foreach(NULL, NULL);
}

int data_usage_test_remove_restriction()
{
	return remove_restriction(NULL);
}

int data_usage_test_exclude_restriction()
{
	return exclude_restriction(NULL);
}

int data_usage_test_exclude_restriction_by_iftype()
{
	return exclude_restriction_by_iftype(NULL, 0);
}

int data_usage_test_set_net_exclusion()
{
	return set_net_exclusion(NULL, NULL);
}

int data_usage_test_register_net_activity_cb()
{
	return register_net_activity_cb(NULL);
}

int data_usage_test_resourced_update_statistics()
{
	return resourced_update_statistics();
}

int data_usage_test_data_usage_foreach()
{
	return data_usage_foreach(NULL, NULL, NULL);
}

int data_usage_test_data_usage_details_foreach()
{
	return data_usage_details_foreach(NULL, NULL, NULL, NULL);
}

int data_usage_test_reset_data_usage()
{
	return reset_data_usage(NULL);
}

int data_usage_test_remove_datausage_quota()
{
	return remove_datausage_quota(NULL);
}

int data_usage_test_remove_datausage_quota_by_iftype()
{
	return remove_datausage_quota_by_iftype(NULL, 0);
}

int data_usage_test_set_datausage_quota()
{
	return set_datausage_quota(NULL, NULL);
}

int data_usage_test_get_restriction_state()
{
	return get_restriction_state(NULL, 0, NULL);
}

int data_usage_test_remove_restriction_by_iftype()
{
	return remove_restriction_by_iftype(NULL, 0);
}

int data_usage_test_remove_restriction_full()
{
	return remove_restriction_full(NULL, NULL);
}

int data_usage_test_resourced_remove_restriction()
{
	return resourced_remove_restriction(NULL, NULL);
}

int data_usage_test_resourced_remove_restriction_by_iftype()
{
	return resourced_remove_restriction_by_iftype(NULL, 0, NULL);
}

static struct data_usage_test_t data_usage_tests[] = {
	{ "set_resourced_options", data_usage_test_set_resourced_options },
	{ "get_resourced_options", data_usage_test_get_resourced_options },
	{ "set_net_restriction", data_usage_test_set_net_restriction },
	{ "restrictions_foreach", data_usage_test_restrictions_foreach },
	{ "remove_restriction", data_usage_test_remove_restriction },
	{ "exclude_restriction", data_usage_test_exclude_restriction },
	{ "exclude_restriction_by_iftype", data_usage_test_exclude_restriction_by_iftype },
	{ "set_net_exclusion", data_usage_test_set_net_exclusion },
	{ "register_net_activity_cb", data_usage_test_register_net_activity_cb },
	{ "resourced_update_statistics", data_usage_test_resourced_update_statistics },
	{ "data_usage_foreach", data_usage_test_data_usage_foreach },
	{ "data_usage_details_foreach", data_usage_test_data_usage_details_foreach },
	{ "reset_data_usage", data_usage_test_reset_data_usage },
	{ "remove_datausage_quota", data_usage_test_remove_datausage_quota },
	{ "remove_datausage_quota_by_iftype", data_usage_test_remove_datausage_quota_by_iftype },
	{ "set_datausage_quota", data_usage_test_set_datausage_quota },
	{ "get_restriction_state", data_usage_test_get_restriction_state },
	{ "remove_restriction_by_iftype", data_usage_test_remove_restriction_by_iftype },
	{ "remove_restriction_full", data_usage_test_remove_restriction_full },
	{ "resourced_remove_restriction", data_usage_test_resourced_remove_restriction },
	{ "resourced_restriction_by_iftype", data_usage_test_resourced_remove_restriction_by_iftype },
	{ "", NULL }
};

int main(int argc, char *argv[])
{
	int i, ret;
	char buf[STRING_MAX];

	printf("Testing data-usage library. Current pid: %d\n", getpid());
	printf("Start journalctl and enter input:");
	ret = scanf("%s\n", buf);

	i = 0;
	while(data_usage_tests[i].test_func) {
		_D("=======================================");
		_D("Current Test: %s", data_usage_tests[i].name);
		ret = (*data_usage_tests[i].test_func)();
		if (ret)
			_E("Test %s failed!", data_usage_tests[i].name);
		else
			_D("Test %s passed!", data_usage_tests[i].name);
		i++;
	}
	return 0;
}

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
 *
 */

/**
 * @file proc-main.h
 * @desc intialize and start pthread for lowmem handler
 **/

#ifndef __PROC_MAIN_H__
#define __PROC_MAIN_H__

#include <unistd.h>
#include <glib.h>

#include "daemon-options.h"
#include "resourced.h"
#include "const.h"
#include "memcontrol.h"

#define PROC_BUF_MAX 64
#define PROC_NAME_MAX 1024

typedef GSList *pid_info_list;

enum application_type {
	PROC_TYPE_UNKNOWN,
	PROC_TYPE_GUI,
	PROC_TYPE_SERVICE,
	PROC_TYPE_GROUP,
};

struct pid_info_t {
	pid_t pid;
	enum application_type type; /* not so fancy */
};

struct proc_process_info_t {
	char appid[MAX_PATH_LENGTH];
	char pkgname[MAX_PATH_LENGTH];
	pid_t main_pid;
	pid_info_list pids;
	int proc_exclude;
	int runtime_exclude;
	int memcg_idx;
	struct memcg_info_t *memcg_info;
	int type;
};

struct proc_status {
	pid_t pid;
	char* appid;
	struct proc_process_info_t *ppi;
};

enum proc_exclude_type {
	PROC_EXCLUDE,
	PROC_INCLUDE,
};

enum {
	LCD_STATE_ON,
	LCD_STATE_OFF,
};

enum proc_prelaunch_flags {
	PROC_NONE	= 0x00u,
	PROC_LARGEMEMORY	= 0x01u,	/* for mark large memory */
	PROC_SIGTERM	= 0x02u,	/* for make killer kill victim by SIGTERM */
	PROC_WEBAPP	= 0x04u,	/* for checking webapp */
};

extern int current_lcd_state;
extern GSList *proc_process_list;


void proc_add_pid_list(struct proc_process_info_t *ppi, int pid, enum application_type type);

int resourced_proc_init(const struct daemon_opts *opts);

/**
 * @desc This function handle PROC_ typs @see
 */
int resourced_proc_action(int type, int argnum, char **arg);

int resourced_proc_excluded(const char *app_name);

int resourced_proc_status_change(int type, pid_t pid, char* app_name,  char* pkg_name);

void resourced_proc_dump(int type, const char *path);

struct proc_process_info_t *find_process_info(const char *appid, const pid_t pid, const char *pkgid);

struct pid_info_t *new_pid_info(const pid_t pid, const int type);

void proc_set_process_info_memcg(struct proc_process_info_t *ppi,
	int memcg_idx, struct memcg_info_t *memcg_info);
resourced_ret_c proc_set_runtime_exclude_list(const int pid, int type);
struct proc_process_info_t *proc_add_process_list(const int type, const pid_t pid, const char *appid, const char *pkgid);
struct proc_process_info_t * proc_create_process_list(const char *appid, const char *pkgid);
int proc_remove_process_list(const pid_t pid);
void proc_set_apptype(const char *appid, const char *pkgid, int type);
int proc_get_apptype(const pid_t pid);

#endif /*__PROC_MAIN_H__ */

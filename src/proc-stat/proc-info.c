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

/*
 * @file proc_info.c
 * @desc It's main thread to get system & process information
 *       to provide runtime api
*/

#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <pthread.h>

#include <Ecore.h>

#include "macro.h"
#include "proc-main.h"
#include "proc-info.h"
#include "proc-process.h"
#include "proc-noti.h"
#include "resourced.h"
#include "module.h"
#include "trace.h"

#define MAX_CONNECTION 5

static pthread_t proc_info_thread;

static void *resourced_proc_info_func(void *data)
{
	struct sockaddr_un client_address;
	struct resourced_noti *msg;
	char *send_buffer = NULL;
	int ret, send_len = 0;
	int server_fd, client_fd, client_len;
	pid_t pid;
	struct timeval tv = { 1, 0 };	/* 1 sec */

	if (!data) {
		_E("data is NULL");
		return NULL;
	}

	server_fd = (int)data;

	client_len = sizeof(client_address);

	if (listen(server_fd, MAX_CONNECTION) < 0) {
		_E("Failed to listen socket");
		close(server_fd);
		return NULL;
	}

	while (1) {
		client_fd =
			accept(server_fd, (struct sockaddr *)&client_address,
					(socklen_t *)&client_len);
		if (client_fd < 0) {
			_E("Failed to accept");
			continue;
		}
		msg = calloc(1, sizeof(struct resourced_noti));
		if (msg == NULL) {
			_E("proc_noti_cb : Not enough memory");
			goto end;
		}
		ret = setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		if (ret)
			_E("failed to set socket option");
		ret = read_message(client_fd, msg);
		if (ret)
			goto end;
		if (msg->argc > NOTI_MAXARG || msg->type < PROC_CGROUP_GET_CMDLINE) {
			_E("%s : error argument", __func__);
			goto end;
		}

		pid = atoi(msg->argv[0]);
		send_len = atoi(msg->argv[1]);
		send_buffer = calloc(1, send_len);
		if (send_buffer == NULL) {
			_E("Not enough memory");
			goto end;
		}
		ret = proc_get_state(msg->type, pid, send_buffer, send_len);
end:
		write_response(&ret, client_fd, send_buffer, send_len);
		free_message(msg);
		close(client_fd);
		if (send_buffer) {
			free(send_buffer);
			send_buffer = NULL;
		}
		ret = 0;
		send_len = 0;
	}

	return NULL;
}

static int proc_info_socket_init(void)
{
	int fd;
	struct sockaddr_un serveraddr;

	if (access(RESOURCED_PROC_INFO_SOCKET_PATH, F_OK) == 0)
		unlink(RESOURCED_PROC_INFO_SOCKET_PATH);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		_E("Failed to create socket");
		return -1;
	}

	if ((fsetxattr(fd, "security.SMACK64IPOUT", "@", 2, 0)) < 0) {
		_E("Failed to set Socket SMACK label");
		if (errno != EOPNOTSUPP) {
			close(fd);
			return -1;
		}
	}

	if ((fsetxattr(fd, "security.SMACK64IPIN", "*", 2, 0)) < 0) {
		_E("Failed to set Socket SMACK label");
		if (errno != EOPNOTSUPP) {
			close(fd);
			return -1;
		}
	}

	bzero(&serveraddr, sizeof(struct sockaddr_un));
	serveraddr.sun_family = AF_UNIX;
	strncpy(serveraddr.sun_path, RESOURCED_PROC_INFO_SOCKET_PATH,
			sizeof(serveraddr.sun_path));

	if (bind(fd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr)) < 0) {
		_E("Failed to bind socket");
		close(fd);
		return -1;
	}

	if (chmod(RESOURCED_PROC_INFO_SOCKET_PATH, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
		_E("Failed to change the socket permission");
	_D("socket create ok");
	return fd;
}

static int proc_info_init(void *data)
{
	int fd, ret;

	fd = proc_info_socket_init();
	if (fd < 0) {
		_E("Failed to init socket");
		return -1;
	}
	/* start thread */
	ret = pthread_create(&proc_info_thread, NULL, resourced_proc_info_func,
			(void *)fd);
	if (ret != 0) {
		_E("Failed to create thread");
		return RESOURCED_ERROR_FAIL;
	}

	return RESOURCED_ERROR_NONE;
}

static int proc_info_exit(void *data)
{
	_D("proc info exit!");
	return RESOURCED_ERROR_NONE;
}

static const struct proc_module_ops proc_info_ops = {
	.name           = "PROC_INFO",
	.init           = proc_info_init,
	.exit           = proc_info_exit,
};
PROC_MODULE_REGISTER(&proc_info_ops)

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _VFIO_USER_SERVER_H
#define _VFIO_USER_SERVER_H

#include <sys/epoll.h>

#include "vfio_user_base.h"

struct vfio_user_server {
	int dev_id;
	int started;
	int conn_fd;
	uint32_t msg_id;
	char sock_addr[PATH_MAX];
	struct vfio_user_version ver;
	struct vfio_device_info *dev_info;
	struct rte_vfio_user_regions *reg;
};

typedef int (*event_handler)(int fd, void *data);

typedef struct listen_fd_info {
	int fd;
	uint32_t event;
	event_handler ev_handle;
	void *data;
} FD_INFO;

struct vfio_user_epoll {
	int epfd;
	FD_INFO fdinfo[VFIO_USER_MAX_FD];
	uint32_t fd_num;	/* Current num of listen_fd */
	struct epoll_event events[VFIO_USER_MAX_FD];
	pthread_mutex_t fd_mutex;
};

struct vfio_user_server_socket {
	struct vfio_user_socket sock;
	struct sockaddr_un un;
	/* For vfio-user protocol v0.1, a server only supports one client */
	int conn_fd;
};

struct vfio_user_ep_sock {
	struct vfio_user_epoll ep;
	struct vfio_user_server_socket *sock[VFIO_USER_MAX_FD];
	uint32_t sock_num;
	pthread_mutex_t mutex;
};

typedef int (*vfio_user_msg_handler_t)(struct vfio_user_server *dev,
					struct vfio_user_msg *msg);

#endif

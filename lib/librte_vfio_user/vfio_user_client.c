/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "vfio_user_client.h"
#include "rte_vfio_user.h"

#define REPLY_USEC 1000
#define RECV_MAX_TRY 50

static struct vfio_user_client_devs vfio_client_devs = {
	.cl_num = 0,
	.mutex = PTHREAD_MUTEX_INITIALIZER,
};

/* Check if the sock_addr exists. If not, alloc and return index */
static int
vfio_user_client_allocate(const char *sock_addr)
{
	uint32_t i, count = 0;
	int index = -1;

	if (sock_addr == NULL)
		return -1;

	if (vfio_client_devs.cl_num == 0)
		return 0;

	for (i = 0; i < MAX_VFIO_USER_CLIENT; i++) {
		struct vfio_user_client *cl = vfio_client_devs.cl[i];

		if (!cl) {
			if (index == -1)
				index = i;
			continue;
		}

		if (!strcmp(cl->sock.sock_addr, sock_addr))
			return -1;

		count++;
		if (count == vfio_client_devs.cl_num)
			break;
	}

	return index;
}

static struct vfio_user_client *
vfio_user_client_create_dev(const char *sock_addr)
{
	struct vfio_user_client *cl;
	struct vfio_user_socket *sock;
	int fd, idx;
	struct sockaddr_un un = { 0 };

	pthread_mutex_lock(&vfio_client_devs.mutex);
	if (vfio_client_devs.cl_num == MAX_VFIO_USER_CLIENT) {
		VFIO_USER_LOG(ERR, "Failed to create client:"
			" client num reaches max\n");
		goto err;
	}

	idx = vfio_user_client_allocate(sock_addr);
	if (idx < 0) {
		VFIO_USER_LOG(ERR, "Failed to alloc a slot for client\n");
		goto err;
	}

	cl = malloc(sizeof(*cl));
	if (!cl) {
		VFIO_USER_LOG(ERR, "Failed to alloc client\n");
		goto err;
	}

	sock = &cl->sock;
	sock->sock_addr = strdup(sock_addr);
	if (!sock->sock_addr) {
		VFIO_USER_LOG(ERR, "Failed to copy sock_addr\n");
		goto err_dup;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		VFIO_USER_LOG(ERR, "Client failed to create socket: %s\n",
			strerror(errno));
		goto err_sock;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
		VFIO_USER_LOG(ERR, "Failed to set nonblocking mode for client "
			"socket, fd: %d (%s)\n", fd, strerror(errno));
		goto err_ctl;
	}

	un.sun_family = AF_UNIX;
	strncpy(un.sun_path, sock->sock_addr, sizeof(un.sun_path));
	un.sun_path[sizeof(un.sun_path) - 1] = '\0';

	if (connect(fd, &un, sizeof(un)) < 0) {
		VFIO_USER_LOG(ERR, "Client connect error, %s\n",
			strerror(errno));
		goto err_ctl;
	}

	sock->sock_fd = fd;
	sock->dev_id = idx;
	cl->msg_id = 0;

	vfio_client_devs.cl[idx] = cl;
	vfio_client_devs.cl_num++;

	pthread_mutex_unlock(&vfio_client_devs.mutex);

	return cl;

err_ctl:
	close(fd);
err_sock:
	free(sock->sock_addr);
err_dup:
	free(sock);
err:
	pthread_mutex_unlock(&vfio_client_devs.mutex);
	return NULL;
}

static int
vfio_user_client_destroy_dev(int dev_id)
{
	struct vfio_user_client *cl;
	struct vfio_user_socket *sock;
	int ret = 0;

	pthread_mutex_lock(&vfio_client_devs.mutex);
	if (vfio_client_devs.cl_num == 0) {
		VFIO_USER_LOG(ERR, "Failed to destroy client:"
			" no client exists\n");
		ret = -EINVAL;
		goto err;
	}

	cl = vfio_client_devs.cl[dev_id];
	if (!cl) {
		VFIO_USER_LOG(ERR, "Failed to destroy client:"
			" wrong device ID(%d)\n", dev_id);
		ret = -EINVAL;
		goto err;
	}

	sock = &cl->sock;
	free(sock->sock_addr);
	close(sock->sock_fd);

	free(cl);
	vfio_client_devs.cl[dev_id] = NULL;
	vfio_client_devs.cl_num--;

err:
	pthread_mutex_unlock(&vfio_client_devs.mutex);
	return ret;
}

static inline void
vfio_user_client_fill_hdr(struct vfio_user_msg *msg, uint16_t cmd,
	uint32_t sz, uint16_t msg_id)
{
	msg->msg_id = msg_id;
	msg->cmd = cmd;
	msg->size = sz;
	msg->flags = VFIO_USER_TYPE_CMD;
	msg->err = 0;
}

static int
vfio_user_client_send_recv(int sock_fd, struct vfio_user_msg *msg)
{
	uint16_t cmd = msg->cmd;
	uint16_t id = msg->msg_id;
	uint8_t try_recv = 0;
	int ret;

	ret = vfio_user_send_msg(sock_fd, msg);
	if (ret < 0) {
		VFIO_USER_LOG(ERR, "Send error for %s\n",
			vfio_user_msg_str[cmd]);
		return -1;
	}

	VFIO_USER_LOG(INFO, "Send request %s\n", vfio_user_msg_str[cmd]);

	memset(msg, 0, sizeof(*msg));

	while (try_recv < RECV_MAX_TRY) {
		ret = vfio_user_recv_msg(sock_fd, msg);
		if (!ret) {
			VFIO_USER_LOG(ERR, "Peer closed\n");
			return -1;
		} else if (ret > 0) {
			if (id != msg->msg_id)
				continue;
			else
				break;
		}
		usleep(REPLY_USEC);
		try_recv++;
	}

	if (cmd != msg->cmd) {
		VFIO_USER_LOG(ERR, "Request and reply mismatch\n");
		ret = -1;
	} else
		ret = 0;

	VFIO_USER_LOG(INFO, "Recv reply %s\n", vfio_user_msg_str[cmd]);

	return ret;
}

int
rte_vfio_user_attach_dev(const char *sock_addr)
{
	struct vfio_user_client *dev;
	struct vfio_user_msg msg = { 0 };
	uint32_t sz = VFIO_USER_MSG_HDR_SIZE + sizeof(struct vfio_user_version)
		- VFIO_USER_MAX_VERSION_DATA;
	struct vfio_user_version *ver = &msg.payload.ver;
	int ret;

	if (!sock_addr)
		return -EINVAL;

	dev = vfio_user_client_create_dev(sock_addr);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to attach the device "
			"with sock_addr %s\n", sock_addr);
		return -1;
	}

	vfio_user_client_fill_hdr(&msg, VFIO_USER_VERSION, sz, dev->msg_id++);
	ver->major = VFIO_USER_VERSION_MAJOR;
	ver->minor = VFIO_USER_VERSION_MINOR;

	ret = vfio_user_client_send_recv(dev->sock.sock_fd, &msg);
	if (ret)
		return ret;

	if (msg.flags & VFIO_USER_ERROR) {
		VFIO_USER_LOG(ERR, "Failed to negotiate version: %s\n",
				msg.err ? strerror(msg.err) : "Unknown error");
		return msg.err ? -(int)msg.err : -1;
	}

	if (vfio_user_check_msg_fdnum(&msg, 0) != 0)
		return -1;

	return dev->sock.dev_id;
}

int
rte_vfio_user_detach_dev(int dev_id)
{
	int ret;

	if (dev_id < 0)
		return -EINVAL;

	ret = vfio_user_client_destroy_dev(dev_id);
	if (ret)
		VFIO_USER_LOG(ERR, "Failed to detach the device (ID:%d)\n",
			dev_id);

	return ret;
}

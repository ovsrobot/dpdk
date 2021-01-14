/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "vfio_user_server.h"

#define MAX_VFIO_USER_DEVICE 1024

static struct vfio_user_server *vfio_user_devices[MAX_VFIO_USER_DEVICE];
static pthread_mutex_t vfio_dev_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct vfio_user_ep_sock vfio_ep_sock = {
	.ep = {
		.fd_mutex = PTHREAD_MUTEX_INITIALIZER,
		.fd_num = 0
	},
	.sock_num = 0,
	.mutex = PTHREAD_MUTEX_INITIALIZER,
};

static int
vfio_user_negotiate_version(struct vfio_user_server *dev,
	struct vfio_user_msg *msg)
{
	struct vfio_user_version *ver = &msg->payload.ver;

	if (vfio_user_check_msg_fdnum(msg, 0) != 0)
		return -EINVAL;

	if (ver->major == dev->ver.major && ver->minor <= dev->ver.minor)
		return 0;
	else
		return -ENOTSUP;
}

static vfio_user_msg_handler_t vfio_user_msg_handlers[VFIO_USER_MAX] = {
	[VFIO_USER_NONE] = NULL,
	[VFIO_USER_VERSION] = vfio_user_negotiate_version,
};

static struct vfio_user_server_socket *
vfio_user_find_socket(const char *sock_addr)
{
	uint32_t i;

	if (sock_addr == NULL)
		return NULL;

	for (i = 0; i < vfio_ep_sock.sock_num; i++) {
		struct vfio_user_server_socket *s = vfio_ep_sock.sock[i];

		if (!strcmp(s->sock.sock_addr, sock_addr))
			return s;
	}

	return NULL;
}

static struct vfio_user_server_socket *
vfio_user_create_sock(const char *sock_addr)
{
	struct vfio_user_server_socket *sk;
	struct vfio_user_socket *sock;
	int fd;
	struct sockaddr_un *un;

	pthread_mutex_lock(&vfio_ep_sock.mutex);
	if (vfio_ep_sock.sock_num == VFIO_USER_MAX_FD) {
		VFIO_USER_LOG(ERR, "Failed to create socket:"
			" socket num reaches max\n");
		goto err;
	}

	sk = vfio_user_find_socket(sock_addr);
	if (sk) {
		VFIO_USER_LOG(ERR, "Failed to create socket:"
			"socket addr exists\n");
		goto err;
	}

	sk = malloc(sizeof(*sk));
	if (!sk) {
		VFIO_USER_LOG(ERR, "Failed to alloc server socket\n");
		goto err;
	}

	sock = &sk->sock;
	sock->sock_addr = strdup(sock_addr);
	if (!sock->sock_addr) {
		VFIO_USER_LOG(ERR, "Failed to copy sock_addr\n");
		goto err_dup;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		VFIO_USER_LOG(ERR, "Failed to create socket\n");
		goto err_sock;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
		VFIO_USER_LOG(ERR, "can't set nonblocking mode for socket, "
			"fd: %d (%s)\n", fd, strerror(errno));
		goto err_fcntl;
	}

	un = &sk->un;
	memset(un, 0, sizeof(*un));
	un->sun_family = AF_UNIX;
	strncpy(un->sun_path, sock->sock_addr, sizeof(un->sun_path));
	un->sun_path[sizeof(un->sun_path) - 1] = '\0';
	sock->sock_fd = fd;
	sk->conn_fd = -1;

	vfio_ep_sock.sock[vfio_ep_sock.sock_num++] = sk;

	pthread_mutex_unlock(&vfio_ep_sock.mutex);

	return sk;

err_fcntl:
	close(fd);
err_sock:
	free(sock->sock_addr);
err_dup:
	free(sk);
err:
	pthread_mutex_unlock(&vfio_ep_sock.mutex);
	return NULL;
}

static void
vfio_user_delete_sock(struct vfio_user_server_socket *sk)
{
	uint32_t i, end;
	struct vfio_user_socket *sock;

	if (!sk)
		return;

	pthread_mutex_lock(&vfio_ep_sock.mutex);

	for (i = 0; i < vfio_ep_sock.sock_num; i++) {
		if (vfio_ep_sock.sock[i] == sk)
			break;
	}

	sock = &sk->sock;
	end = --vfio_ep_sock.sock_num;
	vfio_ep_sock.sock[i] = vfio_ep_sock.sock[end];
	vfio_ep_sock.sock[end] = NULL;

	free(sock->sock_addr);
	close(sock->sock_fd);
	if (sk->conn_fd != -1)
		close(sk->conn_fd);
	unlink(sock->sock_addr);
	free(sk);

	pthread_mutex_unlock(&vfio_ep_sock.mutex);
}

static inline int
vfio_user_init_epoll(struct vfio_user_epoll *ep)
{
	int epfd = epoll_create(1);
	if (epfd < 0) {
		VFIO_USER_LOG(ERR, "Failed to create epoll fd\n");
		return -1;
	}

	ep->epfd = epfd;
	return 0;
}

static inline void
vfio_user_destroy_epoll(struct vfio_user_epoll *ep)
{
	close(ep->epfd);
	ep->epfd = -1;
}

static int
vfio_user_add_listen_fd(struct vfio_user_epoll *ep,
	int sock_fd, event_handler evh, void *data)
{
	struct epoll_event evt;
	int ret = 0;
	uint32_t event = EPOLLIN | EPOLLPRI;

	pthread_mutex_lock(&ep->fd_mutex);

	evt.events = event;
	evt.data.ptr = &ep->fdinfo[ep->fd_num];

	if (ep->fd_num >= VFIO_USER_MAX_FD) {
		VFIO_USER_LOG(ERR, "Error add listen fd, "
			"exceed max num\n");
		ret = -1;
		goto err;
	}

	ep->fdinfo[ep->fd_num].fd = sock_fd;
	ep->fdinfo[ep->fd_num].event = event;
	ep->fdinfo[ep->fd_num].ev_handle = evh;
	ep->fdinfo[ep->fd_num].data = data;

	if (epoll_ctl(ep->epfd, EPOLL_CTL_ADD, sock_fd, &evt) < 0) {
		VFIO_USER_LOG(ERR, "Error add listen fd, "
			"epoll_ctl failed\n");
		ret = -1;
		goto err;
	}

	ep->fd_num++;
err:
	pthread_mutex_unlock(&ep->fd_mutex);
	return ret;
}

static int
vfio_user_del_listen_fd(struct vfio_user_epoll *ep,
	int sock_fd)
{
	struct epoll_event evt;
	uint32_t event = EPOLLIN | EPOLLPRI;
	uint32_t i;
	int ret = 0;

	pthread_mutex_lock(&ep->fd_mutex);

	for (i = 0; i < ep->fd_num; i++) {
		if (ep->fdinfo[i].fd == sock_fd) {
			ep->fdinfo[i].fd = -1;
			break;
		}
	}

	evt.events = event;
	evt.data.ptr = &ep->fdinfo[i];

	if (epoll_ctl(ep->epfd, EPOLL_CTL_DEL, sock_fd, &evt) < 0) {
		VFIO_USER_LOG(ERR, "Error del listen fd, "
			"epoll_ctl failed\n");
		ret = -1;
	}

	pthread_mutex_unlock(&ep->fd_mutex);
	return ret;
}

static inline int
next_mv_src_idx(FD_INFO *info, int end)
{
	int i;

	for (i = end; i >= 0 && info[i].fd == -1; i--)
		;

	return i;
}

static void
vfio_user_fd_cleanup(struct vfio_user_epoll *ep)
{
	int mv_src_idx, mv_dst_idx;
	if (ep->fd_num != 0) {
		pthread_mutex_lock(&ep->fd_mutex);

		mv_src_idx = next_mv_src_idx(ep->fdinfo, ep->fd_num - 1);
		for (mv_dst_idx = 0; mv_dst_idx < mv_src_idx; mv_dst_idx++) {
			if (ep->fdinfo[mv_dst_idx].fd != -1)
				continue;
			ep->fdinfo[mv_dst_idx] = ep->fdinfo[mv_src_idx];
			mv_src_idx = next_mv_src_idx(ep->fdinfo,
				mv_src_idx - 1);
		}
		ep->fd_num = mv_src_idx + 1;

		pthread_mutex_unlock(&ep->fd_mutex);
	}
}

static void *
vfio_user_fd_event_handler(void *arg)
{
	struct vfio_user_epoll *ep = arg;
	struct epoll_event *events;
	int num_fd, i, ret, cleanup;
	event_handler evh;
	FD_INFO *info;

	while (1) {
		events = ep->events;
		num_fd = epoll_wait(ep->epfd, events,
			VFIO_USER_MAX_FD, 1000);
		if (num_fd <= 0)
			continue;
		cleanup = 0;

		for (i = 0; i < num_fd; i++) {
			info = (FD_INFO *)events[i].data.ptr;
			evh = info->ev_handle;

			if (evh) {
				ret = evh(info->fd, info->data);
				if (ret < 0) {
					info->fd = -1;
					cleanup = 1;
				}
			}
		}

		if (cleanup)
			vfio_user_fd_cleanup(ep);
	}
	return NULL;
}

static inline int
vfio_user_add_device(void)
{
	struct vfio_user_server *dev;
	int i;

	pthread_mutex_lock(&vfio_dev_mutex);
	for (i = 0; i < MAX_VFIO_USER_DEVICE; i++) {
		if (vfio_user_devices[i] == NULL)
			break;
	}

	if (i == MAX_VFIO_USER_DEVICE) {
		VFIO_USER_LOG(ERR, "vfio user device num reaches max!\n");
		i = -1;
		goto exit;
	}

	dev = malloc(sizeof(struct vfio_user_server));
	if (dev == NULL) {
		VFIO_USER_LOG(ERR, "Failed to alloc new vfio-user dev.\n");
		i = -1;
		goto exit;
	}

	memset(dev, 0, sizeof(struct vfio_user_server));
	vfio_user_devices[i] = dev;
	dev->dev_id = i;
	dev->conn_fd = -1;

exit:
	pthread_mutex_unlock(&vfio_dev_mutex);
	return i;
}

static inline void
vfio_user_del_device(struct vfio_user_server *dev)
{
	if (dev == NULL)
		return;

	pthread_mutex_lock(&vfio_dev_mutex);
	vfio_user_devices[dev->dev_id] = NULL;
	free(dev);
	pthread_mutex_unlock(&vfio_dev_mutex);
}

static inline struct vfio_user_server *
vfio_user_get_device(int dev_id)
{
	struct vfio_user_server *dev;

	pthread_mutex_lock(&vfio_dev_mutex);
	dev = vfio_user_devices[dev_id];
	if (!dev)
		VFIO_USER_LOG(ERR, "Device %d not found.\n", dev_id);
	pthread_mutex_unlock(&vfio_dev_mutex);

	return dev;
}

static int
vfio_user_message_handler(int dev_id, int fd)
{
	struct vfio_user_server *dev;
	struct vfio_user_msg msg;
	uint32_t cmd;
	int ret = 0;

	dev = vfio_user_get_device(dev_id);
	if (!dev)
		return -1;

	ret = vfio_user_recv_msg(fd, &msg);
	if (ret <= 0) {
		if (ret < 0)
			VFIO_USER_LOG(ERR, "Read message failed\n");
		else
			VFIO_USER_LOG(ERR, "Peer closed\n");
		return -1;
	}

	if (msg.msg_id != dev->msg_id)
		return -1;
	ret = 0;
	cmd = msg.cmd;
	dev->msg_id++;
	if (cmd > VFIO_USER_NONE && cmd < VFIO_USER_MAX &&
			vfio_user_msg_str[cmd]) {
		VFIO_USER_LOG(INFO, "Read message %s\n",
			vfio_user_msg_str[cmd]);
	} else {
		VFIO_USER_LOG(ERR, "Read unknown message\n");
		return -1;
	}

	if (vfio_user_msg_handlers[cmd])
		ret = vfio_user_msg_handlers[cmd](dev, &msg);
	else {
		VFIO_USER_LOG(ERR, "Handler not defined for %s\n",
			vfio_user_msg_str[cmd]);
		ret = -1;
		goto handle_end;
	}

	if (!(msg.flags & VFIO_USER_NEED_NO_RP)) {
		if (ret < 0) {
			msg.flags |= VFIO_USER_ERROR;
			msg.err = -ret;
			/* If an error occurs, the reply message must
			 * only include the reply header.
			 */
			msg.size = VFIO_USER_MSG_HDR_SIZE;
			VFIO_USER_LOG(ERR, "Handle status error(%d) for %s\n",
				ret, vfio_user_msg_str[cmd]);
		}

		ret = vfio_user_reply_msg(fd, &msg);
		if (ret < 0) {
			VFIO_USER_LOG(ERR, "Reply error for %s\n",
				vfio_user_msg_str[cmd]);
		} else {
			VFIO_USER_LOG(INFO, "Reply %s succeeds\n",
				vfio_user_msg_str[cmd]);
			ret = 0;
		}
	}

handle_end:
	return ret;
}

static int
vfio_user_sock_read(int fd, void *data)
{
	struct vfio_user_server_socket *sk = data;
	int ret, dev_id = sk->sock.dev_id;

	ret = vfio_user_message_handler(dev_id, fd);
	if (ret < 0) {
		struct vfio_user_server *dev;

		vfio_user_del_listen_fd(&vfio_ep_sock.ep, sk->conn_fd);
		close(fd);
		sk->conn_fd = -1;
		dev = vfio_user_get_device(dev_id);
		if (dev)
			dev->msg_id = 0;
	}

	return ret;
}

static void
vfio_user_set_ifname(int dev_id, const char *sock_addr, unsigned int size)
{
	struct vfio_user_server *dev;
	unsigned int len;

	dev = vfio_user_get_device(dev_id);
	if (!dev)
		return;

	len = size > sizeof(dev->sock_addr) ?
		sizeof(dev->sock_addr) : size;
	strncpy(dev->sock_addr, sock_addr, len);
	dev->sock_addr[len] = '\0';
}

static int
vfio_user_add_new_connection(int fd, void *data)
{
	struct vfio_user_server *dev;
	int dev_id;
	size_t size;
	struct vfio_user_server_socket *sk = data;
	struct vfio_user_socket *sock = &sk->sock;
	int conn_fd;
	int ret;

	if (sk->conn_fd != -1)
		return 0;

	conn_fd = accept(fd, NULL, NULL);
	if (fd < 0)
		return -1;

	VFIO_USER_LOG(INFO, "New vfio-user client(%s) connected\n",
		sock->sock_addr);

	if (sock == NULL)
		return -1;

	dev_id = sock->dev_id;
	sk->conn_fd = conn_fd;

	dev = vfio_user_get_device(dev_id);
	if (!dev)
		return -1;

	dev->conn_fd = conn_fd;

	size = strnlen(sock->sock_addr, PATH_MAX);
	vfio_user_set_ifname(dev_id, sock->sock_addr, size);

	ret = vfio_user_add_listen_fd(&vfio_ep_sock.ep,
		conn_fd, vfio_user_sock_read, sk);
	if (ret < 0) {
		VFIO_USER_LOG(ERR, "Failed to add fd %d into vfio server fdset\n",
			conn_fd);
		goto err_cleanup;
	}

	return 0;

err_cleanup:
	close(fd);
	return -1;
}

static int
vfio_user_start_server(struct vfio_user_server_socket *sk)
{
	struct vfio_user_server *dev;
	int ret;
	struct vfio_user_socket *sock = &sk->sock;
	int fd = sock->sock_fd;
	const char *path = sock->sock_addr;

	dev = vfio_user_get_device(sock->dev_id);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to start, "
			"device not found\n");
		return -1;
	}

	if (dev->started) {
		VFIO_USER_LOG(INFO, "device already started\n");
		return 0;
	}

	unlink(path);
	ret = bind(fd, (struct sockaddr *)&sk->un, sizeof(sk->un));
	if (ret < 0) {
		VFIO_USER_LOG(ERR, "failed to bind to %s: %s;"
			"remove it and try again\n",
			path, strerror(errno));
		goto err;
	}

	ret = listen(fd, 128);
	if (ret < 0)
		goto err;

	ret = vfio_user_add_listen_fd(&vfio_ep_sock.ep,
		fd, vfio_user_add_new_connection, (void *)sk);
	if (ret < 0) {
		VFIO_USER_LOG(ERR, "failed to add listen fd %d to "
			"vfio-user server fdset\n", fd);
		goto err;
	}

	dev->started = 1;

	return 0;

err:
	close(fd);
	return -1;
}

int
rte_vfio_user_register(const char *sock_addr)
{
	struct vfio_user_server_socket *sk;
	struct vfio_user_server *dev;
	int dev_id;

	if (!sock_addr)
		return -1;

	sk = vfio_user_create_sock(sock_addr);
	if (!sk) {
		VFIO_USER_LOG(ERR, "Create socket failed\n");
		goto exit;
	}

	dev_id = vfio_user_add_device();
	if (dev_id == -1) {
		VFIO_USER_LOG(ERR, "Failed to add new vfio device\n");
		goto err_add_dev;
	}
	sk->sock.dev_id = dev_id;

	dev = vfio_user_get_device(dev_id);

	dev->ver.major = VFIO_USER_VERSION_MAJOR;
	dev->ver.minor = VFIO_USER_VERSION_MINOR;

	return 0;

err_add_dev:
	vfio_user_delete_sock(sk);
exit:
	return -1;
}

int
rte_vfio_user_unregister(const char *sock_addr)
{
	struct vfio_user_server_socket *sk;
	struct vfio_user_server *dev;
	int dev_id;

	pthread_mutex_lock(&vfio_ep_sock.mutex);
	sk = vfio_user_find_socket(sock_addr);
	pthread_mutex_unlock(&vfio_ep_sock.mutex);

	if (!sk) {
		VFIO_USER_LOG(ERR, "Failed to unregister:"
			"socket addr not registered.\n");
		return -1;
	}

	dev_id = sk->sock.dev_id;
	/* Client may already disconnect before unregistration */
	if (sk->conn_fd != -1)
		vfio_user_del_listen_fd(&vfio_ep_sock.ep, sk->conn_fd);
	vfio_user_del_listen_fd(&vfio_ep_sock.ep, sk->sock.sock_fd);
	vfio_user_fd_cleanup(&vfio_ep_sock.ep);
	vfio_user_delete_sock(sk);

	dev = vfio_user_get_device(dev_id);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to unregister:"
			"device not found.\n");
		return -1;
	}

	vfio_user_del_device(dev);

	return 0;
}

int
rte_vfio_user_start(const char *sock_addr)
{
	static pthread_t pid;
	struct vfio_user_server_socket *sock;

	pthread_mutex_lock(&vfio_ep_sock.mutex);

	sock = vfio_user_find_socket(sock_addr);
	if (!sock) {
		VFIO_USER_LOG(ERR, "sock_addr not registered to vfio_user "
			"before start\n");
		goto exit;
	}

	if (pid == 0) {
		struct vfio_user_epoll *ep = &vfio_ep_sock.ep;

		if (vfio_user_init_epoll(ep)) {
			VFIO_USER_LOG(ERR, "Init vfio-user epoll failed\n");
			return -1;
		}

		if (pthread_create(&pid, NULL,
			vfio_user_fd_event_handler, ep)) {
			vfio_user_destroy_epoll(ep);
			VFIO_USER_LOG(ERR, "Event handler thread create failed\n");
			return -1;
		}
	}

	pthread_mutex_unlock(&vfio_ep_sock.mutex);

	return vfio_user_start_server(sock);

exit:
	pthread_mutex_unlock(&vfio_ep_sock.mutex);
	return -1;
}

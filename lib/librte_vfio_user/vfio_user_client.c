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

int
rte_vfio_user_get_dev_info(int dev_id, struct vfio_device_info *info)
{
	struct vfio_user_msg msg = { 0 };
	struct vfio_user_client *dev;
	int ret;
	uint32_t sz = VFIO_USER_MSG_HDR_SIZE + sizeof(struct vfio_device_info);

	if (!info)
		return -EINVAL;

	dev = vfio_client_devs.cl[dev_id];
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to get device info: "
			"wrong device ID\n");
		return -EINVAL;
	}

	vfio_user_client_fill_hdr(&msg, VFIO_USER_DEVICE_GET_INFO,
		sz, dev->msg_id++);

	ret = vfio_user_client_send_recv(dev->sock.sock_fd, &msg);
	if (ret)
		return ret;

	if (msg.flags & VFIO_USER_ERROR) {
		VFIO_USER_LOG(ERR, "Failed to get device info: %s\n",
				msg.err ? strerror(msg.err) : "Unknown error");
		return msg.err ? -(int)msg.err : -1;
	}

	if (vfio_user_check_msg_fdnum(&msg, 0) != 0)
		return -1;

	memcpy(info, &msg.payload.dev_info, sizeof(*info));
	return ret;
}

int
rte_vfio_user_get_reg_info(int dev_id, struct vfio_region_info *info,
	int *fd)
{
	struct vfio_user_msg msg = { 0 };
	int ret, fd_num = 0;
	struct vfio_user_client *dev;
	uint32_t sz = VFIO_USER_MSG_HDR_SIZE + info->argsz;
	struct vfio_user_reg *reg = &msg.payload.reg_info;

	if (!info || !fd)
		return -EINVAL;

	dev = vfio_client_devs.cl[dev_id];
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to get region info: "
			"wrong device ID\n");
		return -EINVAL;
	}

	vfio_user_client_fill_hdr(&msg, VFIO_USER_DEVICE_GET_REGION_INFO,
		sz, dev->msg_id++);
	reg->reg_info.index = info->index;

	ret = vfio_user_client_send_recv(dev->sock.sock_fd, &msg);
	if (ret)
		return ret;

	if (msg.flags & VFIO_USER_ERROR) {
		VFIO_USER_LOG(ERR, "Failed to get region(%u) info: %s\n",
				info->index, msg.err ? strerror(msg.err) :
				"Unknown error");
		return msg.err ? -(int)msg.err : -1;
	}

	if (reg->reg_info.flags & VFIO_REGION_INFO_FLAG_MMAP)
		fd_num = 1;

	if (vfio_user_check_msg_fdnum(&msg, fd_num) != 0)
		return -1;

	if (reg->reg_info.index != info->index ||
		msg.size - VFIO_USER_MSG_HDR_SIZE > sizeof(*reg)) {
		VFIO_USER_LOG(ERR,
			"Incorrect reply message for region info\n");
		return -1;
	}

	memcpy(info, &msg.payload.reg_info, info->argsz);
	*fd = fd_num == 1 ? msg.fds[0] : -1;

	return 0;
}

int
rte_vfio_user_get_irq_info(int dev_id, struct vfio_irq_info *info)
{
	struct vfio_user_msg msg = { 0 };
	int ret;
	struct vfio_user_client *dev;
	uint32_t sz = VFIO_USER_MSG_HDR_SIZE + sizeof(struct vfio_irq_info);
	struct vfio_irq_info *irq_info = &msg.payload.irq_info;

	if (!info)
		return -EINVAL;

	dev = vfio_client_devs.cl[dev_id];
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to get region info: "
			"wrong device ID\n");
		return -EINVAL;
	}

	vfio_user_client_fill_hdr(&msg, VFIO_USER_DEVICE_GET_IRQ_INFO,
		sz, dev->msg_id++);
	irq_info->index = info->index;

	ret = vfio_user_client_send_recv(dev->sock.sock_fd, &msg);
	if (ret)
		return ret;

	if (msg.flags & VFIO_USER_ERROR) {
		VFIO_USER_LOG(ERR, "Failed to get irq(%u) info: %s\n",
				info->index, msg.err ? strerror(msg.err) :
				"Unknown error");
		return msg.err ? -(int)msg.err : -1;
	}

	if (vfio_user_check_msg_fdnum(&msg, 0) != 0)
		return -1;

	if (irq_info->index != info->index ||
		msg.size - VFIO_USER_MSG_HDR_SIZE != sizeof(*irq_info)) {
		VFIO_USER_LOG(ERR,
			"Incorrect reply message for IRQ info\n");
		return -1;
	}

	memcpy(info, irq_info, sizeof(*info));
	return 0;
}

static int
vfio_user_client_dma_map_unmap(struct vfio_user_client *dev,
	struct rte_vfio_user_mem_reg *mem, int *fds, uint32_t num, bool ismap)
{
	struct vfio_user_msg msg = { 0 };
	int ret;
	uint32_t i, mem_sz, map;
	uint16_t cmd = VFIO_USER_DMA_UNMAP;

	if (num > VFIO_USER_MSG_MAX_NREG) {
		VFIO_USER_LOG(ERR,
			"Too many memory regions to %s (MAX: %u)\n",
			ismap ? "map" : "unmap", VFIO_USER_MSG_MAX_NREG);
		return -EINVAL;
	}

	if (ismap) {
		cmd = VFIO_USER_DMA_MAP;

		for (i = 0; i < num; i++) {
			map = mem->flags & RTE_VUSER_MEM_MAPPABLE;
			if ((map && (fds[i] == -1)) ||
				(!map && (fds[i] != -1))) {
				VFIO_USER_LOG(ERR, "%spable memory region "
					"should%s have valid fd\n",
					ismap ? "Map" : "Unmap",
					ismap ? "" : " not");
				return -EINVAL;
			}

			if (fds[i] != -1)
				msg.fds[msg.fd_num++] = fds[i];
		}
	}

	mem_sz = sizeof(struct rte_vfio_user_mem_reg) * num;
	memcpy(&msg.payload, mem, mem_sz);

	vfio_user_client_fill_hdr(&msg, cmd, mem_sz + VFIO_USER_MSG_HDR_SIZE,
		dev->msg_id++);

	ret = vfio_user_client_send_recv(dev->sock.sock_fd, &msg);
	if (ret)
		return ret;

	if (msg.flags & VFIO_USER_ERROR) {
		VFIO_USER_LOG(ERR, "Failed to %smap memory regions: "
				"%s\n", ismap ? "" : "un",
				msg.err ? strerror(msg.err) : "Unknown error");
		return msg.err ? -(int)msg.err : -1;
	}

	if (vfio_user_check_msg_fdnum(&msg, 0) != 0)
		return -1;

	return 0;
}

int
rte_vfio_user_dma_map(int dev_id, struct rte_vfio_user_mem_reg *mem,
	int *fds, uint32_t num)
{
	struct vfio_user_client *dev;

	if (!mem || !fds)
		return -EINVAL;

	dev = vfio_client_devs.cl[dev_id];
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to dma map: "
			"wrong device ID\n");
		return -EINVAL;
	}

	return vfio_user_client_dma_map_unmap(dev, mem, fds, num, true);
}

int
rte_vfio_user_dma_unmap(int dev_id, struct rte_vfio_user_mem_reg *mem,
	uint32_t num)
{
	struct vfio_user_client *dev;

	if (!mem)
		return -EINVAL;

	dev = vfio_client_devs.cl[dev_id];
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to dma unmap: "
			"wrong device ID\n");
		return -EINVAL;
	}

	return vfio_user_client_dma_map_unmap(dev, mem, NULL, num, false);
}

int
rte_vfio_user_set_irqs(int dev_id, struct vfio_irq_set *set)
{
	struct vfio_user_msg msg = { 0 };
	int ret;
	struct vfio_user_client *dev;
	uint32_t set_sz = set->argsz;
	struct vfio_user_irq_set *irq_set = &msg.payload.irq_set;

	if (!set)
		return -EINVAL;

	dev = vfio_client_devs.cl[dev_id];
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to set irqs: "
			"wrong device ID\n");
		return -EINVAL;
	}

	if (set->flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		msg.fd_num = set->count;
		memcpy(msg.fds, set->data, sizeof(int) * set->count);
		set_sz -= sizeof(int) * set->count;
	}
	memcpy(irq_set, set, set_sz);
	irq_set->set.argsz = set_sz;
	vfio_user_client_fill_hdr(&msg, VFIO_USER_DEVICE_SET_IRQS,
		VFIO_USER_MSG_HDR_SIZE + set_sz, dev->msg_id++);

	ret = vfio_user_client_send_recv(dev->sock.sock_fd, &msg);
	if (ret)
		return ret;

	if (msg.flags & VFIO_USER_ERROR) {
		VFIO_USER_LOG(ERR, "Failed to set irq(%u): %s\n",
				set->index, msg.err ? strerror(msg.err) :
				"Unknown error");
		return msg.err ? -(int)msg.err : -1;
	}

	if (vfio_user_check_msg_fdnum(&msg, 0) != 0)
		return -1;

	return 0;
}

int
rte_vfio_user_region_read(int dev_id, uint32_t idx, uint64_t offset,
	uint32_t size, void *data)
{
	struct vfio_user_msg msg = { 0 };
	int ret;
	struct vfio_user_client *dev;
	uint32_t sz = VFIO_USER_MSG_HDR_SIZE + sizeof(struct vfio_user_reg_rw)
		- VFIO_USER_MAX_RW_DATA;
	struct vfio_user_reg_rw *rw = &msg.payload.reg_rw;

	if (!data)
		return -EINVAL;

	dev = vfio_client_devs.cl[dev_id];
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to read region: "
			"wrong device ID\n");
		return -EINVAL;
	}

	if (sz > VFIO_USER_MAX_RW_DATA) {
		VFIO_USER_LOG(ERR, "Region read size exceeds max\n");
		return -1;
	}

	vfio_user_client_fill_hdr(&msg, VFIO_USER_REGION_READ,
		sz, dev->msg_id++);

	rw->reg_idx = idx;
	rw->reg_offset = offset;
	rw->size = size;

	ret = vfio_user_client_send_recv(dev->sock.sock_fd, &msg);
	if (ret)
		return ret;

	if (msg.flags & VFIO_USER_ERROR) {
		VFIO_USER_LOG(ERR, "Failed to read region(%u): %s\n",
				idx, msg.err ? strerror(msg.err) :
				"Unknown error");
		return msg.err ? -(int)msg.err : -1;
	}

	if (vfio_user_check_msg_fdnum(&msg, 0) != 0)
		return -1;

	memcpy(data, rw->data, size);
	return 0;
}

int
rte_vfio_user_region_write(int dev_id, uint32_t idx, uint64_t offset,
	uint32_t size, const void *data)
{
	struct vfio_user_msg msg = { 0 };
	int ret;
	struct vfio_user_client *dev;
	uint32_t sz = VFIO_USER_MSG_HDR_SIZE + sizeof(struct vfio_user_reg_rw)
		- VFIO_USER_MAX_RW_DATA + size;
	struct vfio_user_reg_rw *rw = &msg.payload.reg_rw;

	if (!data)
		return -EINVAL;

	dev = vfio_client_devs.cl[dev_id];
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to write region: "
			"wrong device ID\n");
		return -EINVAL;
	}

	if (sz > VFIO_USER_MAX_RW_DATA) {
		VFIO_USER_LOG(ERR, "Region write size exceeds max\n");
		return -EINVAL;
	}

	vfio_user_client_fill_hdr(&msg, VFIO_USER_REGION_WRITE,
		sz, dev->msg_id++);

	rw->reg_idx = idx;
	rw->reg_offset = offset;
	rw->size = size;
	memcpy(rw->data, data, size);

	ret = vfio_user_client_send_recv(dev->sock.sock_fd, &msg);
	if (ret)
		return ret;

	if (msg.flags & VFIO_USER_ERROR) {
		VFIO_USER_LOG(ERR, "Failed to write region(%u): %s\n",
				idx, msg.err ? strerror(msg.err) :
				"Unknown error");
		return msg.err ? -(int)msg.err : -1;
	}

	if (vfio_user_check_msg_fdnum(&msg, 0) != 0)
		return -1;

	return 0;
}

int
rte_vfio_user_reset(int dev_id)
{
	struct vfio_user_msg msg = { 0 };
	int ret;
	struct vfio_user_client *dev;
	uint32_t sz = VFIO_USER_MSG_HDR_SIZE;

	dev = vfio_client_devs.cl[dev_id];
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to write region: "
			"wrong device ID\n");
		return -EINVAL;
	}

	vfio_user_client_fill_hdr(&msg, VFIO_USER_DEVICE_RESET,
		sz, dev->msg_id++);

	ret = vfio_user_client_send_recv(dev->sock.sock_fd, &msg);
	if (ret)
		return ret;

	if (msg.flags & VFIO_USER_ERROR) {
		VFIO_USER_LOG(ERR, "Failed to reset device: %s\n",
				msg.err ? strerror(msg.err) :
				"Unknown error");
		return msg.err ? -(int)msg.err : -1;
	}

	if (vfio_user_check_msg_fdnum(&msg, 0) != 0)
		return -1;

	return ret;
}

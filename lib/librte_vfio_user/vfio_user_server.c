/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/eventfd.h>

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

static int
mmap_one_region(struct rte_vfio_user_mtb_entry *entry,
	struct rte_vfio_user_mem_reg *memory, int fd)
{
	if (fd != -1) {
		if (memory->fd_offset >= -memory->size) {
			VFIO_USER_LOG(ERR, "memory fd_offset and size overflow\n");
			return -EINVAL;
		}
		entry->mmap_size = memory->fd_offset + memory->size;
		entry->mmap_addr = mmap(NULL,
			entry->mmap_size,
			memory->protection, MAP_SHARED,
			fd, 0);
		if (entry->mmap_addr == MAP_FAILED) {
			VFIO_USER_LOG(ERR, "Failed to mmap dma region\n");
			return -EINVAL;
		}

		entry->host_user_addr =
			(uint64_t)entry->mmap_addr + memory->fd_offset;
		entry->fd = fd;
	} else {
		entry->mmap_size = 0;
		entry->mmap_addr = NULL;
		entry->host_user_addr = 0;
		entry->fd = -1;
	}

	entry->gpa = memory->gpa;
	entry->size = memory->size;

	return 0;
}

static uint32_t
add_one_region(struct rte_vfio_user_mem *mem,
	struct rte_vfio_user_mem_reg *memory, int fd)
{
	struct rte_vfio_user_mtb_entry *entry = &mem->entry[0];
	uint32_t num = mem->entry_num, i, j;
	uint32_t sz = sizeof(struct rte_vfio_user_mtb_entry);
	struct rte_vfio_user_mtb_entry ent;
	int err = 0;

	if (mem->entry_num == RTE_VUSER_MAX_DMA) {
		VFIO_USER_LOG(ERR, "Add mem region failed, reach max!\n");
		return -EBUSY;
	}

	for (i = 0; i < num; i++) {
		entry = &mem->entry[i];

		if (memory->gpa == entry->gpa &&
			memory->size == entry->size)
			return -EEXIST;

		if (memory->gpa > entry->gpa &&
			memory->gpa >= entry->gpa + entry->size)
			continue;

		if (memory->gpa < entry->gpa &&
			memory->gpa + memory->size <= entry->gpa)
			break;

		return -EINVAL;
	}

	err = mmap_one_region(&ent, memory, fd);
	if (err)
		return err;

	for (j = num; j > i; j--)
		memcpy(&mem->entry[j], &mem->entry[j - 1], sz);
	memcpy(&mem->entry[i], &ent, sz);
	mem->entry_num++;

	VFIO_USER_LOG(DEBUG, "DMA MAP(gpa: 0x%" PRIx64 ", sz: 0x%" PRIx64
			", hva: 0x%" PRIx64 ", ma: 0x%" PRIx64
			", msz: 0x%" PRIx64 ", fd: %d)\n", ent.gpa,
			ent.size, ent.host_user_addr, (uint64_t)ent.mmap_addr,
			ent.mmap_size, ent.fd);
	return 0;
}

static void
del_one_region(struct rte_vfio_user_mem *mem,
	struct rte_vfio_user_mem_reg *memory)
{
	struct rte_vfio_user_mtb_entry *entry;
	uint32_t num = mem->entry_num, i, j;
	uint32_t sz = sizeof(struct rte_vfio_user_mtb_entry);

	if (mem->entry_num == 0) {
		VFIO_USER_LOG(ERR, "Delete mem region failed (No region exists)!\n");
		return;
	}

	for (i = 0; i < num; i++) {
		entry = &mem->entry[i];

		if (memory->gpa == entry->gpa &&
			memory->size == entry->size) {
			if (entry->mmap_addr != NULL) {
				munmap(entry->mmap_addr, entry->mmap_size);
				mem->entry[i].mmap_size = 0;
				mem->entry[i].mmap_addr = NULL;
				mem->entry[i].host_user_addr = 0;
				mem->entry[i].fd = -1;
			}

			mem->entry[i].gpa = 0;
			mem->entry[i].size = 0;

			for (j = i; j < num - 1; j++) {
				memcpy(&mem->entry[j], &mem->entry[j + 1],
					sz);
			}
			mem->entry_num--;

			VFIO_USER_LOG(DEBUG, "DMA UNMAP(gpa: 0x%" PRIx64
				", sz: 0x%" PRIx64 ", hva: 0x%" PRIx64
				", ma: 0x%" PRIx64", msz: 0x%" PRIx64
				", fd: %d)\n", entry->gpa, entry->size,
				entry->host_user_addr,
				(uint64_t)entry->mmap_addr, entry->mmap_size,
				entry->fd);

			return;
		}
	}

	VFIO_USER_LOG(ERR, "Failed to find the region for dma unmap!\n");
}

static int
vfio_user_dma_map(struct vfio_user_server *dev, struct vfio_user_msg *msg)
{
	struct rte_vfio_user_mem_reg *memory = msg->payload.memory;
	uint32_t region_num, expected_fd = 0;
	uint32_t i, j, fd, fd_idx = 0;
	int ret = 0;

	if ((msg->size - VFIO_USER_MSG_HDR_SIZE) % sizeof(*memory) != 0) {
		VFIO_USER_LOG(ERR, "Invalid msg size for dma map\n");
		vfio_user_close_msg_fds(msg);
		ret = -EINVAL;
		goto err;
	}

	region_num = (msg->size - VFIO_USER_MSG_HDR_SIZE)
		/ sizeof(struct rte_vfio_user_mem_reg);

	for (i = 0; i < region_num; i++) {
		if (memory[i].flags & RTE_VUSER_MEM_MAPPABLE)
			expected_fd++;
	}

	if (vfio_user_check_msg_fdnum(msg, expected_fd) != 0) {
		ret = -EINVAL;
		goto err;
	}

	for (i = 0; i < region_num; i++) {
		fd = (memory[i].flags & RTE_VUSER_MEM_MAPPABLE) ?
			msg->fds[fd_idx++] : -1;

		ret = add_one_region(dev->mem, memory + i, fd);
		if (ret < 0) {
			VFIO_USER_LOG(ERR, "Failed to add dma map\n");
			break;
		}
	}

	if (i != region_num) {
		/* Clear all mmaped region and fds */
		for (j = 0; j < region_num; j++) {
			if (j < i)
				del_one_region(dev->mem, memory + j);
			else
				close(msg->fds[j]);
		}
	}
err:
	/* Do not reply fds back */
	msg->fd_num = 0;
	return ret;
}

static int
vfio_user_dma_unmap(struct vfio_user_server *dev, struct vfio_user_msg *msg)
{
	struct rte_vfio_user_mem_reg *memory = msg->payload.memory;
	uint32_t region_num = (msg->size - VFIO_USER_MSG_HDR_SIZE)
		/ sizeof(struct rte_vfio_user_mem_reg);
	uint32_t i;

	if (vfio_user_check_msg_fdnum(msg, 0) != 0)
		return -EINVAL;

	if ((msg->size - VFIO_USER_MSG_HDR_SIZE) % sizeof(*memory) != 0) {
		VFIO_USER_LOG(ERR, "Invalid msg size for dma unmap\n");
		return -EINVAL;
	}

	for (i = 0; i < region_num; i++)
		del_one_region(dev->mem, memory);

	return 0;
}

static int
vfio_user_device_get_info(struct vfio_user_server *dev,
	struct vfio_user_msg *msg)
{
	struct vfio_device_info *dev_info = &msg->payload.dev_info;

	if (vfio_user_check_msg_fdnum(msg, 0) != 0)
		return -EINVAL;

	if (msg->size != sizeof(*dev_info) + VFIO_USER_MSG_HDR_SIZE) {
		VFIO_USER_LOG(ERR, "Invalid message for get dev info\n");
		return -EINVAL;
	}

	memcpy(dev_info, dev->dev_info, sizeof(*dev_info));

	VFIO_USER_LOG(DEBUG, "Device info: argsz(0x%x), flags(0x%x), "
		"regions(%u), irqs(%u)\n", dev_info->argsz, dev_info->flags,
		dev_info->num_regions, dev_info->num_irqs);

	return 0;
}

static int
vfio_user_device_get_reg_info(struct vfio_user_server *dev,
	struct vfio_user_msg *msg)
{
	struct vfio_user_reg *reg = &msg->payload.reg_info;
	struct rte_vfio_user_reg_info *reg_info;
	struct vfio_region_info *vinfo;

	if (vfio_user_check_msg_fdnum(msg, 0) != 0)
		return -EINVAL;

	if (msg->size > sizeof(*reg) + VFIO_USER_MSG_HDR_SIZE ||
		dev->reg->reg_num <= reg->reg_info.index) {
		VFIO_USER_LOG(ERR, "Invalid message for get region info\n");
		return -EINVAL;
	}

	reg_info = &dev->reg->reg_info[reg->reg_info.index];
	vinfo = reg_info->info;
	memcpy(reg, vinfo, vinfo->argsz);

	if (reg_info->fd != -1) {
		msg->fd_num = 1;
		msg->fds[0] = reg_info->fd;
	}

	VFIO_USER_LOG(DEBUG, "Region(%u) info: addr(0x%" PRIx64 "), fd(%d), "
		"sz(0x%llx), argsz(0x%x), c_off(0x%x), flags(0x%x) "
		"off(0x%llx)\n", vinfo->index, (uint64_t)reg_info->base,
		reg_info->fd, vinfo->size, vinfo->argsz, vinfo->cap_offset,
		vinfo->flags, vinfo->offset);

	return 0;
}

static int
vfio_user_device_get_irq_info(struct vfio_user_server *dev,
	struct vfio_user_msg *msg)
{
	struct vfio_irq_info *irq_info = &msg->payload.irq_info;
	struct rte_vfio_user_irq_info *info = dev->irqs.info;
	uint32_t i;

	if (vfio_user_check_msg_fdnum(msg, 0) != 0)
		return -EINVAL;

	for (i = 0; i < info->irq_num; i++) {
		if (irq_info->index == info->irq_info[i].index) {
			irq_info->count = info->irq_info[i].count;
			irq_info->flags |= info->irq_info[i].flags;
			break;
		}
	}
	if (i == info->irq_num)
		return -EINVAL;

	VFIO_USER_LOG(DEBUG, "IRQ info: argsz(0x%x), flags(0x%x), index(0x%x),"
		" count(0x%x)\n", irq_info->argsz, irq_info->flags,
		irq_info->index, irq_info->count);

	return 0;
}

static inline int
irq_set_trigger(struct vfio_user_irqs *irqs,
	struct vfio_irq_set *irq_set, struct vfio_user_msg *msg)
{
	uint32_t i = irq_set->start;
	int eventfd;

	switch (irq_set->flags & VFIO_IRQ_SET_DATA_TYPE_MASK) {
	case VFIO_IRQ_SET_DATA_NONE:
		if (vfio_user_check_msg_fdnum(msg, 0) != 0)
			return -EINVAL;

		for (; i < irq_set->start + irq_set->count; i++) {
			eventfd = irqs->fds[irq_set->index][i];
			if (eventfd >= 0) {
				if (eventfd_write(eventfd, (eventfd_t)1))
					return -errno;
			}
		}
		break;
	case VFIO_IRQ_SET_DATA_BOOL:
		if (vfio_user_check_msg_fdnum(msg, 0) != 0)
			return -EINVAL;

		uint8_t *idx = irq_set->data;
		for (; i < irq_set->start + irq_set->count; i++, idx++) {
			eventfd = irqs->fds[irq_set->index][i];
			if (eventfd >= 0 && *idx == 1) {
				if (eventfd_write(eventfd, (eventfd_t)1))
					return -errno;
			}
		}
		break;
	case VFIO_IRQ_SET_DATA_EVENTFD:
		if (vfio_user_check_msg_fdnum(msg, irq_set->count) != 0)
			return -EINVAL;

		int32_t *fds = msg->fds;
		for (; i < irq_set->start + irq_set->count; i++, fds++) {
			eventfd = irqs->fds[irq_set->index][i];
			if (eventfd >= 0)
				close(eventfd); /* Clear original irqfd*/
			if (*fds >= 0)
				irqs->fds[irq_set->index][i] = *fds;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void
vfio_user_disable_irqs(struct vfio_user_irqs *irqs)
{
	struct rte_vfio_user_irq_info *info = irqs->info;
	uint32_t i, j;

	for (i = 0; i < info->irq_num; i++) {
		for (j = 0; j < info->irq_info[i].count; j++) {
			if (irqs->fds[i][j] != -1) {
				close(irqs->fds[i][j]);
				irqs->fds[i][j] = -1;
			}
		}
	}
}

static int
vfio_user_device_set_irqs(struct vfio_user_server *dev,
	struct vfio_user_msg *msg)
{
	struct vfio_user_irq_set *irq = &msg->payload.irq_set;
	struct vfio_irq_set *irq_set = &irq->set;
	struct rte_vfio_user_irq_info *info = dev->irqs.info;
	int ret = 0;

	if (info->irq_num <= irq_set->index
		|| info->irq_info[irq_set->index].count <
		irq_set->start + irq_set->count) {
		vfio_user_close_msg_fds(msg);
		return -EINVAL;
	}

	if (irq_set->count == 0) {
		if (irq_set->flags & VFIO_IRQ_SET_DATA_NONE) {
			vfio_user_disable_irqs(&dev->irqs);
			return 0;
		}
		vfio_user_close_msg_fds(msg);
		return -EINVAL;
	}

	switch (irq_set->flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
	/* Mask/Unmask not supported for now */
	case VFIO_IRQ_SET_ACTION_MASK:
		/* FALLTHROUGH */
	case VFIO_IRQ_SET_ACTION_UNMASK:
		return 0;
	case VFIO_IRQ_SET_ACTION_TRIGGER:
		ret = irq_set_trigger(&dev->irqs, irq_set, msg);
		break;
	default:
		return -EINVAL;
	}

	VFIO_USER_LOG(DEBUG, "Set IRQ: argsz(0x%x), flags(0x%x), index(0x%x), "
		"start(0x%x), count(0x%x)\n", irq_set->argsz, irq_set->flags,
		irq_set->index, irq_set->start, irq_set->count);

	/* Do not reply fds back */
	msg->fd_num = 0;
	return ret;
}

static int
vfio_user_region_read(struct vfio_user_server *dev,
	struct vfio_user_msg *msg)
{
	struct vfio_user_reg_rw *rw = &msg->payload.reg_rw;
	struct rte_vfio_user_regions *reg = dev->reg;
	struct rte_vfio_user_reg_info *reg_info;
	size_t count;

	if (vfio_user_check_msg_fdnum(msg, 0) != 0)
		return -EINVAL;

	reg_info = &reg->reg_info[rw->reg_idx];

	if (rw->reg_idx >= reg->reg_num ||
		rw->size > VFIO_USER_MAX_RW_DATA ||
		rw->reg_offset >= reg_info->info->size ||
		rw->reg_offset + rw->size > reg_info->info->size) {
		VFIO_USER_LOG(ERR, "Invalid read region request\n");
		rw->size = 0;
		return 0;
	}

	VFIO_USER_LOG(DEBUG, "Read Region(%u): offset(0x%" PRIx64 "),"
		"size(0x%x)\n", rw->reg_idx, rw->reg_offset, rw->size);

	if (reg_info->rw) {
		count = reg_info->rw(reg_info, msg->payload.reg_rw.data,
				rw->size, rw->reg_offset, 0);
		rw->size = count;
		msg->size += count;
		return 0;
	}

	memcpy(&msg->payload.reg_rw.data,
		(uint8_t *)reg_info->base + rw->reg_offset, rw->size);
	msg->size += rw->size;
	return 0;
}

static int
vfio_user_region_write(struct vfio_user_server *dev,
	struct vfio_user_msg *msg)
{
	struct vfio_user_reg_rw *rw = &msg->payload.reg_rw;
	struct rte_vfio_user_regions *reg = dev->reg;
	struct rte_vfio_user_reg_info *reg_info;
	size_t count;

	if (vfio_user_check_msg_fdnum(msg, 0) != 0)
		return -EINVAL;

	if (rw->reg_idx >= reg->reg_num) {
		VFIO_USER_LOG(ERR, "Write a non-existed region\n");
		return -EINVAL;
	}

	reg_info = &reg->reg_info[rw->reg_idx];

	VFIO_USER_LOG(DEBUG, "Write Region(%u): offset(0x%" PRIx64 "),"
		"size(0x%x)\n", rw->reg_idx, rw->reg_offset, rw->size);

	if (reg_info->rw) {
		count = reg_info->rw(reg_info, msg->payload.reg_rw.data,
				rw->size, rw->reg_offset, 1);
		if (count < rw->size) {
			VFIO_USER_LOG(ERR, "Write region %d failed\n",
				rw->reg_idx);
			return -EIO;
		}
		rw->size = 0;
		return 0;
	}

	memcpy((uint8_t *)reg_info->base + rw->reg_offset,
		&msg->payload.reg_rw.data, rw->size);
	rw->size = 0;
	return 0;
}

static inline void
vfio_user_destroy_mem_entries(struct rte_vfio_user_mem *mem)
{
	struct rte_vfio_user_mtb_entry *ent;
	uint32_t i;

	for (i = 0; i < mem->entry_num; i++) {
		ent = &mem->entry[i];
		if (ent->host_user_addr) {
			munmap(ent->mmap_addr, ent->mmap_size);
			close(ent->fd);
		}
	}

	memset(mem, 0, sizeof(*mem));
}

static inline void
vfio_user_destroy_mem(struct vfio_user_server *dev)
{
	struct rte_vfio_user_mem *mem = dev->mem;

	if (!mem)
		return;

	vfio_user_destroy_mem_entries(mem);

	free(mem);
	dev->mem = NULL;
}

static inline void
vfio_user_destroy_irq(struct vfio_user_server *dev)
{
	struct vfio_user_irqs *irq = &dev->irqs;
	int *fd;
	uint32_t i, j;

	if (!irq->info)
		return;

	for (i = 0; i < irq->info->irq_num; i++) {
		fd = irq->fds[i];

		for (j = 0; j < irq->info->irq_info[i].count; j++) {
			if (fd[j] != -1)
				close(fd[j]);
		}

		free(fd);
	}

	free(irq->fds);
}

static inline void
vfio_user_clean_irqfd(struct vfio_user_server *dev)
{
	struct vfio_user_irqs *irq = &dev->irqs;
	int *fd;
	uint32_t i, j;

	if (!irq->info)
		return;

	for (i = 0; i < irq->info->irq_num; i++) {
		fd = irq->fds[i];

		for (j = 0; j < irq->info->irq_info[i].count; j++) {
			close(fd[j]);
			fd[j] = -1;
		}
	}
}

static int
vfio_user_device_reset(struct vfio_user_server *dev,
	struct vfio_user_msg *msg)
{
	struct vfio_device_info *dev_info;

	if (vfio_user_check_msg_fdnum(msg, 0) != 0)
		return -EINVAL;

	dev_info = dev->dev_info;

	if (!(dev_info->flags & VFIO_DEVICE_FLAGS_RESET))
		return -ENOTSUP;

	vfio_user_destroy_mem_entries(dev->mem);
	vfio_user_clean_irqfd(dev);
	dev->is_ready = 0;

	if (dev->ops->reset_device)
		dev->ops->reset_device(dev->dev_id);

	return 0;
}

static vfio_user_msg_handler_t vfio_user_msg_handlers[VFIO_USER_MAX] = {
	[VFIO_USER_NONE] = NULL,
	[VFIO_USER_VERSION] = vfio_user_negotiate_version,
	[VFIO_USER_DMA_MAP] = vfio_user_dma_map,
	[VFIO_USER_DMA_UNMAP] = vfio_user_dma_unmap,
	[VFIO_USER_DEVICE_GET_INFO] = vfio_user_device_get_info,
	[VFIO_USER_DEVICE_GET_REGION_INFO] = vfio_user_device_get_reg_info,
	[VFIO_USER_DEVICE_GET_IRQ_INFO] = vfio_user_device_get_irq_info,
	[VFIO_USER_DEVICE_SET_IRQS] = vfio_user_device_set_irqs,
	[VFIO_USER_REGION_READ] = vfio_user_region_read,
	[VFIO_USER_REGION_WRITE] = vfio_user_region_write,
	[VFIO_USER_DMA_READ] = NULL,
	[VFIO_USER_DMA_WRITE] = NULL,
	[VFIO_USER_VM_INTERRUPT] = NULL,
	[VFIO_USER_DEVICE_RESET] = vfio_user_device_reset,
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

static inline int
vfio_user_is_ready(struct vfio_user_server *dev)
{
	/* vfio-user currently has no definition of when the device is ready.
	 * For now, we define it as when the device has at least one dma
	 * memory table entry.
	 */
	if (dev->mem->entry_num > 0) {
		dev->is_ready = 1;
		return 1;
	}

	return 0;
}

static int
vfio_user_message_handler(int dev_id, int fd)
{
	struct vfio_user_server *dev;
	struct vfio_user_msg msg;
	uint32_t cmd;
	int ret = 0;
	int dev_locked = 0;

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

	/*
	 * Below messages should lock the data path upon receiving
	 * to avoid errors in data path handling
	 */
	if ((cmd == VFIO_USER_DMA_MAP || cmd == VFIO_USER_DMA_UNMAP ||
		cmd == VFIO_USER_DEVICE_SET_IRQS ||
		cmd == VFIO_USER_DEVICE_RESET)
		&& dev->ops->lock_dp) {
		dev->ops->lock_dp(dev_id, 1);
		dev_locked = 1;
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

	if (!dev->is_ready) {
		if (vfio_user_is_ready(dev) && dev->ops->new_device)
			dev->ops->new_device(dev_id);
	} else {
		if ((cmd == VFIO_USER_DMA_MAP || cmd == VFIO_USER_DMA_UNMAP
			|| cmd == VFIO_USER_DEVICE_SET_IRQS)
			&& dev->ops->update_status)
			dev->ops->update_status(dev_id);
	}

handle_end:
	if (dev_locked)
		dev->ops->lock_dp(dev_id, 0);
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
		if (dev) {
			dev->ops->destroy_device(dev_id);
			vfio_user_destroy_mem_entries(dev->mem);
			vfio_user_clean_irqfd(dev);
			dev->is_ready = 0;
			dev->msg_id = 0;
		}
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

	/* All the info must be set before start */
	if (!dev->dev_info || !dev->reg || !dev->irqs.info) {
		VFIO_USER_LOG(ERR, "Failed to start, "
			"dev/reg/irq info must be set before start\n");
		return -1;
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
rte_vfio_user_register(const char *sock_addr,
	const struct rte_vfio_user_notify_ops *ops)
{
	struct vfio_user_server_socket *sk;
	struct vfio_user_server *dev;
	int dev_id;

	if (!sock_addr || !ops)
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

	dev->mem = malloc(sizeof(struct rte_vfio_user_mem));
	if (!dev->mem) {
		VFIO_USER_LOG(ERR, "Failed to alloc vfio_user_mem\n");
		goto err_mem;
	}
	memset(dev->mem, 0, sizeof(struct rte_vfio_user_mem));

	dev->ver.major = VFIO_USER_VERSION_MAJOR;
	dev->ver.minor = VFIO_USER_VERSION_MINOR;
	dev->ops = ops;
	dev->is_ready = 0;

	return 0;

err_mem:
	vfio_user_del_device(dev);
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
	vfio_user_destroy_mem(dev);
	vfio_user_destroy_irq(dev);
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

static struct vfio_user_server *
vfio_user_find_stopped_server(const char *sock_addr)
{
	struct vfio_user_server *dev;
	struct vfio_user_server_socket *sk;
	int dev_id;

	pthread_mutex_lock(&vfio_ep_sock.mutex);
	sk = vfio_user_find_socket(sock_addr);
	pthread_mutex_unlock(&vfio_ep_sock.mutex);

	if (!sk) {
		VFIO_USER_LOG(ERR, "Failed to find server with sock_addr "
			"%s: addr not registered.\n", sock_addr);
		return NULL;
	}

	dev_id = sk->sock.dev_id;
	dev = vfio_user_get_device(dev_id);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to find server: "
			"device %d not found.\n", dev_id);
		return NULL;
	}

	if (dev->started) {
		VFIO_USER_LOG(ERR, "Failed to find stopped server: "
			 "device %d already started\n", dev_id);
		return NULL;
	}

	return dev;
}

int
rte_vfio_user_set_dev_info(const char *sock_addr,
	struct vfio_device_info *dev_info)
{
	struct vfio_user_server *dev;

	if (!dev_info)
		return -1;

	dev = vfio_user_find_stopped_server(sock_addr);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to set device(%s) information: "
			"cannot find stopped server\n", sock_addr);
		return -1;
	}

	dev->dev_info = dev_info;

	return 0;
}

int
rte_vfio_user_set_reg_info(const char *sock_addr,
	struct rte_vfio_user_regions *reg)
{
	struct vfio_user_server *dev;

	if (!reg)
		return -1;

	dev = vfio_user_find_stopped_server(sock_addr);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to set region information for "
			"device with sock(%s): cannot find stopped server\n",
			sock_addr);
		return -1;
	}

	dev->reg = reg;

	return 0;
}

int
rte_vfio_get_sock_addr(int dev_id, char *buf, size_t len)
{
	struct vfio_user_server *dev;

	dev = vfio_user_get_device(dev_id);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to get sock address:"
			"device %d not found.\n", dev_id);
		return -1;
	}

	len = len > sizeof(dev->sock_addr) ?
		sizeof(dev->sock_addr) : len;
	strncpy(buf, dev->sock_addr, len);
	buf[len - 1] = '\0';

	return 0;
}

const struct rte_vfio_user_mem *
rte_vfio_user_get_mem_table(int dev_id)
{
	struct vfio_user_server *dev;

	dev = vfio_user_get_device(dev_id);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to get memory table:"
			"device %d not found.\n", dev_id);
		return NULL;
	}

	if (!dev->mem) {
		VFIO_USER_LOG(ERR, "Failed to get memory table for device %d:"
			"memory table not allocated.\n", dev_id);
		return NULL;
	}

	return dev->mem;
}

int
rte_vfio_user_get_irq(int dev_id, uint32_t index, uint32_t count, int *fds)
{
	struct vfio_user_server *dev;
	struct vfio_user_irqs *irqs;
	uint32_t irq_max;

	dev = vfio_user_get_device(dev_id);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to get irq info:"
			"device %d not found.\n", dev_id);
		return -1;
	}

	if (!fds)
		return -1;

	irqs = &dev->irqs;
	if (index >= irqs->info->irq_num)
		return -1;

	irq_max = irqs->info->irq_info[index].count;
	if (count > irq_max)
		return -1;

	memcpy(fds, dev->irqs.fds[index], count * sizeof(int));
	return 0;
}

int
rte_vfio_user_set_irq_info(const char *sock_addr,
	struct rte_vfio_user_irq_info *irq)
{
	struct vfio_user_server *dev;
	struct vfio_user_server_socket *sk;
	uint32_t i;
	int dev_id, ret;

	if (!irq)
		return -1;

	pthread_mutex_lock(&vfio_ep_sock.mutex);
	sk = vfio_user_find_socket(sock_addr);
	pthread_mutex_unlock(&vfio_ep_sock.mutex);

	if (!sk) {
		VFIO_USER_LOG(ERR, "Failed to set irq info with sock_addr:"
			"%s: addr not registered.\n", sock_addr);
		return -1;
	}

	dev_id = sk->sock.dev_id;
	dev = vfio_user_get_device(dev_id);
	if (!dev) {
		VFIO_USER_LOG(ERR, "Failed to set irq info:"
			"device %d not found.\n", dev_id);
		return -1;
	}

	if (dev->started) {
		VFIO_USER_LOG(ERR, "Failed to set irq info for device %d\n"
			 ", device already started\n", dev_id);
		return -1;
	}

	if (dev->irqs.info)
		vfio_user_destroy_irq(dev);

	dev->irqs.info = irq;

	dev->irqs.fds = malloc(irq->irq_num * sizeof(int *));
	if (!dev->irqs.fds)
		return -1;

	for (i = 0; i < irq->irq_num; i++) {
		uint32_t sz = irq->irq_info[i].count * sizeof(int);
		dev->irqs.fds[i] = malloc(sz);
		if (!dev->irqs.fds[i]) {
			ret = -1;
			goto exit;
		}

		memset(dev->irqs.fds[i], 0xFF, sz);
	}

	return 0;
exit:
	for (--i;; i--) {
		free(dev->irqs.fds[i]);
		if (i == 0)
			break;
	}
	free(dev->irqs.fds);
	return ret;
}

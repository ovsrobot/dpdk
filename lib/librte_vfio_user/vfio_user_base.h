/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _VFIO_USER_BASE_H
#define _VFIO_USER_BASE_H

#include <rte_log.h>

#include "rte_vfio_user.h"

#define VFIO_USER_MSG_MAX_NREG 8
#define VFIO_USER_VERSION_MAJOR 1
#define VFIO_USER_VERSION_MINOR 0
#define VFIO_USER_MAX_RSVD 512
#define VFIO_USER_MAX_RW_DATA 512
#define VFIO_USER_MAX_FD 1024
#define VFIO_USER_MAX_VERSION_DATA 512

extern int vfio_user_log_level;
extern const char *vfio_user_msg_str[];

#define VFIO_USER_LOG(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, vfio_user_log_level,		\
	"VFIO_USER: " fmt, ## args)

struct vfio_user_socket {
	char *sock_addr;
	int sock_fd;
	int dev_id;
};

typedef enum VFIO_USER_CMD_TYPE {
	VFIO_USER_NONE = 0,
	VFIO_USER_VERSION = 1,
	VFIO_USER_DMA_MAP = 2,
	VFIO_USER_DMA_UNMAP = 3,
	VFIO_USER_DEVICE_GET_INFO = 4,
	VFIO_USER_DEVICE_GET_REGION_INFO = 5,
	VFIO_USER_DEVICE_GET_IRQ_INFO = 6,
	VFIO_USER_DEVICE_SET_IRQS = 7,
	VFIO_USER_REGION_READ = 8,
	VFIO_USER_REGION_WRITE = 9,
	VFIO_USER_DMA_READ = 10,
	VFIO_USER_DMA_WRITE = 11,
	VFIO_USER_VM_INTERRUPT = 12,
	VFIO_USER_DEVICE_RESET = 13,
	VFIO_USER_MAX = 14,
} VFIO_USER_CMD_TYPE;

struct vfio_user_version {
	uint16_t major;
	uint16_t minor;
	/* Version data (JSON), for now not supported */
	uint8_t ver_data[VFIO_USER_MAX_VERSION_DATA];
};

struct vfio_user_reg {
	struct vfio_region_info reg_info;
	/* Reserved for region capability list */
	uint8_t rsvd[VFIO_USER_MAX_RSVD];
};

struct vfio_user_irq_set {
	struct vfio_irq_set set;
	/* Reserved for data of irq set */
	uint8_t rsvd[VFIO_USER_MAX_RSVD];
};

struct vfio_user_reg_rw {
	uint64_t reg_offset;
	uint32_t reg_idx;
	uint32_t size;
	char data[VFIO_USER_MAX_RW_DATA];
};

struct vfio_user_msg {
	uint16_t msg_id;
	uint16_t cmd;
	uint32_t size;
#define VFIO_USER_TYPE_CMD	(0x0)		/* Message type is COMMAND */
#define VFIO_USER_TYPE_REPLY	(0x1 << 0)	/* Message type is REPLY */
#define VFIO_USER_NEED_NO_RP	(0x1 << 4)	/* Message needs no reply */
#define VFIO_USER_ERROR		(0x1 << 5)	/* Reply message has error */
	uint32_t flags;
	uint32_t err;				/* Valid in reply, optional */
	union {
		struct vfio_user_version ver;
		struct rte_vfio_user_mem_reg memory[VFIO_USER_MSG_MAX_NREG];
		struct vfio_device_info dev_info;
		struct vfio_user_reg reg_info;
		struct vfio_irq_info irq_info;
		struct vfio_user_irq_set irq_set;
		struct vfio_user_reg_rw reg_rw;
	} payload;
	int fds[VFIO_USER_MAX_FD];
	int fd_num;
};

#define VFIO_USER_MSG_HDR_SIZE offsetof(struct vfio_user_msg, payload.ver)

void vfio_user_close_msg_fds(struct vfio_user_msg *msg);
int vfio_user_check_msg_fdnum(struct vfio_user_msg *msg, int expected_fds);
void vfio_user_close_msg_fds(struct vfio_user_msg *msg);
int vfio_user_recv_msg(int sockfd, struct vfio_user_msg *msg);
int vfio_user_send_msg(int sockfd, struct vfio_user_msg *msg);
int vfio_user_reply_msg(int sockfd, struct vfio_user_msg *msg);

#endif

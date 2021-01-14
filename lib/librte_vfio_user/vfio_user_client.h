/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _VFIO_USER_CLIENT_H
#define _VFIO_USER_CLIENT_H

#include <stdint.h>

#include "vfio_user_base.h"

#define MAX_VFIO_USER_CLIENT 1024

struct vfio_user_client {
	struct vfio_user_socket sock;
	uint16_t msg_id;
	uint8_t rsvd[16];	/* Reserved for future use */
};

struct vfio_user_client_devs {
	struct vfio_user_client *cl[MAX_VFIO_USER_CLIENT];
	uint32_t cl_num;
	pthread_mutex_t mutex;
};

#endif

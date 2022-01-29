/*    INTEL CONFIDENTIAL
 *
 *    Copyright (c) Intel Corporation.
 *    All rights reserved.
 *
 *    The source code contained or described herein and all documents related
 *    to the source code ("Material") are owned by Intel Corporation or its
 *    suppliers or licensors.  Title to the Material remains with Intel
 *    Corporation or its suppliers and licensors.  The Material contains trade
 *    secrets and proprietary and confidential information of Intel or its
 *    suppliers and licensors.  The Material is protected by worldwide
 *    copyright and trade secret laws and treaty provisions.  No part of the
 *    Material may be used, copied, reproduced, modified, published, uploaded,
 *    posted, transmitted, distributed, or disclosed in any way without Intel's
 *    prior express written permission.
 *
 *    No license under any patent, copyright, trade secret or other
 *    intellectual property right is granted to or conferred upon you by
 *    disclosure or delivery of the Materials, either expressly, by
 *    implication, inducement, estoppel or otherwise.  Any license under such
 *    intellectual property rights must be express and approved by Intel in
 *    writing.
 */

/* @file
 *
 * Block device specific vhost lib
 */

#include <stdbool.h>

#include <rte_malloc.h>
#include <vdpa_driver.h>
#include <rte_vhost.h>
#include "vdpa_blk_compact.h"
#include "vhost_user.h"

#define VHOST_USER_GET_CONFIG	24
#define VHOST_USER_SET_CONFIG	25

#ifndef VHOST_USER_PROTOCOL_F_CONFIG
#define VHOST_USER_PROTOCOL_F_CONFIG   9
#endif

/*
 * Function to handle vhost user blk message
 */
static enum rte_vhost_msg_result
rte_vhost_blk_extern_vhost_pre_msg_handler(int vid, void *_msg)
{
	struct VhostUserMsg *msg = _msg;
	struct rte_vdpa_device *vdev = NULL;

	vdev = rte_vhost_get_vdpa_device(vid);
	if (vdev == NULL)
		return RTE_VHOST_MSG_RESULT_ERR;

	fprintf(stderr, "msg is %d\n", msg->request.master);
	switch (msg->request.master) {
	case VHOST_USER_GET_CONFIG: {
		int rc = 0;

		fprintf(stdout, "read message VHOST_USER_GET_CONFIG\n");

		if (vdev->ops->get_config) {
			fprintf(stdout, "get_config() function is valid!\n");
			rc = vdev->ops->get_config(vid,
						   msg->payload.cfg.region,
						   msg->payload.cfg.size);
			if (rc != 0) {
				msg->size = 0;
				fprintf(stdout, "get_config() return error!\n");
			}
		} else {
			fprintf(stdout, "get_config() function is invalid!\n");
		}

		return RTE_VHOST_MSG_RESULT_REPLY;
	}
	case VHOST_USER_SET_CONFIG: {
		int rc = 0;

		fprintf(stdout,
			"read message VHOST_USER_SET_CONFIG\n");

		if (vdev->ops->set_config) {
			rc = vdev->ops->set_config(vid,
				msg->payload.cfg.region,
				msg->payload.cfg.offset,
				msg->payload.cfg.size,
				msg->payload.cfg.flags);
		}

		return rc == 0 ? RTE_VHOST_MSG_RESULT_OK : RTE_VHOST_MSG_RESULT_ERR;
	}
	default:
		break;
	}

	return RTE_VHOST_MSG_RESULT_NOT_HANDLED;
}

struct rte_vhost_user_extern_ops g_blk_extern_vhost_ops = {
	.pre_msg_handle = rte_vhost_blk_extern_vhost_pre_msg_handler,
	.post_msg_handle = NULL,
};

int
rte_vhost_blk_session_install_rte_compat_hooks(int vid)
{
	int rc;

	rc = rte_vhost_extern_callback_register(vid,
						&g_blk_extern_vhost_ops,
						NULL);
	if (rc != 0) {
		fprintf(stderr, "%s() failed for vid = %d\n",  __func__, vid);
		return -1;
	}
	fprintf(stdout, "register extern vhost ops on vid = %d\n", vid);
	return 0;
}


int
vdpa_blk_device_set_features_and_protocol(const char *path,
	struct rte_vdpa_device *vdev)
{
	uint64_t protocol_features = 0;

	if (!vdev) {
		fprintf(stdout, "vdev is NULL.\n");
		return -EINVAL;
	}

	/* vdpa net does not have the get_config */
	if (!vdev->ops->get_config)
		return 0;

	rte_vhost_driver_set_features(path, SPDK_VHOST_BLK_FEATURES_BASE);
	rte_vhost_driver_disable_features(path,
		SPDK_VHOST_BLK_DISABLED_FEATURES);

	rte_vhost_driver_get_protocol_features(path, &protocol_features);
	protocol_features |= (1ULL << VHOST_USER_PROTOCOL_F_CONFIG);
	protocol_features |= (1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD);
	rte_vhost_driver_set_protocol_features(path, protocol_features);

	return 0;
}

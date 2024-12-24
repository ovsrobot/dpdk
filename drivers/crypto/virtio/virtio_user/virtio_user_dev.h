/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Marvell.
 */

#ifndef _VIRTIO_USER_DEV_H
#define _VIRTIO_USER_DEV_H

#include <limits.h>
#include <stdbool.h>

#include "../virtio_pci.h"
#include "../virtio_ring.h"

extern struct virtio_user_backend_ops virtio_crypto_ops_vdpa;

enum virtio_user_backend_type {
	VIRTIO_USER_BACKEND_UNKNOWN,
	VIRTIO_USER_BACKEND_VHOST_USER,
	VIRTIO_USER_BACKEND_VHOST_VDPA,
};

struct virtio_user_queue {
	uint16_t used_idx;
	bool avail_wrap_counter;
	bool used_wrap_counter;
};

struct virtio_user_dev {
	union {
		struct virtio_crypto_hw hw;
		uint8_t dummy[256];
	};

	void		*backend_data;
	uint16_t	**notify_area;
	char		path[PATH_MAX];
	bool		hw_cvq;
	uint16_t	max_queue_pairs;
	uint64_t	device_features; /* supported features by device */
	bool		*qp_enabled;

	enum virtio_user_backend_type backend_type;
	bool		is_server;  /* server or client mode */

	int		*callfds;
	int		*kickfds;
	uint16_t	queue_pairs;
	uint32_t	queue_size;
	uint64_t	features; /* the negotiated features with driver,
				   * and will be sync with device
				   */
	uint64_t	frontend_features; /* enabled frontend features */
	uint64_t	unsupported_features; /* unsupported features mask */
	uint8_t		status;
	uint32_t	crypto_status;
	uint32_t	crypto_services;
	uint64_t	cipher_algo;
	uint32_t	hash_algo;
	uint64_t	auth_algo;
	uint32_t	aead_algo;
	uint32_t	akcipher_algo;

	union {
		void			*ptr;
		struct vring		*split;
		struct vring_packed	*packed;
	} vrings;

	struct virtio_user_queue *packed_queues;

	struct virtio_user_backend_ops *ops;
	pthread_mutex_t	mutex;
	bool		started;

	struct virtqueue	*scvq;
};

int crypto_virtio_user_dev_set_features(struct virtio_user_dev *dev);
int crypto_virtio_user_start_device(struct virtio_user_dev *dev);
int crypto_virtio_user_stop_device(struct virtio_user_dev *dev);
int crypto_virtio_user_dev_init(struct virtio_user_dev *dev, char *path, uint16_t queues,
			int queue_size, int server);
void crypto_virtio_user_dev_uninit(struct virtio_user_dev *dev);
int crypto_virtio_user_dev_set_status(struct virtio_user_dev *dev, uint8_t status);
int crypto_virtio_user_dev_update_status(struct virtio_user_dev *dev);
int crypto_virtio_user_dev_update_link_state(struct virtio_user_dev *dev);
extern const char * const crypto_virtio_user_backend_strings[];
#endif

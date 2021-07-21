/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2020 Intel Corporation
 */

#ifndef _IOAT_H_
#define _IOAT_H_

#include <rte_vhost.h>
#include <rte_pci.h>
#include <rte_vhost_async.h>

#define MAX_VHOST_DEVICE 1024
#define IOAT_RING_SIZE 4096
#define MAX_ENQUEUED_SIZE 4096
#define MAX_RING_COUNT	2
#define ASYNC_ENQUEUE_VHOST	1
#define ASYNC_DEQUEUE_VHOST	2

struct dma_info {
	struct rte_pci_addr addr;
	uint16_t dev_id;
	bool is_valid;
};

struct dma_for_vhost {
	int async_flag;
	struct dma_info dmas[RTE_MAX_QUEUES_PER_PORT * 2];
	uint16_t nr;
};

#ifdef RTE_RAW_IOAT
int open_ioat(const char *value);

uint32_t
ioat_transfer_data_cb(int vid, uint16_t queue_id,
		struct rte_vhost_async_desc *descs,
		struct rte_vhost_async_status *opaque_data, uint16_t count);

uint32_t
ioat_check_completed_copies_cb(int vid, uint16_t queue_id,
		struct rte_vhost_async_status *opaque_data,
		uint16_t max_packets);

uint32_t get_async_flag_by_vid(int vid);
uint32_t get_async_flag_by_socketid(int socketid);
void init_vid2socketid_array(int vid, int socketid);
#else
static int open_ioat(const char *value __rte_unused)
{
	return -1;
}

static uint32_t
ioat_transfer_data_cb(int vid __rte_unused, uint16_t queue_id __rte_unused,
		struct rte_vhost_async_desc *descs __rte_unused,
		struct rte_vhost_async_status *opaque_data __rte_unused,
		uint16_t count __rte_unused)
{
	return -1;
}

static uint32_t
ioat_check_completed_copies_cb(int vid __rte_unused,
		uint16_t queue_id __rte_unused,
		struct rte_vhost_async_status *opaque_data __rte_unused,
		uint16_t max_packets __rte_unused)
{
	return -1;
}

static uint32_t
get_async_flag_by_vid(int vid __rte_unused)
{
	return 0;
}

static uint32_t
get_async_flag_by_socketid(int socketid __rte_unused)
{
	return 0;
}

static void
init_vid2socketid_array(int vid __rte_unused, int socketid __rte_unused)
{
}
#endif
#endif /* _IOAT_H_ */

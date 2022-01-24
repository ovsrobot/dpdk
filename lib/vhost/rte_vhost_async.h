/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_VHOST_ASYNC_H_
#define _RTE_VHOST_ASYNC_H_

#include "rte_vhost.h"

/**
 * iovec
 */
struct rte_vhost_iovec {
	void *src_addr;
	void *dst_addr;
	size_t len;
};

/**
 * iovec iterator
 */
struct rte_vhost_iov_iter {
	/** pointer to the iovec array */
	struct rte_vhost_iovec *iov;
	/** number of iovec in this iterator */
	unsigned long nr_segs;
};

/**
 * Register an async channel for a vhost queue
 *
 * @param vid
 *  vhost device id async channel to be attached to
 * @param queue_id
 *  vhost queue id async channel to be attached to
 * @return
 *  0 on success, -1 on failures
 */
__rte_experimental
int rte_vhost_async_channel_register(int vid, uint16_t queue_id);

/**
 * Unregister an async channel for a vhost queue
 *
 * @param vid
 *  vhost device id async channel to be detached from
 * @param queue_id
 *  vhost queue id async channel to be detached from
 * @return
 *  0 on success, -1 on failures
 */
__rte_experimental
int rte_vhost_async_channel_unregister(int vid, uint16_t queue_id);

/**
 * Register an async channel for a vhost queue without performing any
 * locking
 *
 * @note This function does not perform any locking, and is only safe to
 *       call in vhost callback functions.
 *
 * @param vid
 *  vhost device id async channel to be attached to
 * @param queue_id
 *  vhost queue id async channel to be attached to
 * @return
 *  0 on success, -1 on failures
 */
__rte_experimental
int rte_vhost_async_channel_register_thread_unsafe(int vid, uint16_t queue_id);

/**
 * Unregister an async channel for a vhost queue without performing any
 * locking
 *
 * @note This function does not perform any locking, and is only safe to
 *       call in vhost callback functions.
 *
 * @param vid
 *  vhost device id async channel to be detached from
 * @param queue_id
 *  vhost queue id async channel to be detached from
 * @return
 *  0 on success, -1 on failures
 */
__rte_experimental
int rte_vhost_async_channel_unregister_thread_unsafe(int vid,
		uint16_t queue_id);

/**
 * This function submits enqueue packets to async copy engine. Users
 * need to poll transfer status by rte_vhost_poll_enqueue_completed()
 * for successfully enqueued packets.
 *
 * @param vid
 *  id of vhost device to enqueue data
 * @param queue_id
 *  queue id to enqueue data
 * @param pkts
 *  array of packets to be enqueued
 * @param count
 *  packets num to be enqueued
 * @param dma_id
 *  the identifier of the DMA device
 * @param vchan_id
 *  the identifier of virtual DMA channel
 * @return
 *  num of packets enqueued
 */
__rte_experimental
uint16_t rte_vhost_submit_enqueue_burst(int vid, uint16_t queue_id,
		struct rte_mbuf **pkts, uint16_t count, int16_t dma_id,
		uint16_t vchan_id);

/**
 * This function checks async completion status for a specific vhost
 * device queue. Packets which finish copying (enqueue) operation
 * will be returned in an array.
 *
 * @param vid
 *  id of vhost device to enqueue data
 * @param queue_id
 *  queue id to enqueue data
 * @param pkts
 *  blank array to get return packet pointer
 * @param count
 *  size of the packet array
 * @param dma_id
 *  the identifier of the DMA device
 * @param vchan_id
 *  the identifier of virtual DMA channel
 * @return
 *  num of packets returned
 */
__rte_experimental
uint16_t rte_vhost_poll_enqueue_completed(int vid, uint16_t queue_id,
		struct rte_mbuf **pkts, uint16_t count, int16_t dma_id,
		uint16_t vchan_id);

/**
 * This function returns the amount of in-flight packets for the vhost
 * queue which uses async channel acceleration.
 *
 * @param vid
 *  id of vhost device to enqueue data
 * @param queue_id
 *  queue id to enqueue data
 * @return
 *  the amount of in-flight packets on success; -1 on failure
 */
__rte_experimental
int rte_vhost_async_get_inflight(int vid, uint16_t queue_id);

/**
 * This function checks async completion status and clear packets for
 * a specific vhost device queue. Packets which are inflight will be
 * returned in an array.
 *
 * @note This function does not perform any locking
 *
 * @param vid
 *  ID of vhost device to clear data
 * @param queue_id
 *  Queue id to clear data
 * @param pkts
 *  Blank array to get return packet pointer
 * @param count
 *  Size of the packet array
 * @param dma_id
 *  the identifier of the DMA device
 * @param vchan_id
 *  the identifier of virtual DMA channel
 * @return
 *  Number of packets returned
 */
__rte_experimental
uint16_t rte_vhost_clear_queue_thread_unsafe(int vid, uint16_t queue_id,
		struct rte_mbuf **pkts, uint16_t count, int16_t dma_id,
		uint16_t vchan_id);
/**
 * The DMA vChannels used in asynchronous data path must be configured
 * first. So this function needs to be called before enabling DMA
 * acceleration for vring. If this function fails, asynchronous data path
 * cannot be enabled for any vring further.
 *
 * DMA devices used in data-path must belong to DMA devices given in this
 * function. But users are free to use DMA devices given in the function
 * in non-vhost scenarios, only if guarantee no copies in vhost are
 * offloaded to them at the same time.
 *
 * @param dmas_id
 *  DMA ID array
 * @param count
 *  Element number of 'dmas_id'
 * @param poll_factor
 *  For large or scatter-gather packets, one packet would consist of
 *  small buffers. In this case, vhost will issue several DMA copy
 *  operations for the packet. Therefore, the number of copies to
 *  check by rte_dma_completed() is calculated by "nb_pkts_to_poll *
 *  poll_factor" andused in rte_vhost_poll_enqueue_completed(). The
 *  default value of "poll_factor" is 1.
 * @return
 *  0 on success, and -1 on failure
 */
__rte_experimental
int rte_vhost_async_dma_configure(int16_t *dmas_id, uint16_t count,
		uint16_t poll_factor);

#endif /* _RTE_VHOST_ASYNC_H_ */

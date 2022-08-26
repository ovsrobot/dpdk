/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018, Microsoft Corporation.
 * All Rights Reserved.
 */

#ifndef _VMBUS_H_
#define _VMBUS_H_

/**
 * @file
 *
 * VMBUS Interface
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>

#include <rte_compat.h>
#include <rte_uuid.h>
#include <rte_debug.h>
#include <rte_interrupts.h>
#include <rte_vmbus_reg.h>

/* Forward declarations */
struct rte_vmbus_device;
struct rte_vmbus_driver;
struct vmbus_channel;

/**
 * Scan the content of the VMBUS bus, and the devices in the devices
 * list
 *
 * @return
 *  0 on success, negative on error
 */
int rte_vmbus_scan(void);

/**
 * Probe the VMBUS bus
 *
 * @return
 *   - 0 on success.
 *   - !0 on error.
 */
int rte_vmbus_probe(void);

/**
 * Map the VMBUS device resources in user space virtual memory address
 *
 * @param dev
 *   A pointer to a rte_vmbus_device structure describing the device
 *   to use
 *
 * @return
 *   0 on success, negative on error and positive if no driver
 *   is found for the device.
 */
int rte_vmbus_map_device(struct rte_vmbus_device *dev);

/**
 * Unmap this device
 *
 * @param dev
 *   A pointer to a rte_vmbus_device structure describing the device
 *   to use
 */
void rte_vmbus_unmap_device(struct rte_vmbus_device *dev);

/**
 * Get connection to primary VMBUS channel
 *
 * @param device
 *   A pointer to a rte_vmbus_device structure describing the device
 * @param chan
 *   A pointer to a VMBUS channel pointer that will be filled.
 * @return
 *   - 0 Success; channel opened.
 *   - -ENOMEM: Not enough memory available.
 *   - -EINVAL: Regions could not be mapped.
 */
int rte_vmbus_chan_open(struct rte_vmbus_device *device,
			struct vmbus_channel **chan);

/**
 * Free connection to VMBUS channel
 *
 * @param chan
 *    VMBUS channel
 */
void rte_vmbus_chan_close(struct vmbus_channel *chan);

/**
 * Gets the maximum number of channels supported on device
 *
 * @param device
 *   A pointer to a rte_vmbus_device structure describing the device
 * @return
 *   Number of channels available.
 */
int rte_vmbus_max_channels(const struct rte_vmbus_device *device);

/**
 * Get a connection to new secondary vmbus channel
 *
 * @param primary
 *   A pointer to primary VMBUS channel
 * @param chan
 *   A pointer to a secondary VMBUS channel pointer that will be filled.
 * @return
 *   - 0 Success; channel opened.
 *   - -ENOMEM: Not enough memory available.
 *   - -EINVAL: Regions could not be mapped.
 */
int rte_vmbus_subchan_open(struct vmbus_channel *primary,
			   struct vmbus_channel **new_chan);

/**
 * Disable IRQ for device
 *
 * @param device
 *    VMBUS device
 */
void rte_vmbus_irq_mask(struct rte_vmbus_device *device);

/**
 * Enable IRQ for device
 *
 * @param device
 *    VMBUS device
 */
void rte_vmbus_irq_unmask(struct rte_vmbus_device *device);

/**
 * Read (and wait) for IRQ
 *
 * @param device
 *    VMBUS device
 */
int rte_vmbus_irq_read(struct rte_vmbus_device *device);

/**
 * Test if channel is empty
 *
 * @param channel
 *	Pointer to vmbus_channel structure.
 * @return
 *	Return true if no data present in incoming ring.
 */
bool rte_vmbus_chan_rx_empty(const struct vmbus_channel *channel);

/**
 * Send the specified buffer on the given channel
 *
 * @param channel
 *	Pointer to vmbus_channel structure.
 * @param type
 *	Type of packet that is being send e.g. negotiate, time
 *	packet etc.
 * @param data
 *	Pointer to the buffer to send
 * @param dlen
 *	Number of bytes of data to send
 * @param xact
 *	Identifier of the request
 * @param flags
 *	Message type inband, rxbuf, gpa
 * @param need_sig
 *	Is host signal tx is required (optional)
 *
 * Sends data in buffer directly to hyper-v via the vmbus
 */
int rte_vmbus_chan_send(struct vmbus_channel *channel, uint16_t type,
			void *data, uint32_t dlen,
			uint64_t xact, uint32_t flags, bool *need_sig);

/**
 * Explicitly signal host that data is available
 *
 * @param
 *	Pointer to vmbus_channel structure.
 *
 * Used when batching multiple sends and only signaling host
 * after the last send.
 */
void rte_vmbus_chan_signal_tx(const struct vmbus_channel *channel);

/* Structure for scatter/gather I/O */
struct iova_list {
	rte_iova_t	addr;
	uint32_t	len;
};
#define MAX_PAGE_BUFFER_COUNT		32

/**
 * Send a scattered buffer on the given channel
 *
 * @param channel
 *	Pointer to vmbus_channel structure.
 * @param type
 *	Type of packet that is being send e.g. negotiate, time
 *	packet etc.
 * @param gpa
 *	Array of buffers to send
 * @param gpacnt
 *	Number of elements in iov
 * @param data
 *	Pointer to the buffer additional data to send
 * @param dlen
 *	 Maximum size of what the buffer will hold
 * @param xact
 *	Identifier of the request
 * @param flags
 *	Message type inband, rxbuf, gpa
 * @param need_sig
 *	Is host signal tx is required (optional)
 *
 * Sends data in buffer directly to hyper-v via the vmbus
 */
int rte_vmbus_chan_send_sglist(struct vmbus_channel *channel,
			       struct vmbus_gpa gpa[], uint32_t gpacnt,
			       void *data, uint32_t dlen,
			       uint64_t xact, bool *need_sig);
/**
 * Receive response to request on the given channel
 * skips the channel header.
 *
 * @param channel
 *	Pointer to vmbus_channel structure.
 * @param data
 *	Pointer to the buffer you want to receive the data into.
 * @param len
 *	Pointer to size of receive buffer (in/out)
 * @param
 *	Pointer to received transaction_id
 * @return
 *   On success, returns 0
 *   On failure, returns negative errno.
 */
int rte_vmbus_chan_recv(struct vmbus_channel *chan,
			void *data, uint32_t *len,
			uint64_t *request_id);

/**
 * Receive response to request on the given channel
 * includes the channel header.
 *
 * @param channel
 *	Pointer to vmbus_channel structure.
 * @param data
 *	Pointer to the buffer you want to receive the data into.
 * @param len
 *	Pointer to size of receive buffer (in/out)
 * @return
 *   On success, returns number of bytes read.
 *   On failure, returns negative errno.
 */
int rte_vmbus_chan_recv_raw(struct vmbus_channel *chan,
			    void *data, uint32_t *len);

/**
 * Notify host of bytes read (after recv_raw)
 * Signals host if required.
 *
 * @param channel
 *	Pointer to vmbus_channel structure.
 * @param bytes_read
 *	Number of bytes read since last signal
 */
void rte_vmbus_chan_signal_read(struct vmbus_channel *chan, uint32_t bytes_read);

/**
 * Determine sub channel index of the given channel
 *
 * @param channel
 *	Pointer to vmbus_channel structure.
 * @return
 *   Sub channel index (0 for primary)
 */
uint16_t rte_vmbus_sub_channel_index(const struct vmbus_channel *chan);

/**
 * Set the host monitor latency hint
 *
 * @param dev
 *    VMBUS device
 * @param chan
 *	Pointer to vmbus_channel structure.
 * @param latency
 *	Approximate wait period between hypervisor examinations of
 *	the trigger page (in nanoseconds).
 */
void rte_vmbus_set_latency(const struct rte_vmbus_device *dev,
			   const struct vmbus_channel *chan,
			   uint32_t latency);

/**
 * For debug dump contents of ring buffer.
 *
 * @param channel
 *	Pointer to vmbus_channel structure.
 */
void rte_vmbus_chan_dump(FILE *f, const struct vmbus_channel *chan);

#ifdef __cplusplus
}
#endif

#endif /* _VMBUS_H_ */

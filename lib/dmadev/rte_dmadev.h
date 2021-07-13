/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 HiSilicon Limited.
 * Copyright(c) 2021 Intel Corporation.
 * Copyright(c) 2021 Marvell International Ltd.
 * Copyright(c) 2021 SmartShare Systems.
 */

#ifndef _RTE_DMADEV_H_
#define _RTE_DMADEV_H_

/**
 * @file rte_dmadev.h
 *
 * RTE DMA (Direct Memory Access) device APIs.
 *
 * The DMA framework is built on the following model:
 *
 *     ---------------   ---------------       ---------------
 *     | virtual DMA |   | virtual DMA |       | virtual DMA |
 *     | channel     |   | channel     |       | channel     |
 *     ---------------   ---------------       ---------------
 *            |                |                      |
 *            ------------------                      |
 *                     |                              |
 *               ------------                    ------------
 *               |  dmadev  |                    |  dmadev  |
 *               ------------                    ------------
 *                     |                              |
 *            ------------------               ------------------
 *            | HW-DMA-channel |               | HW-DMA-channel |
 *            ------------------               ------------------
 *                     |                              |
 *                     --------------------------------
 *                                     |
 *                           ---------------------
 *                           | HW-DMA-Controller |
 *                           ---------------------
 *
 * The DMA controller could have multiple HW-DMA-channels (aka. HW-DMA-queues),
 * each HW-DMA-channel should be represented by a dmadev.
 *
 * The dmadev could create multiple virtual DMA channel, each virtual DMA
 * channel represents a different transfer context. The DMA operation request
 * must be submitted to the virtual DMA channel.
 * E.G. Application could create virtual DMA channel 0 for mem-to-mem transfer
 *      scenario, and create virtual DMA channel 1 for mem-to-dev transfer
 *      scenario.
 *
 * The dmadev are dynamically allocated by rte_dmadev_pmd_allocate() during the
 * PCI/SoC device probing phase performed at EAL initialization time. And could
 * be released by rte_dmadev_pmd_release() during the PCI/SoC device removing
 * phase.
 *
 * This framework uses 'uint16_t dev_id' as the device identifier of a dmadev,
 * and 'uint16_t vchan' as the virtual DMA channel identifier in one dmadev.
 *
 * The functions exported by the dmadev API to setup a device designated by its
 * device identifier must be invoked in the following order:
 *     - rte_dmadev_configure()
 *     - rte_dmadev_vchan_setup()
 *     - rte_dmadev_start()
 *
 * Then, the application can invoke dataplane APIs to process jobs.
 *
 * If the application wants to change the configuration (i.e. call
 * rte_dmadev_configure()), it must call rte_dmadev_stop() first to stop the
 * device and then do the reconfiguration before calling rte_dmadev_start()
 * again. The dataplane APIs should not be invoked when the device is stopped.
 *
 * Finally, an application can close a dmadev by invoking the
 * rte_dmadev_close() function.
 *
 * The dataplane APIs include two parts:
 *   a) The first part is the submission of operation requests:
 *        - rte_dmadev_copy()
 *        - rte_dmadev_copy_sg() - scatter-gather form of copy
 *        - rte_dmadev_fill()
 *        - rte_dmadev_fill_sg() - scatter-gather form of fill
 *        - rte_dmadev_perform() - issue doorbell to hardware
 *      These APIs could work with different virtual DMA channels which have
 *      different contexts.
 *      The first four APIs are used to submit the operation request to the
 *      virtual DMA channel, if the submission is successful, a uint16_t
 *      ring_idx is returned, otherwise a negative number is returned.
 *   b) The second part is to obtain the result of requests:
 *        - rte_dmadev_completed()
 *            - return the number of operation requests completed successfully.
 *        - rte_dmadev_completed_fails()
 *            - return the number of operation requests failed to complete.
 *
 * About the ring_idx which rte_dmadev_copy/copy_sg/fill/fill_sg() returned,
 * the rules are as follows:
 *   a) ring_idx for each virtual DMA channel are independent.
 *   b) For a virtual DMA channel, the ring_idx is monotonically incremented,
 *      when it reach UINT16_MAX, it wraps back to zero.
 *   c) This ring_idx can be used by applications to track per-operation
 *      metadata in an application-defined circular ring.
 *   d) The initial ring_idx of a virtual DMA channel is zero, after the device
 *      is stopped, the ring_idx needs to be reset to zero.
 *   Example:
 *      step-1: start one dmadev
 *      step-2: enqueue a copy operation, the ring_idx return is 0
 *      step-3: enqueue a copy operation again, the ring_idx return is 1
 *      ...
 *      step-101: stop the dmadev
 *      step-102: start the dmadev
 *      step-103: enqueue a copy operation, the cookie return is 0
 *      ...
 *      step-x+0: enqueue a fill operation, the ring_idx return is 65535
 *      step-x+1: enqueue a copy operation, the ring_idx return is 0
 *      ...
 *
 * By default, all the functions of the dmadev API exported by a PMD are
 * lock-free functions which assume to not be invoked in parallel on different
 * logical cores to work on the same target object.
 *
 */

#include <rte_common.h>
#include <rte_compat.h>
#ifdef RTE_DMADEV_DEBUG
#include <rte_dev.h>
#endif
#include <rte_errno.h>
#include <rte_memory.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_DMADEV_NAME_MAX_LEN	RTE_DEV_NAME_MAX_LEN

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * @param dev_id
 *   DMA device index.
 *
 * @return
 *   - If the device index is valid (true) or not (false).
 */
__rte_experimental
bool
rte_dmadev_is_valid_dev(uint16_t dev_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get the total number of DMA devices that have been successfully
 * initialised.
 *
 * @return
 *   The total number of usable DMA devices.
 */
__rte_experimental
uint16_t
rte_dmadev_count(void);

/**
 * The capabilities of a DMA device
 */
#define RTE_DMA_DEV_CAPA_MEM_TO_MEM	(1ull << 0)
/**< DMA device support memory-to-memory transfer.
 *
 * @see struct rte_dmadev_info::dev_capa
 */
#define RTE_DMA_DEV_CAPA_MEM_TO_DEV	(1ull << 1)
/**< DMA device support memory-to-device transfer.
 *
 * @see struct rte_dmadev_info::dev_capa
 */
#define RTE_DMA_DEV_CAPA_DEV_TO_MEM	(1ull << 2)
/**< DMA device support device-to-memory transfer.
 *
 * @see struct rte_dmadev_info::dev_capa
 */
#define RTE_DMA_DEV_CAPA_DEV_TO_DEV	(1ull << 3)
/**< DMA device support device-to-device transfer.
 *
 * @see struct rte_dmadev_info::dev_capa
 */
#define RTE_DMA_DEV_CAPA_OPS_COPY	(1ull << 4)
/**< DMA device support copy ops.
 *
 * @see struct rte_dmadev_info::dev_capa
 */
#define RTE_DMA_DEV_CAPA_OPS_FILL	(1ull << 5)
/**< DMA device support fill ops.
 *
 * @see struct rte_dmadev_info::dev_capa
 */
#define RTE_DMA_DEV_CAPA_OPS_SG		(1ull << 6)
/**< DMA device support scatter-list ops.
 * If device support ops_copy and ops_sg, it means supporting copy_sg ops.
 *
 * @see struct rte_dmadev_info::dev_capa
 */
#define RTE_DMA_DEV_CAPA_FENCE		(1ull << 7)
/**< DMA device support fence.
 * If device support fence, then application could set a fence flags when
 * enqueue operation by rte_dma_copy/copy_sg/fill/fill_sg.
 * If a operation has a fence flags, it means the operation must be processed
 * only after all previous operations are completed.
 *
 * @see struct rte_dmadev_info::dev_capa
 */
#define RTE_DMA_DEV_CAPA_SVA		(1ull << 8)
/**< DMA device support SVA which could use VA as DMA address.
 * If device support SVA then application could pass any VA address like memory
 * from rte_malloc(), rte_memzone(), malloc, stack memory.
 * If device don't support SVA, then application should pass IOVA address which
 * from rte_malloc(), rte_memzone().
 *
 * @see struct rte_dmadev_info::dev_capa
 */

/**
 * A structure used to retrieve the contextual information of
 * an DMA device
 */
struct rte_dmadev_info {
	struct rte_device *device; /**< Generic Device information */
	uint64_t dev_capa; /**< Device capabilities (RTE_DMA_DEV_CAPA_*) */
	/** Maximum number of virtual DMA channels supported */
	uint16_t max_vchans;
	/** Maximum allowed number of virtual DMA channel descriptors */
	uint16_t max_desc;
	/** Minimum allowed number of virtual DMA channel descriptors */
	uint16_t min_desc;
	uint16_t nb_vchans; /**< Number of virtual DMA channel configured */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Retrieve the contextual information of a DMA device.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param[out] dev_info
 *   A pointer to a structure of type *rte_dmadev_info* to be filled with the
 *   contextual information of the device.
 *
 * @return
 *   - =0: Success, driver updates the contextual information of the DMA device
 *   - <0: Error code returned by the driver info get function.
 *
 */
__rte_experimental
int
rte_dmadev_info_get(uint16_t dev_id, struct rte_dmadev_info *dev_info);

/**
 * A structure used to configure a DMA device.
 */
struct rte_dmadev_conf {
	/** Maximum number of virtual DMA channel to use.
	 * This value cannot be greater than the field 'max_vchans' of struct
	 * rte_dmadev_info which get from rte_dmadev_info_get().
	 */
	uint16_t max_vchans;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Configure a DMA device.
 *
 * This function must be invoked first before any other function in the
 * API. This function can also be re-invoked when a device is in the
 * stopped state.
 *
 * @param dev_id
 *   The identifier of the device to configure.
 * @param dev_conf
 *   The DMA device configuration structure encapsulated into rte_dmadev_conf
 *   object.
 *
 * @return
 *   - =0: Success, device configured.
 *   - <0: Error code returned by the driver configuration function.
 */
__rte_experimental
int
rte_dmadev_configure(uint16_t dev_id, const struct rte_dmadev_conf *dev_conf);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Start a DMA device.
 *
 * The device start step is the last one and consists of setting the DMA
 * to start accepting jobs.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   - =0: Success, device started.
 *   - <0: Error code returned by the driver start function.
 */
__rte_experimental
int
rte_dmadev_start(uint16_t dev_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Stop a DMA device.
 *
 * The device can be restarted with a call to rte_dmadev_start()
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   - =0: Success, device stopped.
 *   - <0: Error code returned by the driver stop function.
 */
__rte_experimental
int
rte_dmadev_stop(uint16_t dev_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Close a DMA device.
 *
 * The device cannot be restarted after this call.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *  - =0: Successfully close device
 *  - <0: Failure to close device
 */
__rte_experimental
int
rte_dmadev_close(uint16_t dev_id);

/**
 * DMA transfer direction defines.
 */
#define RTE_DMA_MEM_TO_MEM	(1ull << 0)
/**< DMA transfer direction - from memory to memory.
 *
 * @see struct rte_dmadev_vchan_conf::direction
 */
#define RTE_DMA_MEM_TO_DEV	(1ull << 1)
/**< DMA transfer direction - from memory to device.
 * In a typical scenario, ARM SoCs are installed on x86 servers as iNICs
 * through the PCIE interface. In this case, the ARM SoCs works in EP(endpoint)
 * mode, it could initiate a DMA move request from memory (which is ARM memory)
 * to device (which is x86 host memory).
 *
 * @see struct rte_dmadev_vchan_conf::direction
 */
#define RTE_DMA_DEV_TO_MEM	(1ull << 2)
/**< DMA transfer direction - from device to memory.
 * In a typical scenario, ARM SoCs are installed on x86 servers as iNICs
 * through the PCIE interface. In this case, the ARM SoCs works in EP(endpoint)
 * mode, it could initiate a DMA move request from device (which is x86 host
 * memory) to memory (which is ARM memory).
 *
 * @see struct rte_dmadev_vchan_conf::direction
 */
#define RTE_DMA_DEV_TO_DEV	(1ull << 3)
/**< DMA transfer direction - from device to device.
 * In a typical scenario, ARM SoCs are installed on x86 servers as iNICs
 * through the PCIE interface. In this case, the ARM SoCs works in EP(endpoint)
 * mode, it could initiate a DMA move request from device (which is x86 host
 * memory) to device (which is another x86 host memory).
 *
 * @see struct rte_dmadev_vchan_conf::direction
 */
#define RTE_DMA_TRANSFER_DIR_ALL	(RTE_DMA_MEM_TO_MEM | \
					 RTE_DMA_MEM_TO_DEV | \
					 RTE_DMA_DEV_TO_MEM | \
					 RTE_DMA_DEV_TO_DEV)

/**
 * enum rte_dmadev_port_type - DMA port type defines
 * When
 */
enum rte_dmadev_port_type {
	/** The device port type is PCIE. */
	RTE_DMADEV_PORT_OF_PCIE = 1,
};

/**
 * A structure used to descript DMA port parameters.
 */
struct rte_dmadev_port_parameters {
	enum rte_dmadev_port_type port_type;
	union {
		/** For PCIE port
		 *
		 * The following model show SoC's PCIE module connects to
		 * multiple PCIE hosts and multiple endpoints. The PCIE module
		 * has an integrate DMA controller.
		 * If the DMA wants to access the memory of host A, it can be
		 * initiated by PF1 in core0, or by VF0 of PF0 in core0.
		 *
		 * System Bus
		 *    |     ----------PCIE module----------
		 *    |     Bus
		 *    |     Interface
		 *    |     -----        ------------------
		 *    |     |   |        | PCIE Core0     |
		 *    |     |   |        |                |        -----------
		 *    |     |   |        |   PF-0 -- VF-0 |        | Host A  |
		 *    |     |   |--------|        |- VF-1 |--------| Root    |
		 *    |     |   |        |   PF-1         |        | Complex |
		 *    |     |   |        |   PF-2         |        -----------
		 *    |     |   |        ------------------
		 *    |     |   |
		 *    |     |   |        ------------------
		 *    |     |   |        | PCIE Core1     |
		 *    |     |   |        |                |        -----------
		 *    |     |   |        |   PF-0 -- VF-0 |        | Host B  |
		 *    |-----|   |--------|   PF-1 -- VF-0 |--------| Root    |
		 *    |     |   |        |        |- VF-1 |        | Complex |
		 *    |     |   |        |   PF-2         |        -----------
		 *    |     |   |        ------------------
		 *    |     |   |
		 *    |     |   |        ------------------
		 *    |     |DMA|        |                |        ------
		 *    |     |   |        |                |--------| EP |
		 *    |     |   |--------| PCIE Core2     |        ------
		 *    |     |   |        |                |        ------
		 *    |     |   |        |                |--------| EP |
		 *    |     |   |        |                |        ------
		 *    |     -----        ------------------
		 *
		 * The following structure is used to describe the above access
		 * port.
		 */
		struct {
			uint64_t coreid : 3; /**< PCIE core id used */
			uint64_t pfid : 6; /**< PF id used */
			uint64_t vfen : 1; /**< VF enable bit */
			uint64_t vfid : 8; /**< VF id used */
			/** The pasid filed in TLP packet */
			uint64_t pasid : 20;
			/** The attributes filed in TLP packet */
			uint64_t attr : 3;
			/** The processing hint filed in TLP packet */
			uint64_t ph : 2;
			/** The steering tag filed in TLP packet */
			uint64_t st : 16;
		} pcie;
	};
	uint64_t reserved[2]; /**< Reserved for future fields */
};

/**
 * A structure used to configure a virtual DMA channel.
 */
struct rte_dmadev_vchan_conf {
	uint8_t direction;
	/**< Set of supported transfer directions
	 * @see RTE_DMA_MEM_TO_MEM
	 * @see RTE_DMA_MEM_TO_DEV
	 * @see RTE_DMA_DEV_TO_MEM
	 * @see RTE_DMA_DEV_TO_DEV
	 */
	/** Number of descriptor for the virtual DMA channel */
	uint16_t nb_desc;
	/** 1) Used to describes the port parameter in the device-to-memory
	 * transfer scenario.
	 * 2) Used to describes the source port parameter in the
	 * device-to-device transfer scenario.
	 * @see struct rte_dmadev_port_parameters
	 */
	struct rte_dmadev_port_parameters src_port;
	/** 1) Used to describes the port parameter in the memory-to-device-to
	 * transfer scenario.
	 * 2) Used to describes the destination port parameter in the
	 * device-to-device transfer scenario.
	 * @see struct rte_dmadev_port_parameters
	 */
	struct rte_dmadev_port_parameters dst_port;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate and set up a virtual DMA channel.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param conf
 *   The virtual DMA channel configuration structure encapsulated into
 *   rte_dmadev_vchan_conf object.
 *
 * @return
 *   - >=0: Allocate success, it is the virtual DMA channel id. This value must
 *          be less than the field 'max_vchans' of struct rte_dmadev_conf
 *          which configured by rte_dmadev_configure().
 *   - <0: Error code returned by the driver virtual channel setup function.
 */
__rte_experimental
int
rte_dmadev_vchan_setup(uint16_t dev_id,
		       const struct rte_dmadev_vchan_conf *conf);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Release a virtual DMA channel.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel which return by vchan setup.
 *
 * @return
 *   - =0: Successfully release the virtual DMA channel.
 *   - <0: Error code returned by the driver virtual channel release function.
 */
__rte_experimental
int
rte_dmadev_vchan_release(uint16_t dev_id, uint16_t vchan);

/**
 * rte_dmadev_stats - running statistics.
 */
struct rte_dmadev_stats {
	/** Count of operations which were successfully enqueued */
	uint64_t enqueued_count;
	/** Count of operations which were submitted to hardware */
	uint64_t submitted_count;
	/** Count of operations which failed to complete */
	uint64_t completed_fail_count;
	/** Count of operations which successfully complete */
	uint64_t completed_count;
};

#define RTE_DMADEV_ALL_VCHAN	0xFFFFu

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Retrieve basic statistics of a or all virtual DMA channel(s).
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 *   If equal RTE_DMADEV_ALL_VCHAN means all channels.
 * @param[out] stats
 *   The basic statistics structure encapsulated into rte_dmadev_stats
 *   object.
 *
 * @return
 *   - =0: Successfully retrieve stats.
 *   - <0: Failure to retrieve stats.
 */
__rte_experimental
int
rte_dmadev_stats_get(uint16_t dev_id, uint16_t vchan,
		     struct rte_dmadev_stats *stats);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Reset basic statistics of a or all virtual DMA channel(s).
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 *   If equal RTE_DMADEV_ALL_VCHAN means all channels.
 *
 * @return
 *   - =0: Successfully reset stats.
 *   - <0: Failure to reset stats.
 */
__rte_experimental
int
rte_dmadev_stats_reset(uint16_t dev_id, uint16_t vchan);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Dump DMA device info.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param f
 *   The file to write the output to.
 *
 * @return
 *   0 on success. Non-zero otherwise.
 */
__rte_experimental
int
rte_dmadev_dump(uint16_t dev_id, FILE *f);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Trigger the dmadev self test.
 *
 * @param dev_id
 *   The identifier of the device.
 *
 * @return
 *   - 0: Selftest successful.
 *   - -ENOTSUP if the device doesn't support selftest
 *   - other values < 0 on failure.
 */
__rte_experimental
int
rte_dmadev_selftest(uint16_t dev_id);

/**
 * rte_dma_sge - can hold scatter DMA operation request entry
 */
struct rte_dma_sge {
	rte_iova_t addr;
	uint32_t length;
};

/**
 * rte_dma_sg - can hold scatter DMA operation request
 */
struct rte_dma_sg {
	struct rte_dma_sge *src;
	struct rte_dma_sge *dst;
	uint16_t nb_src; /**< The number of src entry */
	uint16_t nb_dst; /**< The number of dst entry */
};

#include "rte_dmadev_core.h"

/**
 *  DMA flags to augment operation preparation.
 *  Used as the 'flags' parameter of rte_dmadev_copy/fill.
 */
#define RTE_DMA_OP_FLAG_FENCE	(1ull << 0)
/**< DMA fence flag
 * It means the operation with this flag must be processed only after all
 * previous operations are completed.
 *
 * @see rte_dmadev_copy()
 * @see rte_dmadev_copy_sg()
 * @see rte_dmadev_fill()
 */
#define RTE_DMA_OP_FLAG_SUBMIT	(1ull << 1)
/**< DMA submit flag
 * It means the operation with this flag must issue doorbell to hardware after
 * enqueued jobs.
 */

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Enqueue a copy operation onto the virtual DMA channel.
 *
 * This queues up a copy operation to be performed by hardware, but does not
 * trigger hardware to begin that operation.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 * @param src
 *   The address of the source buffer.
 * @param dst
 *   The address of the destination buffer.
 * @param length
 *   The length of the data to be copied.
 * @param flags
 *   An flags for this operation.
 *   @see RTE_DMA_OP_FLAG_*
 *
 * @return
 *   - 0..UINT16_MAX: index of enqueued copy job.
 *   - <0: Error code returned by the driver copy function.
 */
__rte_experimental
static inline int
rte_dmadev_copy(uint16_t dev_id, uint16_t vchan, rte_iova_t src, rte_iova_t dst,
		uint32_t length, uint64_t flags)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
#ifdef RTE_DMADEV_DEBUG
	if (!rte_dmadev_is_valid_dev(dev_id) ||
	    vchan >= dev->data->dev_conf.max_vchans)
		return -EINVAL;
	RTE_FUNC_PTR_OR_ERR_RET(*dev->copy, -ENOTSUP);
#endif
	return (*dev->copy)(dev, vchan, src, dst, length, flags);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Enqueue a scatter list copy operation onto the virtual DMA channel.
 *
 * This queues up a scatter list copy operation to be performed by hardware,
 * but does not trigger hardware to begin that operation.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 * @param sg
 *   The pointer of scatterlist.
 * @param flags
 *   An flags for this operation.
 *   @see RTE_DMA_OP_FLAG_*
 *
 * @return
 *   - 0..UINT16_MAX: index of enqueued copy scatterlist job.
 *   - <0: Error code returned by the driver copy scatterlist function.
 */
__rte_experimental
static inline int
rte_dmadev_copy_sg(uint16_t dev_id, uint16_t vchan, const struct rte_dma_sg *sg,
		   uint64_t flags)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
#ifdef RTE_DMADEV_DEBUG
	if (!rte_dmadev_is_valid_dev(dev_id) ||
	    vchan >= dev->data->dev_conf.max_vchans ||
	    sg == NULL)
		return -EINVAL;
	RTE_FUNC_PTR_OR_ERR_RET(*dev->copy_sg, -ENOTSUP);
#endif
	return (*dev->copy_sg)(dev, vchan, sg, flags);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Enqueue a fill operation onto the virtual DMA channel.
 *
 * This queues up a fill operation to be performed by hardware, but does not
 * trigger hardware to begin that operation.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 * @param pattern
 *   The pattern to populate the destination buffer with.
 * @param dst
 *   The address of the destination buffer.
 * @param length
 *   The length of the destination buffer.
 * @param flags
 *   An flags for this operation.
 *   @see RTE_DMA_OP_FLAG_*
 *
 * @return
 *   - 0..UINT16_MAX: index of enqueued fill job.
 *   - <0: Error code returned by the driver fill function.
 */
__rte_experimental
static inline int
rte_dmadev_fill(uint16_t dev_id, uint16_t vchan, uint64_t pattern,
		rte_iova_t dst, uint32_t length, uint64_t flags)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
#ifdef RTE_DMADEV_DEBUG
	if (!rte_dmadev_is_valid_dev(dev_id) ||
	    vchan >= dev->data->dev_conf.max_vchans)
		return -EINVAL;
	RTE_FUNC_PTR_OR_ERR_RET(*dev->fill, -ENOTSUP);
#endif
	return (*dev->fill)(dev, vchan, pattern, dst, length, flags);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Trigger hardware to begin performing enqueued operations.
 *
 * This API is used to write the "doorbell" to the hardware to trigger it
 * to begin the operations previously enqueued by rte_dmadev_copy/fill()
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 *
 * @return
 *   - =0: Successfully trigger hardware.
 *   - <0: Failure to trigger hardware.
 */
__rte_experimental
static inline int
rte_dmadev_submit(uint16_t dev_id, uint16_t vchan)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
#ifdef RTE_DMADEV_DEBUG
	if (!rte_dmadev_is_valid_dev(dev_id) ||
	    vchan >= dev->data->dev_conf.max_vchans)
		return -EINVAL;
	RTE_FUNC_PTR_OR_ERR_RET(*dev->submit, -ENOTSUP);
#endif
	return (*dev->submit)(dev, vchan);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Returns the number of operations that have been successfully completed.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 * @param nb_cpls
 *   The maximum number of completed operations that can be processed.
 * @param[out] last_idx
 *   The last completed operation's index.
 *   If not required, NULL can be passed in.
 * @param[out] has_error
 *   Indicates if there are transfer error.
 *   If not required, NULL can be passed in.
 *
 * @return
 *   The number of operations that successfully completed.
 */
__rte_experimental
static inline uint16_t
rte_dmadev_completed(uint16_t dev_id, uint16_t vchan, const uint16_t nb_cpls,
		     uint16_t *last_idx, bool *has_error)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
	uint16_t idx;
	bool err;

#ifdef RTE_DMADEV_DEBUG
	if (!rte_dmadev_is_valid_dev(dev_id) ||
	    vchan >= dev->data->dev_conf.max_vchans ||
	    nb_cpls == 0)
		return -EINVAL;
	RTE_FUNC_PTR_OR_ERR_RET(*dev->completed, -ENOTSUP);
#endif

	/* Ensure the pointer values are non-null to simplify drivers.
	 * In most cases these should be compile time evaluated, since this is
	 * an inline function.
	 * - If NULL is explicitly passed as parameter, then compiler knows the
	 *   value is NULL
	 * - If address of local variable is passed as parameter, then compiler
	 *   can know it's non-NULL.
	 */
	if (last_idx == NULL)
		last_idx = &idx;
	if (has_error == NULL)
		has_error = &err;

	*has_error = false;
	return (*dev->completed)(dev, vchan, nb_cpls, last_idx, has_error);
}

/**
 * DMA transfer status code defines
 */
enum rte_dma_status_code {
	/** The operation completed successfully */
	RTE_DMA_STATUS_SUCCESSFUL = 0,
	/** The operation failed to complete due active drop
	 * This is mainly used when processing dev_stop, allow outstanding
	 * requests to be completed as much as possible.
	 */
	RTE_DMA_STATUS_ACTIVE_DROP,
	/** The operation failed to complete due invalid source address */
	RTE_DMA_STATUS_INVALID_SRC_ADDR,
	/** The operation failed to complete due invalid destination address */
	RTE_DMA_STATUS_INVALID_DST_ADDR,
	/** The operation failed to complete due invalid length */
	RTE_DMA_STATUS_INVALID_LENGTH,
	/** The operation failed to complete due invalid opcode
	 * The DMA descriptor could have multiple format, which are
	 * distinguished by the opcode field.
	 */
	RTE_DMA_STATUS_INVALID_OPCODE,
	/** The operation failed to complete due bus err */
	RTE_DMA_STATUS_BUS_ERROR,
	/** The operation failed to complete due data poison */
	RTE_DMA_STATUS_DATA_POISION,
	/** The operation failed to complete due descriptor read error */
	RTE_DMA_STATUS_DESCRIPTOR_READ_ERROR,
	/** The operation failed to complete due device link error
	 * Used to indicates that the link error in the mem-to-dev/dev-to-mem/
	 * dev-to-dev transfer scenario.
	 */
	RTE_DMA_STATUS_DEV_LINK_ERROR,
	/** The operation failed to complete due unknown reason */
	RTE_DMA_STATUS_UNKNOWN,
	/** Driver specific status code offset
	 * Start status code for the driver to define its own error code.
	 */
	RTE_DMA_STATUS_DRV_SPECIFIC_OFFSET = 0x10000,
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Returns the number of operations that failed to complete.
 * NOTE: This API was used when rte_dmadev_completed has_error was set.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 * @param nb_status
 *   Indicates the size of status array.
 * @param[out] status
 *   The error code of operations that failed to complete.
 *   Some standard error code are described in 'enum rte_dma_status_code'
 *   @see rte_dma_status_code
 * @param[out] last_idx
 *   The last failed completed operation's index.
 *
 * @return
 *   The number of operations that failed to complete.
 */
__rte_experimental
static inline uint16_t
rte_dmadev_completed_fails(uint16_t dev_id, uint16_t vchan,
			   const uint16_t nb_status, uint32_t *status,
			   uint16_t *last_idx)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
#ifdef RTE_DMADEV_DEBUG
	if (!rte_dmadev_is_valid_dev(dev_id) ||
	    vchan >= dev->data->dev_conf.max_vchans ||
	    nb_status == 0 ||
	    status == NULL ||
	    last_idx == NULL)
		return -EINVAL;
	RTE_FUNC_PTR_OR_ERR_RET(*dev->completed_fails, -ENOTSUP);
#endif
	return (*dev->completed_fails)(dev, vchan, nb_status, status, last_idx);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_DMADEV_H_ */

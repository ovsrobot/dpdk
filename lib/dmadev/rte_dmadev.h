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
 * The dmadev could create multiple virtual DMA channels, each virtual DMA
 * channel represents a different transfer context. The DMA operation request
 * must be submitted to the virtual DMA channel. e.g. Application could create
 * virtual DMA channel 0 for memory-to-memory transfer scenario, and create
 * virtual DMA channel 1 for memory-to-device transfer scenario.
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
 * If the application wants to change the configuration (i.e. invoke
 * rte_dmadev_configure() or rte_dmadev_vchan_setup()), it must invoke
 * rte_dmadev_stop() first to stop the device and then do the reconfiguration
 * before invoking rte_dmadev_start() again. The dataplane APIs should not be
 * invoked when the device is stopped.
 *
 * Finally, an application can close a dmadev by invoking the
 * rte_dmadev_close() function.
 *
 * The dataplane APIs include two parts:
 * The first part is the submission of operation requests:
 *     - rte_dmadev_copy()
 *     - rte_dmadev_copy_sg()
 *     - rte_dmadev_fill()
 *     - rte_dmadev_submit()
 *
 * These APIs could work with different virtual DMA channels which have
 * different contexts.
 *
 * The first three APIs are used to submit the operation request to the virtual
 * DMA channel, if the submission is successful, a uint16_t ring_idx is
 * returned, otherwise a negative number is returned.
 *
 * The last API was used to issue doorbell to hardware, and also there are flags
 * (@see RTE_DMA_OP_FLAG_SUBMIT) parameter of the first three APIs could do the
 * same work.
 *
 * The second part is to obtain the result of requests:
 *     - rte_dmadev_completed()
 *         - return the number of operation requests completed successfully.
 *     - rte_dmadev_completed_status()
 *         - return the number of operation requests completed.
 *
 * @note If the dmadev works in silent mode (@see RTE_DMADEV_CAPA_SILENT),
 * application does not invoke the above two completed APIs.
 *
 * About the ring_idx which enqueue APIs (e.g. rte_dmadev_copy()
 * rte_dmadev_fill()) returned, the rules are as follows:
 *     - ring_idx for each virtual DMA channel are independent.
 *     - For a virtual DMA channel, the ring_idx is monotonically incremented,
 *       when it reach UINT16_MAX, it wraps back to zero.
 *     - This ring_idx can be used by applications to track per-operation
 *       metadata in an application-defined circular ring.
 *     - The initial ring_idx of a virtual DMA channel is zero, after the
 *       device is stopped, the ring_idx needs to be reset to zero.
 *
 * One example:
 *     - step-1: start one dmadev
 *     - step-2: enqueue a copy operation, the ring_idx return is 0
 *     - step-3: enqueue a copy operation again, the ring_idx return is 1
 *     - ...
 *     - step-101: stop the dmadev
 *     - step-102: start the dmadev
 *     - step-103: enqueue a copy operation, the cookie return is 0
 *     - ...
 *     - step-x+0: enqueue a fill operation, the ring_idx return is 65535
 *     - step-x+1: enqueue a copy operation, the ring_idx return is 0
 *     - ...
 *
 * The DMA operation address used in enqueue APIs (i.e. rte_dmadev_copy(),
 * rte_dmadev_copy_sg(), rte_dmadev_fill()) defined as rte_iova_t type. The
 * dmadev supports two types of address: memory address and device address.
 *
 * - memory address: the source and destination address of the memory-to-memory
 * transfer type, or the source address of the memory-to-device transfer type,
 * or the destination address of the device-to-memory transfer type.
 * @note If the device support SVA (@see RTE_DMADEV_CAPA_SVA), the memory
 * address can be any VA address, otherwise it must be an IOVA address.
 *
 * - device address: the source and destination address of the device-to-device
 * transfer type, or the source address of the device-to-memory transfer type,
 * or the destination address of the memory-to-device transfer type.
 *
 * By default, all the functions of the dmadev API exported by a PMD are
 * lock-free functions which assume to not be invoked in parallel on different
 * logical cores to work on the same target dmadev object.
 * @note Different virtual DMA channels on the same dmadev *DO NOT* support
 * parallel invocation because these virtual DMA channels share the same
 * HW-DMA-channel.
 *
 */

#include <rte_common.h>
#include <rte_compat.h>
#include <rte_dev.h>
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
 * Get the device identifier for the named DMA device.
 *
 * @param name
 *   DMA device name.
 *
 * @return
 *   Returns DMA device identifier on success.
 *   - <0: Failure to find named DMA device.
 */
__rte_experimental
int
rte_dmadev_get_dev_id(const char *name);

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

/* Enumerates DMA device capabilities. */
#define RTE_DMADEV_CAPA_MEM_TO_MEM	(1ull << 0)
/**< DMA device support memory-to-memory transfer.
 *
 * @see struct rte_dmadev_info::dev_capa
 */

#define RTE_DMADEV_CAPA_MEM_TO_DEV	(1ull << 1)
/**< DMA device support memory-to-device transfer.
 *
 * @see struct rte_dmadev_info::dev_capa
 * @see struct rte_dmadev_port_param::port_type
 */

#define RTE_DMADEV_CAPA_DEV_TO_MEM	(1ull << 2)
/**< DMA device support device-to-memory transfer.
 *
 * @see struct rte_dmadev_info::dev_capa
 * @see struct rte_dmadev_port_param::port_type
 */

#define RTE_DMADEV_CAPA_DEV_TO_DEV	(1ull << 3)
/**< DMA device support device-to-device transfer.
 *
 * @see struct rte_dmadev_info::dev_capa
 * @see struct rte_dmadev_port_param::port_type
 */

#define RTE_DMADEV_CAPA_SVA		(1ull << 4)
/**< DMA device support SVA which could use VA as DMA address.
 * If device support SVA then application could pass any VA address like memory
 * from rte_malloc(), rte_memzone(), malloc, stack memory.
 * If device don't support SVA, then application should pass IOVA address which
 * from rte_malloc(), rte_memzone().
 *
 * @see struct rte_dmadev_info::dev_capa
 */

#define RTE_DMADEV_CAPA_SILENT		(1ull << 5)
/**< DMA device support work in silent mode.
 * In this mode, application don't required to invoke rte_dmadev_completed*()
 * API.
 *
 * @see struct rte_dmadev_conf::silent_mode
 */

#define RTE_DMADEV_CAPA_OPS_COPY	(1ull << 32)
/**< DMA device support copy ops.
 * This capability start with index of 32, so that it could leave gap between
 * normal capability and ops capability.
 *
 * @see struct rte_dmadev_info::dev_capa
 */

#define RTE_DMADEV_CAPA_OPS_COPY_SG	(1ull << 33)
/**< DMA device support scatter-list copy ops.
 *
 * @see struct rte_dmadev_info::dev_capa
 */

#define RTE_DMADEV_CAPA_OPS_FILL	(1ull << 34)
/**< DMA device support fill ops.
 *
 * @see struct rte_dmadev_info::dev_capa
 */

/**
 * A structure used to retrieve the information of a DMA device.
 */
struct rte_dmadev_info {
	struct rte_device *device; /**< Generic Device information. */
	uint64_t dev_capa; /**< Device capabilities (RTE_DMADEV_CAPA_*). */
	uint16_t max_vchans;
	/**< Maximum number of virtual DMA channels supported. */
	uint16_t max_desc;
	/**< Maximum allowed number of virtual DMA channel descriptors. */
	uint16_t min_desc;
	/**< Minimum allowed number of virtual DMA channel descriptors. */
	uint16_t nb_vchans; /**< Number of virtual DMA channel configured. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Retrieve information of a DMA device.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param[out] dev_info
 *   A pointer to a structure of type *rte_dmadev_info* to be filled with the
 *   information of the device.
 *
 * @return
 *   - =0: Success, driver updates the information of the DMA device.
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
	uint16_t max_vchans;
	/**< Maximum number of virtual DMA channel to use.
	 * This value cannot be greater than the field 'max_vchans' of struct
	 * rte_dmadev_info which get from rte_dmadev_info_get().
	 */
	bool enable_silent;
	/**< Indicates whether to enable silent mode.
	 * false-default mode, true-silent mode.
	 * This value can be set to true only when the SILENT capability is
	 * supported.
	 *
	 * @see RTE_DMADEV_CAPA_SILENT
	 */
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
 * The device can be restarted with a call to rte_dmadev_start().
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
 * rte_dma_direction - DMA transfer direction defines.
 */
enum rte_dma_direction {
	RTE_DMA_DIR_MEM_TO_MEM,
	/**< DMA transfer direction - from memory to memory.
	 *
	 * @see struct rte_dmadev_vchan_conf::direction
	 */
	RTE_DMA_DIR_MEM_TO_DEV,
	/**< DMA transfer direction - from memory to device.
	 * In a typical scenario, the SoCs are installed on host servers as
	 * iNICs through the PCIe interface. In this case, the SoCs works in
	 * EP(endpoint) mode, it could initiate a DMA move request from memory
	 * (which is SoCs memory) to device (which is host memory).
	 *
	 * @see struct rte_dmadev_vchan_conf::direction
	 */
	RTE_DMA_DIR_DEV_TO_MEM,
	/**< DMA transfer direction - from device to memory.
	 * In a typical scenario, the SoCs are installed on host servers as
	 * iNICs through the PCIe interface. In this case, the SoCs works in
	 * EP(endpoint) mode, it could initiate a DMA move request from device
	 * (which is host memory) to memory (which is SoCs memory).
	 *
	 * @see struct rte_dmadev_vchan_conf::direction
	 */
	RTE_DMA_DIR_DEV_TO_DEV,
	/**< DMA transfer direction - from device to device.
	 * In a typical scenario, the SoCs are installed on host servers as
	 * iNICs through the PCIe interface. In this case, the SoCs works in
	 * EP(endpoint) mode, it could initiate a DMA move request from device
	 * (which is host memory) to the device (which is another host memory).
	 *
	 * @see struct rte_dmadev_vchan_conf::direction
	 */
};

/**
 * enum rte_dmadev_port_type - DMA access port type defines.
 *
 * @see struct rte_dmadev_port_param::port_type
 */
enum rte_dmadev_port_type {
	RTE_DMADEV_PORT_NONE,
	RTE_DMADEV_PORT_PCIE, /**< The DMA access port is PCIe. */
};

/**
 * A structure used to descript DMA access port parameters.
 *
 * @see struct rte_dmadev_vchan_conf::src_port
 * @see struct rte_dmadev_vchan_conf::dst_port
 */
struct rte_dmadev_port_param {
	enum rte_dmadev_port_type port_type;
	/**< The device access port type.
	 * @see enum rte_dmadev_port_type
	 */
	union {
		/* The following model shows SoC's PCIe module connects to
		 * multiple PCIe hosts and multiple endpoints. The PCIe module
		 * has an integrate DMA controller.
		 * If the DMA wants to access the memory of host A, it can be
		 * initiated by PF1 in core0, or by VF0 of PF0 in core0.
		 *
		 * System Bus
		 *    |     ----------PCIe module----------
		 *    |     Bus
		 *    |     Interface
		 *    |     -----        ------------------
		 *    |     |   |        | PCIe Core0     |
		 *    |     |   |        |                |        -----------
		 *    |     |   |        |   PF-0 -- VF-0 |        | Host A  |
		 *    |     |   |--------|        |- VF-1 |--------| Root    |
		 *    |     |   |        |   PF-1         |        | Complex |
		 *    |     |   |        |   PF-2         |        -----------
		 *    |     |   |        ------------------
		 *    |     |   |
		 *    |     |   |        ------------------
		 *    |     |   |        | PCIe Core1     |
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
		 *    |     |   |--------| PCIe Core2     |        ------
		 *    |     |   |        |                |        ------
		 *    |     |   |        |                |--------| EP |
		 *    |     |   |        |                |        ------
		 *    |     -----        ------------------
		 */
		/** The following structure is used to describe the PCIe access
		 * port parameters.
		 *
		 * @note If some fields can not be supported by the
		 * hardware/driver, then the driver ignores those fields.
		 * Please check driver-specific documentation for limitations
		 * and capablites.
		 */
		struct {
			uint64_t coreid : 4; /**< PCIe core id used. */
			uint64_t pfid : 8; /**< PF id used. */
			uint64_t vfen : 1; /**< VF enable bit. */
			uint64_t vfid : 16; /**< VF id used. */
			uint64_t pasid : 20;
			/**< The pasid filed in TLP packet. */
			uint64_t attr : 3;
			/**< The attributes filed in TLP packet. */
			uint64_t ph : 2;
			/**< The processing hint filed in TLP packet. */
			uint64_t st : 16;
			/**< The steering tag filed in TLP packet. */
		} pcie;
	};
	uint64_t reserved[2]; /**< Reserved for future fields. */
};

/**
 * A structure used to configure a virtual DMA channel.
 */
struct rte_dmadev_vchan_conf {
	enum rte_dma_direction direction;
	/**< Transfer direction
	 * @see enum rte_dma_direction
	 */
	uint16_t nb_desc;
	/**< Number of descriptor for the virtual DMA channel */
	struct rte_dmadev_port_param src_port;
	/**< 1) Used to describes the device access port parameter in the
	 * device-to-memory transfer scenario.
	 * 2) Used to describes the source device access port parameter in the
	 * device-to-device transfer scenario.
	 * @see struct rte_dmadev_port_param
	 */
	struct rte_dmadev_port_param dst_port;
	/**< 1) Used to describes the device access port parameter in the
	 * memory-to-device transfer scenario.
	 * 2) Used to describes the destination device access port parameter in
	 * the device-to-device transfer scenario.
	 * @see struct rte_dmadev_port_param
	 */
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
 * rte_dmadev_stats - running statistics.
 */
struct rte_dmadev_stats {
	uint64_t submitted_count;
	/**< Count of operations which were submitted to hardware. */
	uint64_t completed_fail_count;
	/**< Count of operations which failed to complete. */
	uint64_t completed_count;
	/**< Count of operations which successfully complete. */
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
 * rte_dma_status_code - DMA transfer result status code defines.
 */
enum rte_dma_status_code {
	RTE_DMA_STATUS_SUCCESSFUL,
	/**< The operation completed successfully. */
	RTE_DMA_STATUS_USRER_ABORT,
	/**< The operation failed to complete due abort by user.
	 * This is mainly used when processing dev_stop, user could modidy the
	 * descriptors (e.g. change one bit to tell hardware abort this job),
	 * it allows outstanding requests to be complete as much as possible,
	 * so reduce the time to stop the device.
	 */
	RTE_DMA_STATUS_NOT_ATTEMPTED,
	/**< The operation failed to complete due to following scenarios:
	 * The jobs in a particular batch are not attempted because they
	 * appeared after a fence where a previous job failed. In some HW
	 * implementation it's possible for jobs from later batches would be
	 * completed, though, so report the status from the not attempted jobs
	 * before reporting those newer completed jobs.
	 */
	RTE_DMA_STATUS_INVALID_SRC_ADDR,
	/**< The operation failed to complete due invalid source address. */
	RTE_DMA_STATUS_INVALID_DST_ADDR,
	/**< The operation failed to complete due invalid destination
	 * address.
	 */
	RTE_DMA_STATUS_INVALID_LENGTH,
	/**< The operation failed to complete due invalid length. */
	RTE_DMA_STATUS_INVALID_OPCODE,
	/**< The operation failed to complete due invalid opcode.
	 * The DMA descriptor could have multiple format, which are
	 * distinguished by the opcode field.
	 */
	RTE_DMA_STATUS_BUS_ERROR,
	/**< The operation failed to complete due bus err. */
	RTE_DMA_STATUS_DATA_POISION,
	/**< The operation failed to complete due data poison. */
	RTE_DMA_STATUS_DESCRIPTOR_READ_ERROR,
	/**< The operation failed to complete due descriptor read error. */
	RTE_DMA_STATUS_DEV_LINK_ERROR,
	/**< The operation failed to complete due device link error.
	 * Used to indicates that the link error in the memory-to-device/
	 * device-to-memory/device-to-device transfer scenario.
	 */
	RTE_DMA_STATUS_UNKNOWN = 0x100,
	/**< The operation failed to complete due unknown reason.
	 * The initial value is 256, which reserves space for future errors.
	 */
};

/**
 * rte_dmadev_sge - can hold scatter DMA operation request entry.
 */
struct rte_dmadev_sge {
	rte_iova_t addr; /**< The DMA operation address. */
	uint32_t length; /**< The DMA operation length. */
};

#include "rte_dmadev_core.h"

/* DMA flags to augment operation preparation. */
#define RTE_DMA_OP_FLAG_FENCE	(1ull << 0)
/**< DMA fence flag.
 * It means the operation with this flag must be processed only after all
 * previous operations are completed.
 * If the specify DMA HW works in-order (it means it has default fence between
 * operations), this flag could be NOP.
 *
 * @see rte_dmadev_copy()
 * @see rte_dmadev_copy_sg()
 * @see rte_dmadev_fill()
 */

#define RTE_DMA_OP_FLAG_SUBMIT	(1ull << 1)
/**< DMA submit flag.
 * It means the operation with this flag must issue doorbell to hardware after
 * enqueued jobs.
 */

#define RTE_DMA_OP_FLAG_LLC	(1ull << 2)
/**< DMA write data to low level cache hint.
 * Used for performance optimization, this is just a hint, and there is no
 * capability bit for this, driver should not return error if this flag was set.
 */

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Enqueue a copy operation onto the virtual DMA channel.
 *
 * This queues up a copy operation to be performed by hardware, if the 'flags'
 * parameter contains RTE_DMA_OP_FLAG_SUBMIT then trigger doorbell to begin
 * this operation, otherwise do not trigger doorbell.
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
	    vchan >= dev->data->dev_conf.max_vchans ||
	    src == NULL || dst == NULL || length == 0)
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
 * This queues up a scatter list copy operation to be performed by hardware, if
 * the 'flags' parameter contains RTE_DMA_OP_FLAG_SUBMIT then trigger doorbell
 * to begin this operation, otherwise do not trigger doorbell.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 * @param src
 *   The pointer of source scatter entry array.
 * @param dst
 *   The pointer of destination scatter entry array.
 * @param nb_src
 *   The number of source scatter entry.
 * @param nb_dst
 *   The number of destination scatter entry.
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
rte_dmadev_copy_sg(uint16_t dev_id, uint16_t vchan, struct rte_dmadev_sge *src,
		   struct rte_dmadev_sge *dst, uint16_t nb_src, uint16_t nb_dst,
		   uint64_t flags)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];

#ifdef RTE_DMADEV_DEBUG
	if (!rte_dmadev_is_valid_dev(dev_id) ||
	    vchan >= dev->data->dev_conf.max_vchans ||
	    src == NULL || dst == NULL || nb_src == 0 || nb_dst == 0)
		return -EINVAL;
	RTE_FUNC_PTR_OR_ERR_RET(*dev->copy_sg, -ENOTSUP);
#endif

	return (*dev->copy_sg)(dev, vchan, src, dst, nb_src, nb_dst, flags);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Enqueue a fill operation onto the virtual DMA channel.
 *
 * This queues up a fill operation to be performed by hardware, if the 'flags'
 * parameter contains RTE_DMA_OP_FLAG_SUBMIT then trigger doorbell to begin
 * this operation, otherwise do not trigger doorbell.
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
	    vchan >= dev->data->dev_conf.max_vchans ||
	    dst == NULL || length == 0)
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
 * to begin the operations previously enqueued by rte_dmadev_copy/fill().
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
 *   The number of operations that successfully completed. This return value
 *   must be less than or equal to the value of nb_cpls.
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
		return 0;
	RTE_FUNC_PTR_OR_ERR_RET(*dev->completed, 0);
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
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Returns the number of operations that have been completed, and the
 * operations result may succeed or fail.
 *
 * @param dev_id
 *   The identifier of the device.
 * @param vchan
 *   The identifier of virtual DMA channel.
 * @param nb_cpls
 *   Indicates the size of status array.
 * @param[out] last_idx
 *   The last completed operation's index.
 *   If not required, NULL can be passed in.
 * @param[out] status
 *   The error code of operations that completed.
 *   @see enum rte_dma_status_code
 *
 * @return
 *   The number of operations that completed. This return value must be less
 *   than or equal to the value of nb_cpls.
 */
__rte_experimental
static inline uint16_t
rte_dmadev_completed_status(uint16_t dev_id, uint16_t vchan,
			    const uint16_t nb_cpls, uint16_t *last_idx,
			    enum rte_dma_status_code *status)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
	uint16_t idx;

#ifdef RTE_DMADEV_DEBUG
	if (!rte_dmadev_is_valid_dev(dev_id) ||
	    vchan >= dev->data->dev_conf.max_vchans ||
	    nb_cpls == 0 || status == NULL)
		return 0;
	RTE_FUNC_PTR_OR_ERR_RET(*dev->completed_status, 0);
#endif

	if (last_idx == NULL)
		last_idx = &idx;

	return (*dev->completed_status)(dev, vchan, nb_cpls, last_idx, status);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_DMADEV_H_ */

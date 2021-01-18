/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell.
 */
#ifndef _OTX_EP_COMMON_H_
#define _OTX_EP_COMMON_H_

#define OTX_EP_MAX_RINGS_PER_VF        (8)
#define OTX_EP_CFG_IO_QUEUES        OTX_EP_MAX_RINGS_PER_VF
#define OTX_EP_64BYTE_INSTR         (64)
#define OTX_EP_MIN_IQ_DESCRIPTORS   (128)
#define OTX_EP_MIN_OQ_DESCRIPTORS   (128)
#define OTX_EP_MAX_IQ_DESCRIPTORS   (8192)
#define OTX_EP_MAX_OQ_DESCRIPTORS   (8192)
#define OTX_EP_OQ_BUF_SIZE          (2048)
#define OTX_EP_MIN_RX_BUF_SIZE      (64)

#define OTX_EP_OQ_INFOPTR_MODE      (0)
#define OTX_EP_OQ_REFIL_THRESHOLD   (16)
#define OTX_EP_PCI_RING_ALIGN   65536
#define SDP_PKIND 40
#define SDP_OTX2_PKIND 57
#define OTX_EP_MAX_IOQS_PER_VF 8
#define otx_ep_printf(level, fmt, args...)		\
	rte_log(RTE_LOG_ ## level, RTE_LOGTYPE_PMD,		\
		 fmt, ##args)

#define otx_ep_info(fmt, args...)				\
	otx_ep_printf(INFO, fmt, ##args)

#define otx_ep_err(fmt, args...)				\
	otx_ep_printf(ERR, fmt, ##args)

#define otx_ep_dbg(fmt, args...)				\
	otx_ep_printf(DEBUG, fmt, ##args)

#define otx_ep_write64(value, base_addr, reg_off) \
	{\
	typeof(value) val = (value); \
	typeof(reg_off) off = (reg_off); \
	otx_ep_dbg("octeon_write_csr64: reg: 0x%08lx val: 0x%016llx\n", \
		   (unsigned long)off, (unsigned long long)val); \
	rte_write64(val, ((base_addr) + off)); \
	}

struct otx_ep_device;

/* Structure to define the configuration attributes for each Input queue. */
struct otx_ep_iq_config {
	/* Max number of IQs available */
	uint16_t max_iqs;

	/* Command size - 32 or 64 bytes */
	uint16_t instr_type;

	/* Pending list size, usually set to the sum of the size of all IQs */
	uint32_t pending_list_size;
};

/** Descriptor format.
 *  The descriptor ring is made of descriptors which have 2 64-bit values:
 *  -# Physical (bus) address of the data buffer.
 *  -# Physical (bus) address of a otx_ep_droq_info structure.
 *  The device DMA's incoming packets and its information at the address
 *  given by these descriptor fields.
 */
struct otx_ep_droq_desc {
	/* The buffer pointer */
	uint64_t buffer_ptr;

	/* The Info pointer */
	uint64_t info_ptr;
};
#define OTX_EP_DROQ_DESC_SIZE	(sizeof(struct otx_ep_droq_desc))

/* Receive Header */
union otx_ep_rh {
	uint64_t rh64;
};
#define OTX_EP_RH_SIZE (sizeof(union otx_ep_rh))

/** Information about packet DMA'ed by OCTEON TX2.
 *  The format of the information available at Info Pointer after OCTEON TX2
 *  has posted a packet. Not all descriptors have valid information. Only
 *  the Info field of the first descriptor for a packet has information
 *  about the packet.
 */
struct otx_ep_droq_info {
	/* The Length of the packet. */
	uint64_t length;

	/* The Output Receive Header. */
	union otx_ep_rh rh;
};
#define OTX_EP_DROQ_INFO_SIZE	(sizeof(struct otx_ep_droq_info))


/* DROQ statistics. Each output queue has four stats fields. */
struct otx_ep_droq_stats {
	/* Number of packets received in this queue. */
	uint64_t pkts_received;

	/* Bytes received by this queue. */
	uint64_t bytes_received;

	/* Num of failures of rte_pktmbuf_alloc() */
	uint64_t rx_alloc_failure;

	/* Rx error */
	uint64_t rx_err;

	/* packets with data got ready after interrupt arrived */
	uint64_t pkts_delayed_data;

	/* packets dropped due to zero length */
	uint64_t dropped_zlp;
};

/* Structure to define the configuration attributes for each Output queue. */
struct otx_ep_oq_config {
	/* Max number of OQs available */
	uint16_t max_oqs;

	/* If set, the Output queue uses info-pointer mode. (Default: 1 ) */
	uint16_t info_ptr;

	/** The number of buffers that were consumed during packet processing by
	 *  the driver on this Output queue before the driver attempts to
	 *  replenish the descriptor ring with new buffers.
	 */
	uint32_t refill_threshold;
};

/* The Descriptor Ring Output Queue(DROQ) structure. */
struct otx_ep_droq {
	struct otx_ep_device *otx_ep_dev;
	/* The 8B aligned descriptor ring starts at this address. */
	struct otx_ep_droq_desc *desc_ring;

	uint32_t q_no;
	uint64_t last_pkt_count;

	struct rte_mempool *mpool;

	/* Driver should read the next packet at this index */
	uint32_t read_idx;

	/* OCTEON TX2 will write the next packet at this index */
	uint32_t write_idx;

	/* At this index, the driver will refill the descriptor's buffer */
	uint32_t refill_idx;

	/* Packets pending to be processed */
	uint64_t pkts_pending;

	/* Number of descriptors in this ring. */
	uint32_t nb_desc;

	/* The number of descriptors pending to refill. */
	uint32_t refill_count;

	uint32_t refill_threshold;

	/* The 8B aligned info ptrs begin from this address. */
	struct otx_ep_droq_info *info_list;

	/* receive buffer list contains mbuf ptr list */
	struct rte_mbuf **recv_buf_list;

	/* The size of each buffer pointed by the buffer pointer. */
	uint32_t buffer_size;

	/* Statistics for this DROQ. */
	struct otx_ep_droq_stats stats;

	/* DMA mapped address of the DROQ descriptor ring. */
	size_t desc_ring_dma;

	/* Info_ptr list is allocated at this virtual address. */
	size_t info_base_addr;

	/* DMA mapped address of the info list */
	size_t info_list_dma;

	/* Allocated size of info list. */
	uint32_t info_alloc_size;

	/* Memory zone **/
	const struct rte_memzone *desc_ring_mz;
	const struct rte_memzone *info_mz;
};
#define OTX_EP_DROQ_SIZE		(sizeof(struct otx_ep_droq))

/* IQ/OQ mask */
struct otx_ep_io_enable {
	uint64_t iq;
	uint64_t oq;
	uint64_t iq64B;
};

/* Structure to define the configuration. */
struct otx_ep_config {
	/* Input Queue attributes. */
	struct otx_ep_iq_config iq;

	/* Output Queue attributes. */
	struct otx_ep_oq_config oq;

	/* Num of desc for IQ rings */
	uint32_t num_iqdef_descs;

	/* Num of desc for OQ rings */
	uint32_t num_oqdef_descs;

	/* OQ buffer size */
	uint32_t oqdef_buf_size;
};

/* Required functions for each VF device */
struct otx_ep_fn_list {
	void (*setup_oq_regs)(struct otx_ep_device *otx_ep, uint32_t q_no);

	int (*setup_device_regs)(struct otx_ep_device *otx_ep);

	void (*disable_io_queues)(struct otx_ep_device *otx_ep);
};

/* SRIOV information */
struct otx_ep_sriov_info {
	/* Number of rings assigned to VF */
	uint32_t rings_per_vf;

	/* Number of VF devices enabled */
	uint32_t num_vfs;
};

/* OTX_EP EP VF device data structure */
struct otx_ep_device {
	/* PCI device pointer */
	struct rte_pci_device *pdev;

	uint16_t chip_id;

	uint32_t pkind;

	struct rte_eth_dev *eth_dev;

	int port_id;

	/* Memory mapped h/w address */
	uint8_t *hw_addr;

	struct otx_ep_fn_list fn_list;

	uint32_t max_tx_queues;

	uint32_t max_rx_queues;

	/* Num OQs */
	uint32_t nb_rx_queues;

	/* The DROQ output queues  */
	struct otx_ep_droq *droq[OTX_EP_MAX_IOQS_PER_VF];

	/* IOQ mask */
	struct otx_ep_io_enable io_qmask;

	/* SR-IOV info */
	struct otx_ep_sriov_info sriov_info;

	/* Device configuration */
	const struct otx_ep_config *conf;

	int port_configured;

	uint64_t rx_offloads;

	uint64_t tx_offloads;
};

int otx_ep_setup_oqs(struct otx_ep_device *otx_ep, int oq_no, int num_descs,
		     int desc_size, struct rte_mempool *mpool,
		     unsigned int socket_id);
int otx_ep_delete_oqs(struct otx_ep_device *otx_ep, uint32_t oq_no);
#define OTX_EP_MAX_PKT_SZ 64000U

#define OTX_EP_MAX_MAC_ADDRS 1

#endif  /* _OTX_EP_COMMON_H_ */

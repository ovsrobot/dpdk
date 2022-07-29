/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Intel Corporation
 */

#ifndef _GVE_H_
#define _GVE_H_

#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_ether.h>

#include "gve_desc.h"

#ifndef GOOGLE_VENDOR_ID
#define GOOGLE_VENDOR_ID	0x1ae0
#endif

#define GVE_DEV_ID		0x0042

#define GVE_REG_BAR	0
#define GVE_DB_BAR	2

/* 1 for management, 1 for rx, 1 for tx */
#define GVE_MIN_MSIX		3

/* PTYPEs are always 10 bits. */
#define GVE_NUM_PTYPES	1024

/* A list of pages registered with the device during setup and used by a queue
 * as buffers
 */
struct gve_queue_page_list {
	uint32_t id; /* unique id */
	uint32_t num_entries;
	dma_addr_t *page_buses; /* the dma addrs of the pages */
	const struct rte_memzone *mz;
};

/* A TX desc ring entry */
union gve_tx_desc {
	struct gve_tx_pkt_desc pkt; /* first desc for a packet */
	struct gve_tx_seg_desc seg; /* subsequent descs for a packet */
};

struct gve_tx_queue {
	volatile union gve_tx_desc *tx_desc_ring;
	const struct rte_memzone *mz;
	uint64_t tx_ring_phys_addr;

	uint16_t nb_tx_desc;

	/* Only valid for DQO_QPL queue format */
	struct gve_queue_page_list *qpl;

	uint16_t port_id;
	uint16_t queue_id;

	uint16_t ntfy_id;
	volatile rte_be32_t *ntfy_addr;

	struct gve_priv *hw;
	const struct rte_memzone *qres_mz;
	struct gve_queue_resources *qres;

	/* Only valid for DQO_RDA queue format */
	struct gve_tx_queue *complq;
};

struct gve_rx_queue {
	volatile struct gve_rx_desc *rx_desc_ring;
	volatile union gve_rx_data_slot *rx_data_ring;
	const struct rte_memzone *mz;
	const struct rte_memzone *data_mz;
	uint64_t rx_ring_phys_addr;

	uint16_t nb_rx_desc;

	volatile rte_be32_t *ntfy_addr;

	/* only valid for GQI_QPL queue format */
	struct gve_queue_page_list *qpl;

	struct gve_priv *hw;
	const struct rte_memzone *qres_mz;
	struct gve_queue_resources *qres;

	uint16_t port_id;
	uint16_t queue_id;
	uint16_t ntfy_id;
	uint16_t rx_buf_len;

	/* Only valid for DQO_RDA queue format */
	struct gve_rx_queue *bufq;
};

struct gve_irq_db {
	rte_be32_t id;
} ____cacheline_aligned;

struct gve_ptype {
	uint8_t l3_type;  /* `gve_l3_type` in gve_adminq.h */
	uint8_t l4_type;  /* `gve_l4_type` in gve_adminq.h */
};

struct gve_ptype_lut {
	struct gve_ptype ptypes[GVE_NUM_PTYPES];
};

enum gve_queue_format {
	GVE_QUEUE_FORMAT_UNSPECIFIED = 0x0, /* default unspecified */
	GVE_GQI_RDA_FORMAT	     = 0x1, /* GQI Raw Addressing */
	GVE_GQI_QPL_FORMAT	     = 0x2, /* GQI Queue Page List */
	GVE_DQO_RDA_FORMAT	     = 0x3, /* DQO Raw Addressing */
};

struct gve_priv {
	struct gve_irq_db *irq_dbs; /* array of num_ntfy_blks */
	const struct rte_memzone *irq_dbs_mz;
	uint32_t mgmt_msix_idx;
	rte_be32_t *cnt_array; /* array of num_event_counters */
	const struct rte_memzone *cnt_array_mz;

	uint16_t num_event_counters;
	uint16_t tx_desc_cnt; /* txq size */
	uint16_t rx_desc_cnt; /* rxq size */
	uint16_t tx_pages_per_qpl; /* tx buffer length */
	uint16_t rx_data_slot_cnt; /* rx buffer length */

	/* Only valid for DQO_RDA queue format */
	uint16_t tx_compq_size; /* tx completion queue size */
	uint16_t rx_bufq_size; /* rx buff queue size */

	uint64_t max_registered_pages;
	uint64_t num_registered_pages; /* num pages registered with NIC */
	uint16_t default_num_queues; /* default num queues to set up */
	enum gve_queue_format queue_format; /* see enum gve_queue_format */
	uint8_t enable_lsc;

	uint16_t max_nb_txq;
	uint16_t max_nb_rxq;
	uint32_t num_ntfy_blks; /* spilt between TX and RX so must be even */

	struct gve_registers __iomem *reg_bar0; /* see gve_register.h */
	rte_be32_t __iomem *db_bar2; /* "array" of doorbells */
	struct rte_pci_device *pci_dev;

	/* Admin queue - see gve_adminq.h*/
	union gve_adminq_command *adminq;
	struct gve_dma_mem adminq_dma_mem;
	uint32_t adminq_mask; /* masks prod_cnt to adminq size */
	uint32_t adminq_prod_cnt; /* free-running count of AQ cmds executed */
	uint32_t adminq_cmd_fail; /* free-running count of AQ cmds failed */
	uint32_t adminq_timeouts; /* free-running count of AQ cmds timeouts */
	/* free-running count of per AQ cmd executed */
	uint32_t adminq_describe_device_cnt;
	uint32_t adminq_cfg_device_resources_cnt;
	uint32_t adminq_register_page_list_cnt;
	uint32_t adminq_unregister_page_list_cnt;
	uint32_t adminq_create_tx_queue_cnt;
	uint32_t adminq_create_rx_queue_cnt;
	uint32_t adminq_destroy_tx_queue_cnt;
	uint32_t adminq_destroy_rx_queue_cnt;
	uint32_t adminq_dcfg_device_resources_cnt;
	uint32_t adminq_set_driver_parameter_cnt;
	uint32_t adminq_report_stats_cnt;
	uint32_t adminq_report_link_speed_cnt;
	uint32_t adminq_get_ptype_map_cnt;

	volatile uint32_t state_flags;

	/* Gvnic device link speed from hypervisor. */
	uint64_t link_speed;

	uint16_t max_mtu;
	struct rte_ether_addr dev_addr; /* mac address */

	struct gve_queue_page_list *qpl;

	struct gve_tx_queue **txqs;
	struct gve_rx_queue **rxqs;
};

enum gve_state_flags_bit {
	GVE_PRIV_FLAGS_ADMIN_QUEUE_OK		= 1,
	GVE_PRIV_FLAGS_DEVICE_RESOURCES_OK	= 2,
	GVE_PRIV_FLAGS_DEVICE_RINGS_OK		= 3,
	GVE_PRIV_FLAGS_NAPI_ENABLED		= 4,
};

static inline bool gve_is_gqi(struct gve_priv *priv)
{
	return priv->queue_format == GVE_GQI_RDA_FORMAT ||
		priv->queue_format == GVE_GQI_QPL_FORMAT;
}

static inline bool gve_get_admin_queue_ok(struct gve_priv *priv)
{
	return !!rte_bit_relaxed_get32(GVE_PRIV_FLAGS_ADMIN_QUEUE_OK,
				       &priv->state_flags);
}

static inline void gve_set_admin_queue_ok(struct gve_priv *priv)
{
	rte_bit_relaxed_set32(GVE_PRIV_FLAGS_ADMIN_QUEUE_OK,
			      &priv->state_flags);
}

static inline void gve_clear_admin_queue_ok(struct gve_priv *priv)
{
	rte_bit_relaxed_clear32(GVE_PRIV_FLAGS_ADMIN_QUEUE_OK,
				&priv->state_flags);
}

static inline bool gve_get_device_resources_ok(struct gve_priv *priv)
{
	return !!rte_bit_relaxed_get32(GVE_PRIV_FLAGS_DEVICE_RESOURCES_OK,
				       &priv->state_flags);
}

static inline void gve_set_device_resources_ok(struct gve_priv *priv)
{
	rte_bit_relaxed_set32(GVE_PRIV_FLAGS_DEVICE_RESOURCES_OK,
			      &priv->state_flags);
}

static inline void gve_clear_device_resources_ok(struct gve_priv *priv)
{
	rte_bit_relaxed_clear32(GVE_PRIV_FLAGS_DEVICE_RESOURCES_OK,
				&priv->state_flags);
}

static inline bool gve_get_device_rings_ok(struct gve_priv *priv)
{
	return !!rte_bit_relaxed_get32(GVE_PRIV_FLAGS_DEVICE_RINGS_OK,
				       &priv->state_flags);
}

static inline void gve_set_device_rings_ok(struct gve_priv *priv)
{
	rte_bit_relaxed_set32(GVE_PRIV_FLAGS_DEVICE_RINGS_OK,
			      &priv->state_flags);
}

static inline void gve_clear_device_rings_ok(struct gve_priv *priv)
{
	rte_bit_relaxed_clear32(GVE_PRIV_FLAGS_DEVICE_RINGS_OK,
				&priv->state_flags);
}
#endif /* _GVE_H_ */

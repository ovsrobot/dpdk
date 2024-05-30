#ifndef __DPDK_MOD_REG_H__
#define __DPDK_MOD_REG_H__

#include <rte_ethdev.h>
#include "ntnic_ethdev.h"
#include "ntoss_virt_queue.h"
#include "ntnic_stat.h"

/* sg ops section */
struct sg_ops_s {
	/* Setup a virtQueue for a VM */
	struct nthw_virt_queue *(*nthw_setup_rx_virt_queue)(nthw_dbs_t *p_nthw_dbs,
		uint32_t index,
		uint16_t start_idx,
		uint16_t start_ptr,
		void *avail_struct_phys_addr,
		void *used_struct_phys_addr,
		void *desc_struct_phys_addr,
		uint16_t queue_size,
		uint32_t host_id,
		uint32_t header,
		uint32_t vq_type,
		int irq_vector);
	int (*nthw_enable_rx_virt_queue)(struct nthw_virt_queue *rx_vq);
	int (*nthw_disable_rx_virt_queue)(struct nthw_virt_queue *rx_vq);
	int (*nthw_release_rx_virt_queue)(struct nthw_virt_queue *rxvq);
	struct nthw_virt_queue *(*nthw_setup_tx_virt_queue)(nthw_dbs_t *p_nthw_dbs,
		uint32_t index,
		uint16_t start_idx,
		uint16_t start_ptr,
		void *avail_struct_phys_addr,
		void *used_struct_phys_addr,
		void *desc_struct_phys_addr,
		uint16_t queue_size,
		uint32_t host_id,
		uint32_t port,
		uint32_t virtual_port,
		uint32_t header,
		uint32_t vq_type,
		int irq_vector,
		uint32_t in_order);
	int (*nthw_enable_tx_virt_queue)(struct nthw_virt_queue *tx_vq);
	int (*nthw_disable_tx_virt_queue)(struct nthw_virt_queue *tx_vq);
	int (*nthw_release_tx_virt_queue)(struct nthw_virt_queue *txvq);
	int (*nthw_enable_and_change_port_tx_virt_queue)(struct nthw_virt_queue *tx_vq,
		uint32_t outport);
	struct nthw_virt_queue *(*nthw_setup_managed_rx_virt_queue)(nthw_dbs_t *p_nthw_dbs,
		uint32_t index,
		uint32_t queue_size,
		uint32_t host_id,
		uint32_t header,
		/*
		 * Memory that can be used
		 * for virtQueue structs
		 */
		struct nthw_memory_descriptor *p_virt_struct_area,
		/*
		 * Memory that can be used for packet
		 * buffers - Array must have queue_size
		 * entries
		 */
		struct nthw_memory_descriptor *p_packet_buffers,
		uint32_t vq_type,
		int irq_vector);
	int (*nthw_release_managed_rx_virt_queue)(struct nthw_virt_queue *rxvq);
	struct nthw_virt_queue *(*nthw_setup_managed_tx_virt_queue)(nthw_dbs_t *p_nthw_dbs,
		uint32_t index,
		uint32_t queue_size,
		uint32_t host_id,
		uint32_t port,
		uint32_t virtual_port,
		uint32_t header,
		/*
		 * Memory that can be used
		 * for virtQueue structs
		 */
		struct nthw_memory_descriptor *p_virt_struct_area,
		/*
		 * Memory that can be used for packet
		 * buffers - Array must have queue_size
		 * entries
		 */
		struct nthw_memory_descriptor *p_packet_buffers,
		uint32_t vq_type,
		int irq_vector,
		uint32_t in_order);
	int (*nthw_release_managed_tx_virt_queue)(struct nthw_virt_queue *txvq);
	int (*nthw_set_tx_qos_config)(nthw_dbs_t *p_nthw_dbs, uint32_t port, uint32_t enable,
		uint32_t ir, uint32_t bs);
	int (*nthw_set_tx_qos_rate_global)(nthw_dbs_t *p_nthw_dbs,
		uint32_t multiplier,
		uint32_t divider);
	/*
	 * These functions handles both Split and Packed including merged buffers (jumbo)
	 */
	uint16_t (*nthw_get_rx_packets)(struct nthw_virt_queue *rxvq,
		uint16_t n,
		struct nthw_received_packets *rp,
		uint16_t *nb_pkts);
	void (*nthw_release_rx_packets)(struct nthw_virt_queue *rxvq, uint16_t n);
	uint16_t (*nthw_get_tx_buffers)(struct nthw_virt_queue *txvq,
		uint16_t n,
		uint16_t *first_idx,
		struct nthw_cvirtq_desc *cvq,
		struct nthw_memory_descriptor **p_virt_addr);
	void (*nthw_release_tx_buffers)(struct nthw_virt_queue *txvq,
		uint16_t n,
		uint16_t n_segs[]);
	int (*nthw_get_rx_queue_ptr)(struct nthw_virt_queue *rxvq, uint16_t *index);
	int (*nthw_get_tx_queue_ptr)(struct nthw_virt_queue *txvq, uint16_t *index);
	int (*nthw_virt_queue_init)(struct fpga_info_s *p_fpga_info);
};

void register_sg_ops(struct sg_ops_s *ops);
const struct sg_ops_s *get_sg_ops(void);

/* Meter ops section */
struct meter_ops_s {
	int (*eth_mtr_ops_get)(struct rte_eth_dev *eth_dev, void *ops);
};

void register_meter_ops(struct meter_ops_s *ops);
const struct meter_ops_s *get_meter_ops(void);

/*
 *
 */
#ifdef __NTNIC_ETHDEV_H__
struct ntnic_filter_ops {
	int (*poll_statistics)(struct pmd_internals *internals);
};

void register_ntnic_filter_ops(const struct ntnic_filter_ops *ops);
const struct ntnic_filter_ops *get_ntnic_filter_ops(void);
#endif

/*
 *
 */
struct ntnic_xstats_ops {
	int (*nthw_xstats_get_names)(nt4ga_stat_t *p_nt4ga_stat,
		struct rte_eth_xstat_name *xstats_names,
		unsigned int size,
		bool is_vswitch);
	int (*nthw_xstats_get)(nt4ga_stat_t *p_nt4ga_stat,
		struct rte_eth_xstat *stats,
		unsigned int n,
		bool is_vswitch,
		uint8_t port);
	void (*nthw_xstats_reset)(nt4ga_stat_t *p_nt4ga_stat, bool is_vswitch, uint8_t port);
	int (*nthw_xstats_get_names_by_id)(nt4ga_stat_t *p_nt4ga_stat,
		struct rte_eth_xstat_name *xstats_names,
		const uint64_t *ids,
		unsigned int size,
		bool is_vswitch);
	int (*nthw_xstats_get_by_id)(nt4ga_stat_t *p_nt4ga_stat,
		const uint64_t *ids,
		uint64_t *values,
		unsigned int n,
		bool is_vswitch,
		uint8_t port);
};

void register_ntnic_xstats_ops(struct ntnic_xstats_ops *ops);
struct ntnic_xstats_ops *get_ntnic_xstats_ops(void);

#endif	/* __DPDK_MOD_REG_H__ */

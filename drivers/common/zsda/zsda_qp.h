/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_QP_H_
#define _ZSDA_QP_H_

#include <rte_bus_pci.h>

#define WQ_CSR_LBASE 0x1000
#define WQ_CSR_UBASE 0x1004
#define CQ_CSR_LBASE 0x1400
#define CQ_CSR_UBASE 0x1404
#define WQ_TAIL	     0x1800
#define CQ_HEAD	     0x1804

/**
 * Structure associated with each queue.
 */
struct zsda_queue {
	char memz_name[RTE_MEMZONE_NAMESIZE];
	uint8_t *io_addr;
	uint8_t *base_addr;	   /* Base address */
	rte_iova_t base_phys_addr; /* Queue physical address */
	uint16_t head;		   /* Shadow copy of the head */
	uint16_t tail;		   /* Shadow copy of the tail */
	uint16_t modulo_mask;
	uint16_t msg_size;
	uint16_t queue_size;
	uint16_t cycle_size;
	uint16_t pushed_wqe;

	uint8_t hw_queue_number;
	uint32_t csr_head; /* last written head value */
	uint32_t csr_tail; /* last written tail value */

	uint8_t valid;
	uint16_t sid;
};

typedef void (*rx_callback)(void *cookie_in, struct zsda_cqe *cqe);
typedef int (*tx_callback)(void *op_in, const struct zsda_queue *queue,
			   void **op_cookies, uint16_t new_tail);
typedef int (*srv_match)(void *op_in);

struct qp_srv {
	bool used;
	struct zsda_queue tx_q;
	struct zsda_queue rx_q;
	rx_callback rx_cb;
	tx_callback tx_cb;
	srv_match match;
	struct zsda_common_stat stats;
	struct rte_mempool *op_cookie_pool;
	void **op_cookies;
	uint16_t nb_descriptors;
};

struct zsda_qp {
	void *mmap_bar_addr;
	struct qp_srv srv[ZSDA_MAX_SERVICES];

	uint16_t max_inflights;
	uint16_t min_enq_burst_threshold;

} __rte_cache_aligned;

struct zsda_qp_config {
	enum zsda_service_type service_type;
	const struct zsda_qp_hw_data *hw;
	uint16_t nb_descriptors;
	uint32_t cookie_size;
	int socket_id;
	const char *service_str;
};

struct comp_head_info {
	uint32_t head_len;
	phys_addr_t head_phys_addr;
};

extern uint8_t zsda_num_used_qps;

struct zsda_qp_hw *zsda_qps_hw_per_service(struct zsda_pci_device *zsda_pci_dev,
					   enum zsda_service_type service);
uint16_t zsda_qps_per_service(struct zsda_pci_device *zsda_pci_dev,
			      enum zsda_service_type service);

uint16_t zsda_comp_max_nb_qps(struct zsda_pci_device *zsda_pci_dev);
uint16_t zsda_crypto_max_nb_qps(struct zsda_pci_device *zsda_pci_dev);

int zsda_get_queue_cfg(struct zsda_pci_device *zsda_pci_dev);

/* CSR write macro */
#define ZSDA_CSR_WR(csrAddr, csrOffset, val)                                   \
	rte_write32(val, (((uint8_t *)csrAddr) + csrOffset))
#define ZSDA_CSR_WC_WR(csrAddr, csrOffset, val)                                \
	rte_write32_wc(val, (((uint8_t *)csrAddr) + csrOffset))

/* CSR read macro */
#define ZSDA_CSR_RD(csrAddr, csrOffset)                                        \
	rte_read32((((uint8_t *)csrAddr) + csrOffset))

#define ZSDA_CSR_WQ_RING_BASE(csr_base_addr, ring, value)                      \
	do {                                                                   \
		uint32_t l_base = 0, u_base = 0;                               \
		l_base = (uint32_t)(value & 0xFFFFFFFF);                       \
		u_base = (uint32_t)((value & 0xFFFFFFFF00000000ULL) >> 32);    \
		ZSDA_CSR_WR(csr_base_addr, (ring << 3) + WQ_CSR_LBASE,         \
			    l_base);                                           \
		ZSDA_LOG(INFO, "l_basg - offest:0x%x, value:0x%x",             \
			 ((ring << 3) + WQ_CSR_LBASE), l_base);                \
		ZSDA_CSR_WR(csr_base_addr, (ring << 3) + WQ_CSR_UBASE,         \
			    u_base);                                           \
		ZSDA_LOG(INFO, "h_base - offest:0x%x, value:0x%x",             \
			 ((ring << 3) + WQ_CSR_UBASE), u_base);                \
	} while (0)

#define ZSDA_CSR_CQ_RING_BASE(csr_base_addr, ring, value)                      \
	do {                                                                   \
		uint32_t l_base = 0, u_base = 0;                               \
		l_base = (uint32_t)(value & 0xFFFFFFFF);                       \
		u_base = (uint32_t)((value & 0xFFFFFFFF00000000ULL) >> 32);    \
		ZSDA_CSR_WR(csr_base_addr, (ring << 3) + CQ_CSR_LBASE,         \
			    l_base);                                           \
		ZSDA_CSR_WR(csr_base_addr, (ring << 3) + CQ_CSR_UBASE,         \
			    u_base);                                           \
	} while (0)

#define READ_CSR_WQ_HEAD(csr_base_addr, ring)                                  \
	ZSDA_CSR_RD(csr_base_addr, WQ_TAIL + (ring << 3))
#define WRITE_CSR_WQ_TAIL(csr_base_addr, ring, value)                          \
	ZSDA_CSR_WC_WR(csr_base_addr, WQ_TAIL + (ring << 3), value)
#define READ_CSR_CQ_HEAD(csr_base_addr, ring)                                  \
	ZSDA_CSR_RD(csr_base_addr, WQ_TAIL + (ring << 3))
#define WRITE_CSR_CQ_HEAD(csr_base_addr, ring, value)                          \
	ZSDA_CSR_WC_WR(csr_base_addr, CQ_HEAD + (ring << 3), value)

uint16_t zsda_enqueue_op_burst(struct zsda_qp *qp, void **ops, uint16_t nb_ops);
uint16_t zsda_dequeue_op_burst(struct zsda_qp *qp, void **ops, uint16_t nb_ops);

void tx_write_tail(struct zsda_queue *queue);
int zsda_queue_pair_setup(uint32_t dev_id, struct zsda_qp **qp_addr,
			  uint16_t queue_pair_id,
			  struct zsda_qp_config *zsda_qp_conf);

int zsda_queue_pair_release(struct zsda_qp **qp_addr);
int zsda_fill_sgl(struct rte_mbuf *buf, uint32_t offset,
			 struct zsda_sgl *sgl, phys_addr_t sgl_phy_addr,
			 uint32_t remain_len, struct comp_head_info *comp_head_info);

int zsda_get_sgl_num(struct zsda_sgl *sgl);
int zsda_sgl_opt_addr_lost(struct rte_mbuf *mbuf);

int find_next_free_cookie(struct zsda_queue *queue, void **op_cookie,
			  uint16_t *idx);
int common_setup_qp(uint32_t dev_id, struct zsda_qp **qp_addr,
		    uint16_t queue_pair_id, struct zsda_qp_config *conf);

void zsda_stats_get(void **queue_pairs, uint32_t nb_queue_pairs,
		   struct zsda_common_stat *stats);
void zsda_stats_reset(void **queue_pairs, uint32_t nb_queue_pairs);

#endif /* _ZSDA_QP_H_ */

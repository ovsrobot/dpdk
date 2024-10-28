/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_QP_H_
#define _ZSDA_QP_H_

#define WQ_CSR_LBASE 0x1000
#define WQ_CSR_UBASE 0x1004
#define CQ_CSR_LBASE 0x1400
#define CQ_CSR_UBASE 0x1404
#define WQ_TAIL	     0x1800
#define CQ_HEAD	     0x1804

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
		ZSDA_LOG(INFO, "l_basg - offset:0x%x, value:0x%x",             \
			 ((ring << 3) + WQ_CSR_LBASE), l_base);                \
		ZSDA_CSR_WR(csr_base_addr, (ring << 3) + WQ_CSR_UBASE,         \
			    u_base);                                           \
		ZSDA_LOG(INFO, "h_base - offset:0x%x, value:0x%x",             \
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

typedef int (*rx_callback)(void *cookie_in, struct zsda_cqe *cqe);
typedef int (*tx_callback)(void *op_in, const struct zsda_queue *queue,
			   void **op_cookies, const uint16_t new_tail);
typedef int (*srv_match)(const void *op_in);

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
	struct qp_srv srv[ZSDA_MAX_SERVICES];
};

struct zsda_qp_config {
	enum zsda_service_type service_type;
	const struct zsda_qp_hw_data *hw;
	uint16_t nb_descriptors;
	uint32_t cookie_size;
	int socket_id;
	const char *service_str;
};

struct zsda_num_qps {
	uint16_t encomp;
	uint16_t decomp;
	uint16_t encrypt;
	uint16_t decrypt;
	uint16_t hash;
};

extern struct zsda_num_qps zsda_nb_qps;

int zsda_queue_start(const struct rte_pci_device *pci_dev);
int zsda_queue_stop(const struct rte_pci_device *pci_dev);

int zsda_queue_init(struct zsda_pci_device *zsda_pci_dev);

struct zsda_qp_hw *
zsda_qps_hw_per_service(struct zsda_pci_device *zsda_pci_dev,
			const enum zsda_service_type service);

int zsda_get_queue_cfg(struct zsda_pci_device *zsda_pci_dev);

int zsda_queue_pair_release(struct zsda_qp **qp_addr);

uint16_t zsda_enqueue_op_burst(struct zsda_qp *qp, void **ops, const uint16_t nb_ops);
uint16_t zsda_dequeue_op_burst(struct zsda_qp *qp, void **ops, const uint16_t nb_ops);

int zsda_common_setup_qp(uint32_t dev_id, struct zsda_qp **qp_addr,
		    const uint16_t queue_pair_id,
		    const struct zsda_qp_config *conf);

void zsda_stats_get(void **queue_pairs, const uint32_t nb_queue_pairs,
		    struct zsda_common_stat *stats);
void zsda_stats_reset(void **queue_pairs, const uint32_t nb_queue_pairs);

#endif /* _ZSDA_QP_H_ */

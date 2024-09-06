/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_RXTX_H_
#define _XSC_RXTX_H_

struct xsc_cqe {
	union {
		uint8_t		msg_opcode;
		struct {
			uint8_t		error_code:7;
			uint8_t		is_error:1;
		};
	};
	__le32		qp_id:15;
	uint8_t		rsv:1;
	uint8_t		se:1;
	uint8_t		has_pph:1;
	uint8_t		type:1;
	uint8_t		with_immdt:1;
	uint8_t		csum_err:4;
	__le32		imm_data;
	__le32		msg_len;
	__le32		vni;
	__le64		ts:48;
	__le16		wqe_id;
	__le16		rsv2[3];
	__le16		rsv3:15;
	uint8_t		owner:1;
};

struct __rte_cache_aligned xsc_txq_data {
	uint16_t idx;  /*QP idx */
	uint16_t port_id;
	void *cq; /* CQ pointer */
	void *qp; /* QP pointer */
	uint32_t cqn; /* CQ serial number */
	uint32_t qpn; /* QP serial number */
	uint16_t elts_head; /* Current pos in (*elts)[] */
	uint16_t elts_tail; /* Counter of first element awaiting completion */
	uint16_t elts_comp; /* Elts index since last completion request */
	uint16_t elts_s; /* Number of (*elts)[] */
	uint16_t elts_m; /* Mask of (*elts)[] number */
	uint16_t wqe_ci; /* Consumer index for TXQ */
	uint16_t wqe_pi; /* Producer index for TXQ */
	uint16_t wqe_s; /* Number of WQE */
	uint16_t wqe_m; /* Mask of WQE number */
	uint16_t wqe_comp; /* WQE index since last completion request */
	uint16_t cq_ci; /* Consumer index for CQ */
	uint16_t cq_pi; /* Production index for CQ */
	uint16_t cqe_s; /* Number of CQE */
	uint16_t cqe_m; /* Mask of CQE number */
	uint16_t elts_n:4; /* Log 2 of (*elts)[] number */
	uint16_t cqe_n:4; /* Log 2 of CQE number */
	uint16_t wqe_n:4; /* Log 2 of WQE number */
	uint16_t wqe_ds_n:4; /* Log 2 of each WQE DS number */
	uint64_t offloads; /* TXQ offloads */
	struct xsc_wqe *wqes;
	volatile struct xsc_cqe *cqes;
	volatile uint32_t *qp_db;
	volatile uint32_t *cq_db;
	struct xsc_ethdev_priv *priv;
	uint32_t socket;
	uint8_t tso_en:1; /* TSO enable 0-off 1-on */
	uint16_t *fcqs; /* Free completion queue. */
	struct rte_mbuf *elts[0]; /* Storage for queued packets, for free */
};

struct xsc_cqe_u64 {
	struct xsc_cqe cqe0;
	struct xsc_cqe cqe1;
};

struct __rte_cache_aligned xsc_rxq_data {
	uint16_t idx; /*QP idx */
	uint16_t port_id;
	void *cq; /* CQ pointer */
	void *qp; /* QP pointer */
	uint32_t cqn; /* CQ serial number */
	uint32_t qpn; /* QP serial number */
	uint16_t wqe_s; /* Number of WQE */
	uint16_t wqe_m; /* Mask of WQE number */
	uint16_t cqe_s; /* Number of CQE */
	uint16_t cqe_m; /* Mask of CQE number */
	uint16_t wqe_n:4; /* Log 2 of WQE number */
	uint16_t sge_n:4; /* Log 2 of each WQE DS number */
	uint16_t cqe_n:4; /* Log 2 of CQE number */
	volatile uint32_t *rq_db;
	volatile uint32_t *cq_db;
	uint32_t rq_ci;
	uint32_t rq_pi;
	uint16_t cq_ci;
	uint16_t rx_free_thresh;
	uint16_t nb_rx_hold;
	volatile void *wqes;
	union {
		volatile struct xsc_cqe(*cqes)[];
		volatile struct xsc_cqe_u64(*cqes_u64)[];
	};
	struct rte_mbuf *(*elts)[]; /* Record the mbuf of wqe addr */
	struct rte_mempool *mp;
	const struct rte_memzone *rq_pas;  /* Palist memory */
	uint32_t socket;
	struct xsc_ethdev_priv *priv;
	/* attr */
	uint32_t csum:1;  /* Checksum offloading enable */
	uint32_t hw_timestamp:1;
	uint32_t vlan_strip:1;
	uint32_t crc_present:1; /* CRC flag */
	uint32_t rss_hash:1; /* RSS hash enabled */
};

#endif /* _XSC_RXTX_H_ */

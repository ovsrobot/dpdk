/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell.
 */

#ifndef _ROC_NIX_PRIV_H_
#define _ROC_NIX_PRIV_H_

/* Constants */
#define NIX_CQ_ENTRY_SZ	     128
#define NIX_CQ_ENTRY64_SZ    512
#define NIX_CQ_ALIGN	     (uint16_t)512
#define NIX_MAX_SQB	     (uint16_t)512
#define NIX_DEF_SQB	     (uint16_t)16
#define NIX_MIN_SQB	     (uint16_t)8
#define NIX_SQB_LIST_SPACE   (uint16_t)2
#define NIX_SQB_LOWER_THRESH (uint16_t)70

/* Apply BP/DROP when CQ is 95% full */
#define NIX_CQ_THRESH_LEVEL (5 * 256 / 100)

/* IRQ triggered when NIX_LF_CINTX_CNT[QCOUNT] crosses this value */
#define CQ_CQE_THRESH_DEFAULT	0x1ULL
#define CQ_TIMER_THRESH_DEFAULT 0xAULL /* ~1usec i.e (0xA * 100nsec) */
#define CQ_TIMER_THRESH_MAX	255

struct nix_qint {
	struct nix *nix;
	uint8_t qintx;
};

/* Traffic Manager */
#define NIX_TM_MAX_HW_TXSCHQ 512
#define NIX_TM_HW_ID_INVALID UINT32_MAX

/* TM flags */
#define NIX_TM_HIERARCHY_ENA BIT_ULL(0)
#define NIX_TM_TL1_NO_SP     BIT_ULL(1)
#define NIX_TM_TL1_ACCESS    BIT_ULL(2)

struct nix_tm_tb {
	/** Token bucket rate (bytes per second) */
	uint64_t rate;

	/** Token bucket size (bytes), a.k.a. max burst size */
	uint64_t size;
};

struct nix_tm_node {
	TAILQ_ENTRY(nix_tm_node) node;

	/* Input params */
	enum roc_nix_tm_tree tree;
	uint32_t id;
	uint32_t priority;
	uint32_t weight;
	uint16_t lvl;
	uint32_t parent_id;
	uint32_t shaper_profile_id;
	void (*free_fn)(void *node);

	/* Derived params */
	uint32_t hw_id;
	uint16_t hw_lvl;
	uint32_t rr_prio;
	uint32_t rr_num;
	uint32_t max_prio;
	uint32_t parent_hw_id;
	uint32_t flags : 16;
#define NIX_TM_NODE_HWRES   BIT_ULL(0)
#define NIX_TM_NODE_ENABLED BIT_ULL(1)
	/* Shaper algorithm for RED state @NIX_REDALG_E */
	uint32_t red_algo : 2;
	uint32_t pkt_mode : 1;
	uint32_t pkt_mode_set : 1;

	bool child_realloc;
	struct nix_tm_node *parent;

	/* Non-leaf node sp count */
	uint32_t n_sp_priorities;

	/* Last stats */
	uint64_t last_pkts;
	uint64_t last_bytes;
};

struct nix_tm_shaper_profile {
	TAILQ_ENTRY(nix_tm_shaper_profile) shaper;
	struct nix_tm_tb commit;
	struct nix_tm_tb peak;
	int32_t pkt_len_adj;
	bool pkt_mode;
	uint32_t id;
	void (*free_fn)(void *profile);

	uint32_t ref_cnt;
};

TAILQ_HEAD(nix_tm_node_list, nix_tm_node);
TAILQ_HEAD(nix_tm_shaper_profile_list, nix_tm_shaper_profile);

struct nix {
	uint16_t reta[ROC_NIX_RSS_GRPS][ROC_NIX_RSS_RETA_MAX];
	enum roc_nix_rss_reta_sz reta_sz;
	struct plt_pci_device *pci_dev;
	uint16_t bpid[NIX_MAX_CHAN];
	struct nix_qint *qints_mem;
	struct nix_qint *cints_mem;
	uint8_t configured_qints;
	uint8_t configured_cints;
	struct roc_nix_sq **sqs;
	uint16_t vwqe_interval;
	uint16_t tx_chan_base;
	uint16_t rx_chan_base;
	uint16_t nb_rx_queues;
	uint16_t nb_tx_queues;
	uint8_t lso_tsov6_idx;
	uint8_t lso_tsov4_idx;
	uint8_t lso_base_idx;
	uint8_t lf_rx_stats;
	uint8_t lf_tx_stats;
	uint8_t rx_chan_cnt;
	uint8_t rss_alg_idx;
	uint8_t tx_chan_cnt;
	uintptr_t lmt_base;
	uint8_t cgx_links;
	uint8_t lbk_links;
	uint8_t sdp_links;
	uint8_t tx_link;
	uint16_t sqb_size;
	/* Without FCS, with L2 overhead */
	uint16_t mtu;
	uint16_t chan_cnt;
	uint16_t msixoff;
	uint8_t rx_pause;
	uint8_t tx_pause;
	struct dev dev;
	uint16_t cints;
	uint16_t qints;
	uintptr_t base;
	bool sdp_link;
	bool lbk_link;
	bool ptp_en;
	bool is_nix1;

	/* Traffic manager info */

	/* Contiguous resources per lvl */
	struct plt_bitmap *schq_contig_bmp[NIX_TXSCH_LVL_CNT];
	/* Dis-contiguous resources per lvl */
	struct plt_bitmap *schq_bmp[NIX_TXSCH_LVL_CNT];
	void *schq_bmp_mem;

	struct nix_tm_shaper_profile_list shaper_profile_list;
	struct nix_tm_node_list trees[ROC_NIX_TM_TREE_MAX];
	enum roc_nix_tm_tree tm_tree;
	uint64_t tm_rate_min;
	uint16_t tm_root_lvl;
	uint16_t tm_flags;
	uint16_t tm_link_cfg_lvl;
	uint16_t contig_rsvd[NIX_TXSCH_LVL_CNT];
	uint16_t discontig_rsvd[NIX_TXSCH_LVL_CNT];
} __plt_cache_aligned;

enum nix_err_status {
	NIX_ERR_PARAM = -2048,
	NIX_ERR_NO_MEM,
	NIX_ERR_INVALID_RANGE,
	NIX_ERR_INTERNAL,
	NIX_ERR_OP_NOTSUP,
	NIX_ERR_QUEUE_INVALID_RANGE,
	NIX_ERR_AQ_READ_FAILED,
	NIX_ERR_AQ_WRITE_FAILED,
	NIX_ERR_TM_LEAF_NODE_GET,
	NIX_ERR_TM_INVALID_LVL,
	NIX_ERR_TM_INVALID_PRIO,
	NIX_ERR_TM_INVALID_PARENT,
	NIX_ERR_TM_NODE_EXISTS,
	NIX_ERR_TM_INVALID_NODE,
	NIX_ERR_TM_INVALID_SHAPER_PROFILE,
	NIX_ERR_TM_PKT_MODE_MISMATCH,
	NIX_ERR_TM_WEIGHT_EXCEED,
	NIX_ERR_TM_CHILD_EXISTS,
	NIX_ERR_TM_INVALID_PEAK_SZ,
	NIX_ERR_TM_INVALID_PEAK_RATE,
	NIX_ERR_TM_INVALID_COMMIT_SZ,
	NIX_ERR_TM_INVALID_COMMIT_RATE,
	NIX_ERR_TM_SHAPER_PROFILE_IN_USE,
	NIX_ERR_TM_SHAPER_PROFILE_EXISTS,
	NIX_ERR_TM_SHAPER_PKT_LEN_ADJUST,
	NIX_ERR_TM_INVALID_TREE,
	NIX_ERR_TM_PARENT_PRIO_UPDATE,
	NIX_ERR_TM_PRIO_EXCEEDED,
	NIX_ERR_TM_PRIO_ORDER,
	NIX_ERR_TM_MULTIPLE_RR_GROUPS,
	NIX_ERR_TM_SQ_UPDATE_FAIL,
	NIX_ERR_NDC_SYNC,
};

enum nix_q_size {
	nix_q_size_16, /* 16 entries */
	nix_q_size_64, /* 64 entries */
	nix_q_size_256,
	nix_q_size_1K,
	nix_q_size_4K,
	nix_q_size_16K,
	nix_q_size_64K,
	nix_q_size_256K,
	nix_q_size_1M, /* Million entries */
	nix_q_size_max
};

static inline struct nix *
roc_nix_to_nix_priv(struct roc_nix *roc_nix)
{
	return (struct nix *)&roc_nix->reserved[0];
}

static inline struct roc_nix *
nix_priv_to_roc_nix(struct nix *nix)
{
	return (struct roc_nix *)((char *)nix -
				  offsetof(struct roc_nix, reserved));
}

/* IRQ */
int nix_register_irqs(struct nix *nix);
void nix_unregister_irqs(struct nix *nix);

/* TM */
#define NIX_TM_TREE_MASK_ALL                                                   \
	(BIT(ROC_NIX_TM_DEFAULT) | BIT(ROC_NIX_TM_RLIMIT) |                    \
	 BIT(ROC_NIX_TM_USER))

/* NIX_MAX_HW_FRS ==
 * NIX_TM_DFLT_RR_WT * NIX_TM_RR_QUANTUM_MAX / ROC_NIX_TM_MAX_SCHED_WT
 */
#define NIX_TM_DFLT_RR_WT 71

/* Default TL1 priority and Quantum from AF */
#define NIX_TM_TL1_DFLT_RR_QTM	((1 << 24) - 1)
#define NIX_TM_TL1_DFLT_RR_PRIO 1

struct nix_tm_shaper_data {
	uint64_t burst_exponent;
	uint64_t burst_mantissa;
	uint64_t div_exp;
	uint64_t exponent;
	uint64_t mantissa;
	uint64_t burst;
	uint64_t rate;
};

static inline uint64_t
nix_tm_weight_to_rr_quantum(uint64_t weight)
{
	uint64_t max = (roc_model_is_cn9k() ? NIX_CN9K_TM_RR_QUANTUM_MAX :
						    NIX_TM_RR_QUANTUM_MAX);

	weight &= (uint64_t)ROC_NIX_TM_MAX_SCHED_WT;
	return (weight * max) / ROC_NIX_TM_MAX_SCHED_WT;
}

static inline bool
nix_tm_have_tl1_access(struct nix *nix)
{
	return !!(nix->tm_flags & NIX_TM_TL1_ACCESS);
}

static inline bool
nix_tm_is_leaf(struct nix *nix, int lvl)
{
	if (nix_tm_have_tl1_access(nix))
		return (lvl == ROC_TM_LVL_QUEUE);
	return (lvl == ROC_TM_LVL_SCH4);
}

static inline struct nix_tm_node_list *
nix_tm_node_list(struct nix *nix, enum roc_nix_tm_tree tree)
{
	return &nix->trees[tree];
}

static inline const char *
nix_tm_hwlvl2str(uint32_t hw_lvl)
{
	switch (hw_lvl) {
	case NIX_TXSCH_LVL_MDQ:
		return "SMQ/MDQ";
	case NIX_TXSCH_LVL_TL4:
		return "TL4";
	case NIX_TXSCH_LVL_TL3:
		return "TL3";
	case NIX_TXSCH_LVL_TL2:
		return "TL2";
	case NIX_TXSCH_LVL_TL1:
		return "TL1";
	default:
		break;
	}

	return "???";
}

static inline const char *
nix_tm_tree2str(enum roc_nix_tm_tree tree)
{
	if (tree == ROC_NIX_TM_DEFAULT)
		return "Default Tree";
	else if (tree == ROC_NIX_TM_RLIMIT)
		return "Rate Limit Tree";
	else if (tree == ROC_NIX_TM_USER)
		return "User Tree";
	return "???";
}

/*
 * TM priv ops.
 */

int nix_tm_conf_init(struct roc_nix *roc_nix);
void nix_tm_conf_fini(struct roc_nix *roc_nix);
int nix_tm_leaf_data_get(struct nix *nix, uint16_t sq, uint32_t *rr_quantum,
			 uint16_t *smq);
int nix_tm_sq_flush_pre(struct roc_nix_sq *sq);
int nix_tm_sq_flush_post(struct roc_nix_sq *sq);
int nix_tm_smq_xoff(struct nix *nix, struct nix_tm_node *node, bool enable);
int nix_tm_node_add(struct roc_nix *roc_nix, struct nix_tm_node *node);
int nix_tm_node_delete(struct roc_nix *roc_nix, uint32_t node_id,
		       enum roc_nix_tm_tree tree, bool free);
int nix_tm_free_node_resource(struct nix *nix, struct nix_tm_node *node);
int nix_tm_clear_path_xoff(struct nix *nix, struct nix_tm_node *node);

/*
 * TM priv utils.
 */
uint16_t nix_tm_lvl2nix(struct nix *nix, uint32_t lvl);
uint16_t nix_tm_lvl2nix_tl1_root(uint32_t lvl);
uint16_t nix_tm_lvl2nix_tl2_root(uint32_t lvl);
uint16_t nix_tm_resource_avail(struct nix *nix, uint8_t hw_lvl, bool contig);
int nix_tm_validate_prio(struct nix *nix, uint32_t lvl, uint32_t parent_id,
			 uint32_t priority, enum roc_nix_tm_tree tree);
struct nix_tm_node *nix_tm_node_search(struct nix *nix, uint32_t node_id,
				       enum roc_nix_tm_tree tree);
struct nix_tm_shaper_profile *nix_tm_shaper_profile_search(struct nix *nix,
							   uint32_t id);
uint8_t nix_tm_sw_xoff_prep(struct nix_tm_node *node, bool enable,
			    volatile uint64_t *reg, volatile uint64_t *regval);
struct nix_tm_node *nix_tm_node_alloc(void);
void nix_tm_node_free(struct nix_tm_node *node);

#endif /* _ROC_NIX_PRIV_H_ */

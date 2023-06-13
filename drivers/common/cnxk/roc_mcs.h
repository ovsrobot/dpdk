/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#ifndef _ROC_MCS_H_
#define _ROC_MCS_H_

#define MCS_AES_GCM_256_KEYLEN 32

struct roc_mcs_alloc_rsrc_req {
	uint8_t rsrc_type;
	uint8_t rsrc_cnt; /* Resources count */
	uint8_t dir;	  /* Macsec ingress or egress side */
	uint8_t all;	  /* Allocate all resource type one each */
};

struct roc_mcs_alloc_rsrc_rsp {
	uint8_t flow_ids[128]; /* Index of reserved entries */
	uint8_t secy_ids[128];
	uint8_t sc_ids[128];
	uint8_t sa_ids[256];
	uint8_t rsrc_type;
	uint8_t rsrc_cnt; /* No of entries reserved */
	uint8_t dir;
	uint8_t all;
};

struct roc_mcs_free_rsrc_req {
	uint8_t rsrc_id; /* Index of the entry to be freed */
	uint8_t rsrc_type;
	uint8_t dir;
	uint8_t all; /* Free all the cam resources */
};

struct roc_mcs_flowid_entry_write_req {
	uint64_t data[4];
	uint64_t mask[4];
	uint64_t sci; /* 105N for tx_secy_mem_map */
	uint8_t flow_id;
	uint8_t secy_id; /* secyid for which flowid is mapped */
	uint8_t sc_id;	 /* Valid if dir = MCS_TX, SC_CAM id mapped to flowid */
	uint8_t ena;	 /* Enable tcam entry */
	uint8_t ctr_pkt;
	uint8_t dir;
};

struct roc_mcs_secy_plcy_write_req {
	uint64_t plcy;
	uint8_t secy_id;
	uint8_t dir;
};

/* RX SC_CAM mapping */
struct roc_mcs_rx_sc_cam_write_req {
	uint64_t sci;	  /* SCI */
	uint64_t secy_id; /* secy index mapped to SC */
	uint8_t sc_id;	  /* SC CAM entry index */
};

struct roc_mcs_sa_plcy_write_req {
	uint64_t plcy[2][9];
	uint8_t sa_index[2];
	uint8_t sa_cnt;
	uint8_t dir;
};

struct roc_mcs_tx_sc_sa_map {
	uint8_t sa_index0;
	uint8_t sa_index1;
	uint8_t rekey_ena;
	uint8_t sa_index0_vld;
	uint8_t sa_index1_vld;
	uint8_t tx_sa_active;
	uint64_t sectag_sci;
	uint8_t sc_id; /* used as index for SA_MEM_MAP */
};

struct roc_mcs_rx_sc_sa_map {
	uint8_t sa_index;
	uint8_t sa_in_use;
	uint8_t sc_id;
	uint8_t an; /* value range 0-3, sc_id + an used as index SA_MEM_MAP */
};

struct roc_mcs_flowid_ena_dis_entry {
	uint8_t flow_id;
	uint8_t ena;
	uint8_t dir;
};

struct roc_mcs_pn_table_write_req {
	uint64_t next_pn;
	uint8_t pn_id;
	uint8_t dir;
};

struct roc_mcs_cam_entry_read_req {
	uint8_t rsrc_type; /* TCAM/SECY/SC/SA/PN */
	uint8_t rsrc_id;
	uint8_t dir;
};

struct roc_mcs_cam_entry_read_rsp {
	uint64_t reg_val[10];
	uint8_t rsrc_type;
	uint8_t rsrc_id;
	uint8_t dir;
};

struct roc_mcs_hw_info {
	uint8_t num_mcs_blks; /* Number of MCS blocks */
	uint8_t tcam_entries; /* RX/TX Tcam entries per mcs block */
	uint8_t secy_entries; /* RX/TX SECY entries per mcs block */
	uint8_t sc_entries;   /* RX/TX SC CAM entries per mcs block */
	uint16_t sa_entries;  /* PN table entries = SA entries */
	uint64_t rsvd[16];
};

struct roc_mcs_set_lmac_mode {
	uint8_t mode; /* '1' for internal bypass mode (passthrough), '0' for MCS processing */
	uint8_t lmac_id;
	uint64_t rsvd;
};

struct roc_mcs_set_active_lmac {
	uint32_t lmac_bmap;    /* bitmap of active lmac per mcs block */
	uint16_t channel_base; /* MCS channel base */
	uint64_t rsvd;
};

struct roc_mcs_set_pn_threshold {
	uint64_t threshold;
	uint8_t xpn; /* '1' for setting xpn threshold */
	uint8_t dir;
	uint64_t rsvd;
};

struct roc_mcs_stats_req {
	uint8_t id;
	uint8_t dir;
};

struct roc_mcs_flowid_stats {
	uint64_t tcam_hit_cnt;
};

struct roc_mcs_secy_stats {
	uint64_t ctl_pkt_bcast_cnt;
	uint64_t ctl_pkt_mcast_cnt;
	uint64_t ctl_pkt_ucast_cnt;
	uint64_t ctl_octet_cnt;
	uint64_t unctl_pkt_bcast_cnt;
	uint64_t unctl_pkt_mcast_cnt;
	uint64_t unctl_pkt_ucast_cnt;
	uint64_t unctl_octet_cnt;
	/* Valid only for RX */
	uint64_t octet_decrypted_cnt;
	uint64_t octet_validated_cnt;
	uint64_t pkt_port_disabled_cnt;
	uint64_t pkt_badtag_cnt;
	uint64_t pkt_nosa_cnt;
	uint64_t pkt_nosaerror_cnt;
	uint64_t pkt_tagged_ctl_cnt;
	uint64_t pkt_untaged_cnt;
	uint64_t pkt_ctl_cnt;	/* CN10K-B */
	uint64_t pkt_notag_cnt; /* CNF10K-B */
	/* Valid only for TX */
	uint64_t octet_encrypted_cnt;
	uint64_t octet_protected_cnt;
	uint64_t pkt_noactivesa_cnt;
	uint64_t pkt_toolong_cnt;
	uint64_t pkt_untagged_cnt;
};

struct roc_mcs_sc_stats {
	/* RX */
	uint64_t hit_cnt;
	uint64_t pkt_invalid_cnt;
	uint64_t pkt_late_cnt;
	uint64_t pkt_notvalid_cnt;
	uint64_t pkt_unchecked_cnt;
	uint64_t pkt_delay_cnt;	     /* CNF10K-B */
	uint64_t pkt_ok_cnt;	     /* CNF10K-B */
	uint64_t octet_decrypt_cnt;  /* CN10K-B */
	uint64_t octet_validate_cnt; /* CN10K-B */
	/* TX */
	uint64_t pkt_encrypt_cnt;
	uint64_t pkt_protected_cnt;
	uint64_t octet_encrypt_cnt;   /* CN10K-B */
	uint64_t octet_protected_cnt; /* CN10K-B */
};

struct roc_mcs_port_stats {
	uint64_t tcam_miss_cnt;
	uint64_t parser_err_cnt;
	uint64_t preempt_err_cnt; /* CNF10K-B */
	uint64_t sectag_insert_err_cnt;
};

struct roc_mcs_clear_stats {
	uint8_t type; /* FLOWID, SECY, SC, SA, PORT */
	/* type = PORT, If id = FF(invalid) port no is derived from pcifunc */
	uint8_t id;
	uint8_t dir;
	uint8_t all; /* All resources stats mapped to PF are cleared */
};

struct roc_mcs {
	TAILQ_ENTRY(roc_mcs) next;
	struct plt_pci_device *pci_dev;
	struct mbox *mbox;
	void *userdata;
	uint8_t idx;
	uint8_t refcount;

#define ROC_MCS_MEM_SZ (1 * 1024)
	uint8_t reserved[ROC_MCS_MEM_SZ] __plt_cache_aligned;
} __plt_cache_aligned;

TAILQ_HEAD(roc_mcs_head, roc_mcs);

/* Initialization */
__roc_api struct roc_mcs *roc_mcs_dev_init(uint8_t mcs_idx);
__roc_api void roc_mcs_dev_fini(struct roc_mcs *mcs);
/* Get roc mcs dev structure */
__roc_api struct roc_mcs *roc_mcs_dev_get(uint8_t mcs_idx);
/* HW info get */
__roc_api int roc_mcs_hw_info_get(struct roc_mcs_hw_info *hw_info);
/* Active lmac bmap set */
__roc_api int roc_mcs_active_lmac_set(struct roc_mcs *mcs, struct roc_mcs_set_active_lmac *lmac);
/* Port bypass mode set */
__roc_api int roc_mcs_lmac_mode_set(struct roc_mcs *mcs, struct roc_mcs_set_lmac_mode *port);
/* (X)PN threshold set */
__roc_api int roc_mcs_pn_threshold_set(struct roc_mcs *mcs, struct roc_mcs_set_pn_threshold *pn);

/* Resource allocation and free */
__roc_api int roc_mcs_rsrc_alloc(struct roc_mcs *mcs, struct roc_mcs_alloc_rsrc_req *req,
				 struct roc_mcs_alloc_rsrc_rsp *rsp);
__roc_api int roc_mcs_rsrc_free(struct roc_mcs *mcs, struct roc_mcs_free_rsrc_req *req);
/* SA policy read and write */
__roc_api int roc_mcs_sa_policy_write(struct roc_mcs *mcs,
				      struct roc_mcs_sa_plcy_write_req *sa_plcy);
__roc_api int roc_mcs_sa_policy_read(struct roc_mcs *mcs,
				     struct roc_mcs_sa_plcy_write_req *sa_plcy);
/* PN Table read and write */
__roc_api int roc_mcs_pn_table_write(struct roc_mcs *mcs,
				     struct roc_mcs_pn_table_write_req *pn_table);
__roc_api int roc_mcs_pn_table_read(struct roc_mcs *mcs,
				    struct roc_mcs_pn_table_write_req *pn_table);
/* RX SC read, write and enable */
__roc_api int roc_mcs_rx_sc_cam_write(struct roc_mcs *mcs,
				      struct roc_mcs_rx_sc_cam_write_req *rx_sc_cam);
__roc_api int roc_mcs_rx_sc_cam_read(struct roc_mcs *mcs,
				     struct roc_mcs_rx_sc_cam_write_req *rx_sc_cam);
__roc_api int roc_mcs_rx_sc_cam_enable(struct roc_mcs *mcs,
				       struct roc_mcs_rx_sc_cam_write_req *rx_sc_cam);
/* SECY policy read and write */
__roc_api int roc_mcs_secy_policy_write(struct roc_mcs *mcs,
					struct roc_mcs_secy_plcy_write_req *secy_plcy);
__roc_api int roc_mcs_secy_policy_read(struct roc_mcs *mcs,
				       struct roc_mcs_rx_sc_cam_write_req *rx_sc_cam);
/* RX SC-SA MAP read and write */
__roc_api int roc_mcs_rx_sc_sa_map_write(struct roc_mcs *mcs,
					 struct roc_mcs_rx_sc_sa_map *rx_sc_sa_map);
__roc_api int roc_mcs_rx_sc_sa_map_read(struct roc_mcs *mcs,
					struct roc_mcs_rx_sc_sa_map *rx_sc_sa_map);
/* TX SC-SA MAP read and write */
__roc_api int roc_mcs_tx_sc_sa_map_write(struct roc_mcs *mcs,
					 struct roc_mcs_tx_sc_sa_map *tx_sc_sa_map);
__roc_api int roc_mcs_tx_sc_sa_map_read(struct roc_mcs *mcs,
					struct roc_mcs_tx_sc_sa_map *tx_sc_sa_map);
/* Flow entry read, write and enable */
__roc_api int roc_mcs_flowid_entry_write(struct roc_mcs *mcs,
					 struct roc_mcs_flowid_entry_write_req *flowid_req);
__roc_api int roc_mcs_flowid_entry_read(struct roc_mcs *mcs,
					struct roc_mcs_flowid_entry_write_req *flowid_rsp);
__roc_api int roc_mcs_flowid_entry_enable(struct roc_mcs *mcs,
					  struct roc_mcs_flowid_ena_dis_entry *entry);

/* Flow id stats get */
__roc_api int roc_mcs_flowid_stats_get(struct roc_mcs *mcs, struct roc_mcs_stats_req *mcs_req,
				       struct roc_mcs_flowid_stats *stats);
/* Secy stats get */
__roc_api int roc_mcs_secy_stats_get(struct roc_mcs *mcs, struct roc_mcs_stats_req *mcs_req,
				     struct roc_mcs_secy_stats *stats);
/* SC stats get */
__roc_api int roc_mcs_sc_stats_get(struct roc_mcs *mcs, struct roc_mcs_stats_req *mcs_req,
				   struct roc_mcs_sc_stats *stats);
/* Port stats get */
__roc_api int roc_mcs_port_stats_get(struct roc_mcs *mcs, struct roc_mcs_stats_req *mcs_req,
				     struct roc_mcs_port_stats *stats);
/* Clear stats */
__roc_api int roc_mcs_stats_clear(struct roc_mcs *mcs, struct roc_mcs_clear_stats *mcs_req);

#endif /* _ROC_MCS_H_ */

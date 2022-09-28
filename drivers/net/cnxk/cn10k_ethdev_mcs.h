/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <cnxk_ethdev.h>

#define CNXK_MACSEC_HASH_KEY	16

struct cnxk_mcs_dev {
	uint64_t default_sci;
	void *mdev;
	uint8_t port_id;
	uint8_t idx;
};

enum cnxk_mcs_rsrc_type {
	CNXK_MCS_RSRC_TYPE_FLOWID,
	CNXK_MCS_RSRC_TYPE_SECY,
	CNXK_MCS_RSRC_TYPE_SC,
	CNXK_MCS_RSRC_TYPE_SA,
};

struct cnxk_mcs_flow_opts {
	uint32_t outer_tag_id;
	/**< {VLAN_ID[11:0]}, or 20-bit MPLS label*/
	uint8_t outer_priority;
	/**< {PCP/Pbits, DE/CFI} or {1'b0, EXP} for MPLS.*/
	uint32_t second_outer_tag_id;
	/**< {VLAN_ID[11:0]}, or 20-bit MPLS label*/
	uint8_t second_outer_priority;
	/**< {PCP/Pbits, DE/CFI} or {1'b0, EXP} for MPLS. */
	uint16_t bonus_data;
	/**< 2 bytes of additional bonus data extracted from one of the custom tags*/
	uint8_t tag_match_bitmap;
	uint8_t packet_type;
	uint8_t outer_vlan_type;
	uint8_t inner_vlan_type;
	uint8_t num_tags;
	bool express;
	uint8_t port; /**< port 0-3 */
	uint8_t flowid_user;
};

int cn10k_eth_macsec_sa_create(void *device, struct rte_security_macsec_sa *conf);
int cn10k_eth_macsec_sc_create(void *device, struct rte_security_macsec_sc *conf);

int cn10k_eth_macsec_sa_destroy(void *device, uint16_t sa_id);
int cn10k_eth_macsec_sc_destroy(void *device, uint16_t sc_id);

int cn10k_eth_macsec_sa_stats_get(void *device, uint16_t sa_id,
			    struct rte_security_macsec_sa_stats *stats);
int cn10k_eth_macsec_sc_stats_get(void *device, uint16_t sa_id,
			    struct rte_security_macsec_sc_stats *stats);

int cn10k_eth_macsec_session_create(struct cnxk_eth_dev *dev,
			     struct rte_security_session_conf *conf,
			     struct rte_security_session *sess,
			     struct rte_mempool *mempool);
int cn10k_eth_macsec_session_destroy(void *device, struct rte_security_session *sess);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <cnxk_ethdev.h>
#include <cn10k_ethdev_mcs.h>
#include <roc_mcs.h>

static int
mcs_resource_alloc(struct cnxk_mcs_dev *mcs_dev, enum rte_security_macsec_direction dir,
		   uint8_t rsrc_id[], uint8_t rsrc_cnt, enum cnxk_mcs_rsrc_type type)
{
	struct roc_mcs_alloc_rsrc_req req = {0};
	struct roc_mcs_alloc_rsrc_rsp rsp = {0};
	int i;

	req.rsrc_type = type;
	req.rsrc_cnt = rsrc_cnt;
	req.mcs_id = mcs_dev->idx;
	req.dir = dir;

	if (roc_mcs_alloc_rsrc(mcs_dev->mdev, &req, &rsp)) {
		printf("error: Cannot allocate mcs resource.\n");
		return -1;
	}

	for (i = 0; i < rsrc_cnt; i++) {
		switch (rsp.rsrc_type) {
		case CNXK_MCS_RSRC_TYPE_FLOWID:
			rsrc_id[i] = rsp.flow_ids[i];
			break;
		case CNXK_MCS_RSRC_TYPE_SECY:
			rsrc_id[i] = rsp.secy_ids[i];
			break;
		case CNXK_MCS_RSRC_TYPE_SC:
			rsrc_id[i] = rsp.sc_ids[i];
			break;
		case CNXK_MCS_RSRC_TYPE_SA:
			rsrc_id[i] = rsp.sa_ids[i];
			break;
		default :
			printf("error: Invalid mcs resource allocated.\n");
			return -1;
		}
	}
	return 0;
}

int
cn10k_eth_macsec_sa_create(void *device, struct rte_security_macsec_sa *conf)
{
	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)device;
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct cnxk_mcs_dev *mcs_dev = dev->mcs_dev;
	struct roc_mcs_pn_table_write_req pn_req = {0};
	struct roc_mcs_sa_plcy_write_req req = {0};
	uint8_t hash_key[16] = {0};
	uint8_t sa_id = 0;
	int ret = 0;

	ret = mcs_resource_alloc(mcs_dev, conf->dir, &sa_id, 1, CNXK_MCS_RSRC_TYPE_SA);
	if (ret) {
		printf("Failed to allocate SA id.\n");
		return -ENOMEM;
	}
	req.sa_index[0] = sa_id;
	req.sa_cnt = 1;
	req.mcs_id = mcs_dev->idx;
	req.dir = conf->dir;

	if (conf->key.length != 16 || conf->key.length != 32)
		return -EINVAL;

	memcpy(&req.plcy[0][0], conf->key.data, conf->key.length);
	roc_aes_hash_key_derive(conf->key.data, conf->key.length, hash_key);
	memcpy(&req.plcy[0][4], hash_key, CNXK_MACSEC_HASH_KEY);
	memcpy(&req.plcy[0][6], conf->salt, RTE_SECURITY_MACSEC_SALT_LEN);
	req.plcy[0][7] |= (uint64_t)conf->ssci << 32;
	req.plcy[0][8] = conf->an & 0x3;

	ret = roc_mcs_sa_policy_write(mcs_dev->mdev, &req);
	if (ret) {
		printf("Failed to write SA policy.\n");
		return -EINVAL;
	}

	pn_req.next_pn = conf->next_pn;
	pn_req.pn_id = sa_id;
	pn_req.mcs_id = mcs_dev->idx;
	pn_req.dir = conf->dir;

	ret = roc_mcs_pn_table_write(mcs_dev->mdev, &pn_req);
	if (ret) {
		printf("Failed to write PN table.\n");
		return -EINVAL;
	}

	return sa_id;
}

int
cn10k_eth_macsec_sa_destroy(void *device, uint16_t sa_id)
{
	RTE_SET_USED(device);
	RTE_SET_USED(sa_id);

	return 0;
}

int
cn10k_eth_macsec_sc_create(void *device, struct rte_security_macsec_sc *conf)
{
	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)device;
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct cnxk_mcs_dev *mcs_dev = dev->mcs_dev;
	uint8_t sc_id = 0;
	int i, ret = 0;

	ret = mcs_resource_alloc(mcs_dev, conf->dir, &sc_id, 1, CNXK_MCS_RSRC_TYPE_SC);
	if (ret) {
		printf("Failed to allocate SC id.\n");
		return -ENOMEM;
	}

	if (conf->dir == RTE_SECURITY_MACSEC_DIR_TX) {
		struct roc_mcs_tx_sc_sa_map req = {0};

		req.mcs_id = mcs_dev->idx;
		req.sa_index0 = conf->sc_tx.sa_id & 0x7F;
		req.sa_index1 = conf->sc_tx.sa_id_rekey & 0x7F;
		req.rekey_ena = conf->sc_tx.re_key_en;
		req.sa_index0_vld = conf->sc_tx.active;
		req.sa_index1_vld = conf->sc_tx.re_key_en && conf->sc_tx.active;
		req.tx_sa_active = conf->sc_tx.active;
		req.sectag_sci = conf->sc_tx.sci;
		req.sc_id = sc_id;
		req.mcs_id = mcs_dev->idx;

		ret = roc_mcs_tx_sc_sa_map_write(mcs_dev->mdev, &req);
		if (ret) {
			printf("Failed to map TX SC-SA");
			return -EINVAL;
		}
	} else {
		for (i = 0; i < RTE_SECURITY_MACSEC_NUM_AN; i++) {
			struct roc_mcs_rx_sc_sa_map req = {0};

			req.mcs_id = mcs_dev->idx;
			req.sa_index = conf->sc_rx.sa_id[i] & 0x7F;
			req.sa_in_use = conf->sc_rx.sa_in_use[i];
			req.sc_id = sc_id;
			req.an = i & 0x3;
			req.mcs_id = mcs_dev->idx;
			ret = roc_mcs_rx_sc_sa_map_write(mcs_dev->mdev, &req);
			if (ret) {
				printf("Failed to map RX SC-SA");
				return -EINVAL;
			}
		}
	}
	return sc_id;
}

int
cn10k_eth_macsec_sc_destroy(void *device, uint16_t sc_id)
{
	RTE_SET_USED(device);
	RTE_SET_USED(sc_id);

	return 0;
}

struct cnxk_macsec_sess *
cnxk_eth_macsec_sess_get_by_sess(struct cnxk_eth_dev *dev,
				 const struct rte_security_session *sess)
{
	struct cnxk_macsec_sess *macsec_sess = NULL;

	TAILQ_FOREACH(macsec_sess, &dev->mcs_list, entry) {
		if (macsec_sess->sess == sess)
			return macsec_sess;
	}

	return NULL;
}

int
cn10k_eth_macsec_session_create(struct cnxk_eth_dev *dev,
				struct rte_security_session_conf *conf,
				struct rte_security_session *sess,
				struct rte_mempool *mempool)
{
	struct rte_security_macsec_xform *xform = &conf->macsec;
	struct cnxk_macsec_sess *macsec_sess_priv;
	struct roc_mcs_secy_plcy_write_req req;
	struct cnxk_mcs_dev *mcs_dev = dev->mcs_dev;
	uint8_t secy_id = 0;
	uint8_t sectag_tci = 0;
	int ret = 0;

	ret = mcs_resource_alloc(mcs_dev, xform->dir, &secy_id, 1, CNXK_MCS_RSRC_TYPE_SECY);
	if (ret) {
		printf("Failed to allocate SECY id.\n");
		return -ENOMEM;
	}

	req.secy_id = secy_id;
	req.mcs_id = mcs_dev->idx;
	req.dir = xform->dir;
	req.plcy = 0L;

	if (xform->dir == RTE_SECURITY_MACSEC_DIR_TX) {
		sectag_tci = ((uint8_t)xform->tx_secy.sectag_version << 5) |
				((uint8_t)xform->tx_secy.end_station << 4) |
				((uint8_t)xform->tx_secy.send_sci << 3) |
				((uint8_t)xform->tx_secy.scb << 2) |
				((uint8_t)xform->tx_secy.encrypt << 1) |
				(uint8_t)xform->tx_secy.encrypt;
		req.plcy = ((uint64_t)xform->tx_secy.mtu << 48) |
			   (((uint64_t)sectag_tci & 0x3F) << 40) |
			   (((uint64_t)xform->tx_secy.sectag_off & 0x7F) << 32) |
			   ((uint64_t)xform->tx_secy.sectag_insert_mode << 30) |
			   ((uint64_t)xform->tx_secy.icv_include_da_sa << 28) |
			   (((uint64_t)xform->cipher_off & 0x7F) << 20) |
			   ((uint64_t)xform->alg << 12) |
			   ((uint64_t)xform->tx_secy.protect_frames << 4) |
			   (uint64_t)xform->tx_secy.ctrl_port_enable;
	} else {
		req.plcy = ((uint64_t)xform->rx_secy.replay_win_sz << 32) |
			   ((uint64_t)xform->rx_secy.replay_protect << 30) |
			   ((uint64_t)xform->rx_secy.icv_include_da_sa << 28) |
			   (((uint64_t)xform->cipher_off & 0x7F) << 20) |
			   ((uint64_t)xform->alg << 12) |
			   ((uint64_t)xform->rx_secy.preserve_sectag << 9) |
			   ((uint64_t)xform->rx_secy.preserve_icv << 8) |
			   ((uint64_t)xform->rx_secy.validate_frames << 4) |
			   (uint64_t)xform->rx_secy.ctrl_port_enable;
	}

	ret = roc_mcs_secy_policy_write(mcs_dev->mdev, &req);
	if (ret) {
		printf("\n Failed to configure SECY");
		return -EINVAL;
	}

	/*get session priv*/
	if (rte_mempool_get(mempool, (void **)&macsec_sess_priv)) {
		plt_err("Could not allocate security session private data");
		return -ENOMEM;
	}

	macsec_sess_priv->sci = xform->sci;
	macsec_sess_priv->sc_id = xform->sc_id;
	macsec_sess_priv->secy_id = secy_id;
	macsec_sess_priv->dir = xform->dir;

	TAILQ_INSERT_TAIL(&dev->mcs_list, macsec_sess_priv, entry);
	set_sec_session_private_data(sess, (void *)macsec_sess_priv);

	return 0;
}

int
cn10k_eth_macsec_session_destroy(void *device, struct rte_security_session *sess)
{
	RTE_SET_USED(device);
	RTE_SET_USED(sess);

	return 0;
}

int
cn10k_mcs_flow_configure(struct rte_eth_dev *eth_dev,
			 const struct rte_flow_attr *attr __rte_unused,
			 const struct rte_flow_item pattern[],
			 const struct rte_flow_action actions[],
			 struct rte_flow_error *error __rte_unused,
			 void **mcs_flow)
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct roc_mcs_flowid_entry_write_req req = {0};
	struct cnxk_mcs_dev *mcs_dev = dev->mcs_dev;
	struct cnxk_mcs_flow_opts opts = {0};
	struct cnxk_macsec_sess *sess = cnxk_eth_macsec_sess_get_by_sess(dev,
			(const struct rte_security_session *)actions->conf);
	const struct rte_flow_item_eth *eth_item = NULL;
	struct rte_ether_addr src;
	struct rte_ether_addr dst;
	int ret;
	int i = 0;

	ret = mcs_resource_alloc(mcs_dev, sess->dir, &(sess->flow_id), 1, CNXK_MCS_RSRC_TYPE_FLOWID);
	if (ret) {
		printf("Failed to allocate FLow id.\n");
		return -ENOMEM;
	}
	req.sci = sess->sci;
	req.flow_id = sess->flow_id;
	req.secy_id = sess->secy_id;
	req.sc_id = sess->sc_id;
	req.ena = 1;
	req.ctr_pkt = 0; /* TBD */
	req.mcs_id = mcs_dev->idx;
	req.dir = sess->dir;

	while (pattern[i].type != RTE_FLOW_ITEM_TYPE_END) {
		if (pattern[i].type == RTE_FLOW_ITEM_TYPE_ETH)
			eth_item = pattern[i].spec;
		else
			printf("%s:%d unhandled flow item : %d", __func__, __LINE__,
					pattern[i].type);
		i++;
	}
	if (eth_item) {
		dst = eth_item->hdr.dst_addr;
		src = eth_item->hdr.src_addr;

		/* Find ways to fill opts */

		req.data[0] = (uint64_t)dst.addr_bytes[0] << 40 | (uint64_t)dst.addr_bytes[1] << 32 |
			      (uint64_t)dst.addr_bytes[2] << 24 | (uint64_t)dst.addr_bytes[3] << 16 |
			      (uint64_t)dst.addr_bytes[4] << 8 | (uint64_t)dst.addr_bytes[5] |
			      (uint64_t)src.addr_bytes[5] << 48 | (uint64_t)src.addr_bytes[4] << 56;
		req.data[1] = (uint64_t)src.addr_bytes[3] | (uint64_t)src.addr_bytes[2] << 8 |
			      (uint64_t)src.addr_bytes[1] << 16 | (uint64_t)src.addr_bytes[0] << 24 |
			      (uint64_t)eth_item->hdr.ether_type << 32 |
			      ((uint64_t)opts.outer_tag_id & 0xFFFF) << 48;
		req.data[2] = ((uint64_t)opts.outer_tag_id & 0xF0000) |
			      ((uint64_t)opts.outer_priority & 0xF) << 4 |
			      ((uint64_t)opts.second_outer_tag_id & 0xFFFFF) << 8 |
			      ((uint64_t)opts.second_outer_priority & 0xF) << 28 |
			      ((uint64_t)opts.bonus_data << 32) |
			      ((uint64_t)opts.tag_match_bitmap << 48) |
			      ((uint64_t)opts.packet_type & 0xF) << 56 |
			      ((uint64_t)opts.outer_vlan_type & 0x7) << 60 |
			      ((uint64_t)opts.inner_vlan_type & 0x1) << 63;
		req.data[3] = ((uint64_t)opts.inner_vlan_type & 0x6) |
			      ((uint64_t)opts.num_tags & 0x7F) << 2 | ((uint64_t)opts.express & 1) << 9 |
			      ((uint64_t)opts.port & 0x3) << 10 |
			      ((uint64_t)opts.flowid_user & 0xF) << 12;

		req.mask[0] = 0x0;
		req.mask[1] = 0xFFFFFFFF00000000;
		req.mask[2] = 0xFFFFFFFFFFFFFFFF;
		req.mask[3] = 0xFFFFFFFFFFFFF3FF;

		ret = roc_mcs_flowid_entry_write(mcs_dev->mdev, &req);
		if (ret)
			return ret;

		*mcs_flow = &req;
	} else {
		printf("\nFlow not confirured");
		return -EINVAL;
	}
	return 0;
}

int
cn10k_eth_macsec_sa_stats_get(void *device, uint16_t sa_id,
			    struct rte_security_macsec_sa_stats *stats)
{
	RTE_SET_USED(device);
	RTE_SET_USED(sa_id);
	RTE_SET_USED(stats);

	return 0;
}

int
cn10k_eth_macsec_sc_stats_get(void *device, uint16_t sc_id,
			    struct rte_security_macsec_sc_stats *stats)
{
	RTE_SET_USED(device);
	RTE_SET_USED(sc_id);
	RTE_SET_USED(stats);

	return 0;
}

void
cnxk_mcs_dev_fini(struct cnxk_mcs_dev *mcs_dev)
{
	/* Cleanup MACsec dev */
	roc_mcs_dev_fini(mcs_dev->mdev);

	plt_free(mcs_dev);
}

struct cnxk_mcs_dev *
cnxk_mcs_dev_init(uint8_t mcs_idx)
{
	struct cnxk_mcs_dev *mcs_dev;

	mcs_dev = plt_zmalloc(sizeof(struct cnxk_mcs_dev), PLT_CACHE_LINE_SIZE);
	if (!mcs_dev)
		return NULL;

	mcs_dev->mdev = roc_mcs_dev_init(mcs_dev->idx);
	if (!mcs_dev->mdev) {
		plt_free(mcs_dev);
		return NULL;
	}
	mcs_dev->idx = mcs_idx;

	return mcs_dev;
}

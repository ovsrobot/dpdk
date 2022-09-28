/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

int
roc_mcs_alloc_rsrc(struct roc_mcs *mcs, struct roc_mcs_alloc_rsrc_req *req,
		   struct roc_mcs_alloc_rsrc_rsp *rsp)
{
	struct mcs_priv *priv = roc_mcs_to_mcs_priv(mcs);
	struct mcs_alloc_rsrc_req *rsrc_req;
	struct mcs_alloc_rsrc_rsp *rsrc_rsp;
	int rc, i;

	MCS_SUPPORT_CHECK;

	if (req == NULL || rsp == NULL)
		return -EINVAL;

	rsrc_req = mbox_alloc_msg_mcs_alloc_resources(mcs->mbox);
	if (rsrc_req == NULL)
		return -ENOMEM;

	rsrc_req->rsrc_type = req->rsrc_type;
	rsrc_req->rsrc_cnt = req->rsrc_cnt;
	rsrc_req->mcs_id = req->mcs_id;
	rsrc_req->dir = req->dir;
	rsrc_req->all = req->all;

	rc = mbox_process_msg(mcs->mbox, (void *)&rsrc_rsp);
	if (rc)
		return rc;

	if (rsrc_rsp->all) {
		rsrc_rsp->rsrc_cnt = 1;
		rsrc_rsp->rsrc_type = 0xFF;
	}

	for (i = 0; i < rsrc_rsp->rsrc_cnt; i++) {
		switch (rsrc_rsp->rsrc_type) {
		case MCS_RSRC_TYPE_FLOWID:
			rsp->flow_ids[i] = rsrc_rsp->flow_ids[i];
			plt_bitmap_set(priv->tcam_bmap,
				       rsp->flow_ids[i] +
					       ((req->dir == MCS_TX) ? priv->tcam_entries : 0));
			break;
		case MCS_RSRC_TYPE_SECY:
			rsp->secy_ids[i] = rsrc_rsp->secy_ids[i];
			plt_bitmap_set(priv->secy_bmap,
				       rsp->secy_ids[i] +
					       ((req->dir == MCS_TX) ? priv->secy_entries : 0));
			break;
		case MCS_RSRC_TYPE_SC:
			rsp->sc_ids[i] = rsrc_rsp->sc_ids[i];
			plt_bitmap_set(priv->sc_bmap,
				       rsp->sc_ids[i] +
					       ((req->dir == MCS_TX) ? priv->sc_entries : 0));
			break;
		case MCS_RSRC_TYPE_SA:
			rsp->sa_ids[2 * i] = rsrc_rsp->sa_ids[2 * i];
			rsp->sa_ids[2 * i + 1] = rsrc_rsp->sa_ids[2 * i + 1];
			plt_bitmap_set(priv->sa_bmap,
				       rsp->sa_ids[i] +
					       ((req->dir == MCS_TX) ? priv->sa_entries : 0));
			plt_bitmap_set(priv->sa_bmap,
				       rsp->sa_ids[2 * i + 1] +
					       ((req->dir == MCS_TX) ? priv->sa_entries : 0));
			break;
		default:
			rsp->flow_ids[i] = rsrc_rsp->flow_ids[i];
			rsp->secy_ids[i] = rsrc_rsp->secy_ids[i];
			rsp->sc_ids[i] = rsrc_rsp->sc_ids[i];
			rsp->sa_ids[2 * i] = rsrc_rsp->sa_ids[2 * i];
			rsp->sa_ids[2 * i + 1] = rsrc_rsp->sa_ids[2 * i + 1];
			plt_bitmap_set(priv->tcam_bmap,
				       rsp->flow_ids[i] +
					       ((req->dir == MCS_TX) ? priv->tcam_entries : 0));
			plt_bitmap_set(priv->secy_bmap,
				       rsp->secy_ids[i] +
					       ((req->dir == MCS_TX) ? priv->secy_entries : 0));
			plt_bitmap_set(priv->sc_bmap,
				       rsp->sc_ids[i] +
					       ((req->dir == MCS_TX) ? priv->sc_entries : 0));
			plt_bitmap_set(priv->sa_bmap,
				       rsp->sa_ids[i] +
					       ((req->dir == MCS_TX) ? priv->sa_entries : 0));
			plt_bitmap_set(priv->sa_bmap,
				       rsp->sa_ids[2 * i + 1] +
					       ((req->dir == MCS_TX) ? priv->sa_entries : 0));
			break;
		}
	}
	rsp->rsrc_type = rsrc_rsp->rsrc_type;
	rsp->rsrc_cnt = rsrc_rsp->rsrc_cnt;
	rsp->mcs_id = rsrc_rsp->mcs_id;
	rsp->dir = rsrc_rsp->dir;
	rsp->all = rsrc_rsp->all;

	return 0;
}

int
roc_mcs_free_rsrc(struct roc_mcs *mcs, struct roc_mcs_free_rsrc_req *free_req)
{
	struct mcs_priv *priv = roc_mcs_to_mcs_priv(mcs);
	struct mcs_free_rsrc_req *req;
	struct msg_rsp *rsp;
	int rc;

	MCS_SUPPORT_CHECK;

	if (free_req == NULL)
		return -EINVAL;

	req = mbox_alloc_msg_mcs_free_resources(mcs->mbox);
	if (req == NULL)
		return -ENOMEM;

	req->rsrc_id = free_req->rsrc_id;
	req->rsrc_type = free_req->rsrc_type;
	req->mcs_id = free_req->mcs_id;
	req->dir = free_req->dir;
	req->all = free_req->all;

	rc = mbox_process_msg(mcs->mbox, (void *)&rsp);
	if (rc)
		return rc;

	switch (free_req->rsrc_type) {
	case MCS_RSRC_TYPE_FLOWID:
		plt_bitmap_clear(priv->tcam_bmap,
				 free_req->rsrc_id +
					 ((req->dir == MCS_TX) ? priv->tcam_entries : 0));
		break;
	case MCS_RSRC_TYPE_SECY:
		plt_bitmap_clear(priv->secy_bmap,
				 free_req->rsrc_id +
					 ((req->dir == MCS_TX) ? priv->secy_entries : 0));
		break;
	case MCS_RSRC_TYPE_SC:
		plt_bitmap_clear(priv->sc_bmap,
				 free_req->rsrc_id + ((req->dir == MCS_TX) ? priv->sc_entries : 0));
		break;
	case MCS_RSRC_TYPE_SA:
		plt_bitmap_clear(priv->sa_bmap,
				 free_req->rsrc_id + ((req->dir == MCS_TX) ? priv->sa_entries : 0));
		break;
	default:
		break;
	}

	return rc;
}

int
roc_mcs_sa_policy_write(struct roc_mcs *mcs, struct roc_mcs_sa_plcy_write_req *sa_plcy)
{
	struct mcs_sa_plcy_write_req *sa;
	struct msg_rsp *rsp;

	MCS_SUPPORT_CHECK;

	if (sa_plcy == NULL)
		return -EINVAL;

	sa = mbox_alloc_msg_mcs_sa_plcy_write(mcs->mbox);
	if (sa == NULL)
		return -ENOMEM;

	mbox_memcpy(sa->plcy, sa_plcy->plcy, sizeof(uint64_t) * 2 * 9);
	sa->sa_index[0] = sa_plcy->sa_index[0];
	sa->sa_index[1] = sa_plcy->sa_index[1];
	sa->sa_cnt = sa_plcy->sa_cnt;
	sa->mcs_id = sa_plcy->mcs_id;
	sa->dir = sa_plcy->dir;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_sa_policy_read(struct roc_mcs *mcs __plt_unused,
		       struct roc_mcs_sa_plcy_write_req *sa __plt_unused)
{
	MCS_SUPPORT_CHECK;

	return -ENOTSUP;
}

int
roc_mcs_pn_table_write(struct roc_mcs *mcs, struct roc_mcs_pn_table_write_req *pn_table)
{
	struct mcs_pn_table_write_req *pn;
	struct msg_rsp *rsp;

	MCS_SUPPORT_CHECK;

	if (pn_table == NULL)
		return -EINVAL;

	pn = mbox_alloc_msg_mcs_pn_table_write(mcs->mbox);
	if (pn == NULL)
		return -ENOMEM;

	pn->next_pn = pn_table->next_pn;
	pn->pn_id = pn_table->pn_id;
	pn->mcs_id = pn_table->mcs_id;
	pn->dir = pn_table->dir;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_pn_table_read(struct roc_mcs *mcs __plt_unused,
		      struct roc_mcs_pn_table_write_req *sa __plt_unused)
{
	MCS_SUPPORT_CHECK;

	return -ENOTSUP;
}

int
roc_mcs_rx_sc_cam_write(struct roc_mcs *mcs, struct roc_mcs_rx_sc_cam_write_req *rx_sc_cam)
{
	struct mcs_rx_sc_cam_write_req *rx_sc;
	struct msg_rsp *rsp;

	MCS_SUPPORT_CHECK;

	if (rx_sc_cam == NULL)
		return -EINVAL;

	rx_sc = mbox_alloc_msg_mcs_rx_sc_cam_write(mcs->mbox);
	if (rx_sc == NULL)
		return -ENOMEM;

	rx_sc->sci = rx_sc_cam->sci;
	rx_sc->secy_id = rx_sc_cam->secy_id;
	rx_sc->sc_id = rx_sc_cam->sc_id;
	rx_sc->mcs_id = rx_sc_cam->mcs_id;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_rx_sc_cam_read(struct roc_mcs *mcs __plt_unused,
		       struct roc_mcs_rx_sc_cam_write_req *rx_sc_cam __plt_unused)
{
	MCS_SUPPORT_CHECK;

	return -ENOTSUP;
}

int
roc_mcs_rx_sc_cam_enable(struct roc_mcs *mcs __plt_unused,
			 struct roc_mcs_rx_sc_cam_write_req *rx_sc_cam __plt_unused)
{
	MCS_SUPPORT_CHECK;

	return -ENOTSUP;
}

int
roc_mcs_secy_policy_write(struct roc_mcs *mcs, struct roc_mcs_secy_plcy_write_req *secy_plcy)
{
	struct mcs_secy_plcy_write_req *secy;
	struct msg_rsp *rsp;

	MCS_SUPPORT_CHECK;

	if (secy_plcy == NULL)
		return -EINVAL;

	secy = mbox_alloc_msg_mcs_secy_plcy_write(mcs->mbox);
	if (secy == NULL)
		return -ENOMEM;

	secy->plcy = secy_plcy->plcy;
	secy->secy_id = secy_plcy->secy_id;
	secy->mcs_id = secy_plcy->mcs_id;
	secy->dir = secy_plcy->dir;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_secy_policy_read(struct roc_mcs *mcs __plt_unused,
			 struct roc_mcs_rx_sc_cam_write_req *rx_sc_cam __plt_unused)
{
	MCS_SUPPORT_CHECK;

	return -ENOTSUP;
}

int
roc_mcs_rx_sc_sa_map_write(struct roc_mcs *mcs, struct roc_mcs_rx_sc_sa_map *rx_sc_sa_map)
{
	struct mcs_rx_sc_sa_map *sa_map;
	struct msg_rsp *rsp;

	MCS_SUPPORT_CHECK;

	if (rx_sc_sa_map == NULL)
		return -EINVAL;

	sa_map = mbox_alloc_msg_mcs_rx_sc_sa_map_write(mcs->mbox);
	if (sa_map == NULL)
		return -ENOMEM;

	sa_map->sa_index = rx_sc_sa_map->sa_index;
	sa_map->sa_in_use = rx_sc_sa_map->sa_in_use;
	sa_map->sc_id = rx_sc_sa_map->sc_id;
	sa_map->an = rx_sc_sa_map->an;
	sa_map->mcs_id = rx_sc_sa_map->mcs_id;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_rx_sc_sa_map_read(struct roc_mcs *mcs __plt_unused,
			  struct roc_mcs_rx_sc_sa_map *rx_sc_sa_map __plt_unused)
{
	MCS_SUPPORT_CHECK;

	return -ENOTSUP;
}

int
roc_mcs_tx_sc_sa_map_write(struct roc_mcs *mcs, struct roc_mcs_tx_sc_sa_map *tx_sc_sa_map)
{
	struct mcs_tx_sc_sa_map *sa_map;
	struct msg_rsp *rsp;

	MCS_SUPPORT_CHECK;

	if (tx_sc_sa_map == NULL)
		return -EINVAL;

	sa_map = mbox_alloc_msg_mcs_tx_sc_sa_map_write(mcs->mbox);
	if (sa_map == NULL)
		return -ENOMEM;

	sa_map->sa_index0 = tx_sc_sa_map->sa_index0;
	sa_map->sa_index1 = tx_sc_sa_map->sa_index1;
	sa_map->rekey_ena = tx_sc_sa_map->rekey_ena;
	sa_map->sa_index0_vld = tx_sc_sa_map->sa_index0_vld;
	sa_map->sa_index1_vld = tx_sc_sa_map->sa_index1_vld;
	sa_map->tx_sa_active = tx_sc_sa_map->tx_sa_active;
	sa_map->sectag_sci = tx_sc_sa_map->sectag_sci;
	sa_map->sc_id = tx_sc_sa_map->sc_id;
	sa_map->mcs_id = tx_sc_sa_map->mcs_id;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_tx_sc_sa_map_read(struct roc_mcs *mcs __plt_unused,
			  struct roc_mcs_tx_sc_sa_map *tx_sc_sa_map __plt_unused)
{
	MCS_SUPPORT_CHECK;

	return -ENOTSUP;
}

int
roc_mcs_flowid_entry_write(struct roc_mcs *mcs, struct roc_mcs_flowid_entry_write_req *flowid_req)
{
	struct mcs_flowid_entry_write_req *flow_req;
	struct msg_rsp *rsp;

	MCS_SUPPORT_CHECK;

	if (flowid_req == NULL)
		return -EINVAL;

	flow_req = mbox_alloc_msg_mcs_flowid_entry_write(mcs->mbox);
	if (flow_req == NULL)
		return -ENOMEM;

	mbox_memcpy(flow_req->data, flowid_req->data, sizeof(uint64_t) * 4);
	mbox_memcpy(flow_req->mask, flowid_req->mask, sizeof(uint64_t) * 4);
	flow_req->sci = flowid_req->sci;
	flow_req->flow_id = flowid_req->flow_id;
	flow_req->secy_id = flowid_req->secy_id;
	flow_req->sc_id = flowid_req->sc_id;
	flow_req->ena = flowid_req->ena;
	flow_req->ctr_pkt = flowid_req->ctr_pkt;
	flow_req->mcs_id = flowid_req->mcs_id;
	flow_req->dir = flowid_req->dir;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_flowid_entry_read(struct roc_mcs *mcs __plt_unused,
			  struct roc_mcs_flowid_entry_write_req *flowid_rsp __plt_unused)
{
	MCS_SUPPORT_CHECK;

	return -ENOTSUP;
}

int
roc_mcs_flowid_entry_enable(struct roc_mcs *mcs, struct roc_mcs_flowid_ena_dis_entry *entry)
{
	struct mcs_flowid_ena_dis_entry *flow_entry;
	struct msg_rsp *rsp;

	MCS_SUPPORT_CHECK;

	if (entry == NULL)
		return -EINVAL;

	flow_entry = mbox_alloc_msg_mcs_flowid_ena_entry(mcs->mbox);
	if (flow_entry == NULL)
		return -ENOMEM;

	flow_entry->flow_id = entry->flow_id;
	flow_entry->ena = entry->ena;
	flow_entry->mcs_id = entry->mcs_id;
	flow_entry->dir = entry->dir;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

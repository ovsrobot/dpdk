/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <rte_dev.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>
#include <rte_ethdev.h>

#include "ntconnect.h"
#include "ntconnect_api_statistic.h"
#include "ntos_system.h"
#include "ntconn_modules.h"
#include "ntconn_mod_helper.h"
#include "nt_util.h"
#include "ntlog.h"
#include "ntnic_xstats.h"

#define STAT_VERSION_MAJOR 0U
#define STAT_VERSION_MINOR 2U

#define this_module_name "stat"

/*
 * Supported Stat Layout Versions
 */
#define NUM_LAYOUT_VERSIONS_SUPPORTED (RTE_DIM(layout_versions_supported))
static int layout_versions_supported[] = {
	6,
	/*
	 * Add here other layout versions to support
	 * When more versions are added, add new version dependent binary reply structures
	 * in ntconnect_api.h file for client to select on reading layout_version
	 */
};

enum snap_addr_select_e {
	SNAP_COLORS,
	SNAP_QUEUES,
	SNAP_RX_PORT,
	SNAP_TX_PORT,
	SNAP_ADDR_COUNT
};

struct snap_addr_s {
	const uint64_t *ptr;
	unsigned int size;
};

struct snaps_s {
	int client_id;
	/* Pointers into buffer */
	struct snap_addr_s snap_addr[SNAP_ADDR_COUNT];
	uint64_t *buffer;
	struct snaps_s *next;
};

static struct stat_hdl {
	struct drv_s *drv;
	nt4ga_stat_t *p_nt4ga_stat;
	struct snaps_s *snaps_base;
} stat_hdl;

enum stat_type_e {
	STAT_TYPE_COLOR,
	STAT_TYPE_QUEUE,
	STAT_TYPE_RX,
	STAT_TYPE_TX,
	STAT_TYPE_FLOWMATCHER
};

static int func_get_snap_colors(void *hdl, int client_id,
				struct ntconn_header_s *hdr, char **data,
				int *len);
static int func_get_snap_queues(void *hdl, int client_id,
				struct ntconn_header_s *hdr, char **data,
				int *len);
static int func_get_snap_rx_port(void *hdl, int client_id,
				 struct ntconn_header_s *hdr, char **data,
				 int *len);
static int func_get_snap_tx_port(void *hdl, int client_id,
				 struct ntconn_header_s *hdr, char **data,
				 int *len);
static struct func_s func_snap_level2[] = {
	{ "colors", NULL, func_get_snap_colors },
	{ "queues", NULL, func_get_snap_queues },
	{ "rx_counters", NULL, func_get_snap_rx_port },
	{ "tx_counters", NULL, func_get_snap_tx_port },
	{ NULL, NULL, NULL },
};

static int func_get_layout_version(void *hdl, int client_id,
				   struct ntconn_header_s *hdr, char **data,
				   int *len);
static int func_get_flm(void *hdl, int client_id, struct ntconn_header_s *hdr,
			char **data, int *len);
static int func_get_color(void *hdl, int client_id, struct ntconn_header_s *hdr,
			  char **data, int *len);
static int func_get_queue(void *hdl, int client_id, struct ntconn_header_s *hdr,
			  char **data, int *len);
static int func_get_rx_counters(void *hdl, int client_id,
				struct ntconn_header_s *hdr, char **data,
				int *len);
static int func_get_tx_counters(void *hdl, int client_id,
				struct ntconn_header_s *hdr, char **data,
				int *len);
static int func_get_flm_layout_version(void *hdl, int client_id,
				       struct ntconn_header_s *hdr, char **data,
				       int *len);

static struct func_s funcs_get_level1[] = {
	{ "snapshot", func_snap_level2, NULL },
	{ "layout_version", NULL, func_get_layout_version },
	{ "flm", NULL, func_get_flm },
	{ "colors", NULL, func_get_color },
	{ "queues", NULL, func_get_queue },
	{ "rx_counters", NULL, func_get_rx_counters },
	{ "tx_counters", NULL, func_get_tx_counters },
	{ "flm_layout_version", NULL, func_get_flm_layout_version },
	{ NULL, NULL, NULL },
};

/*
 * Entry level
 */
static int func_snapshot(void *hdl, int client_id, struct ntconn_header_s *hdr,
			 char **data, int *len);
static struct func_s stat_entry_funcs[] = {
	{ "get", funcs_get_level1, NULL },
	{ "snapshot", NULL, func_snapshot },
	{ NULL, NULL, NULL },
};

static int read_flm(nt4ga_stat_t *hwstat, uint64_t *val, int nbc)
{
	struct ntc_stat_get_data_s *cdata = (struct ntc_stat_get_data_s *)val;

	cdata->nb_counters = (uint64_t)nbc;
	cdata->timestamp = hwstat->last_timestamp;
	cdata->is_virt = hwstat->mp_nthw_stat->mb_is_vswitch;

	struct rte_eth_xstat stats[100];
	struct rte_eth_xstat_name names[100];
	int cnt_names = nthw_xstats_get_names(hwstat, names, 100,
					      hwstat->mp_nthw_stat->mb_is_vswitch);
	int cnt_values = nthw_xstats_get(hwstat, stats, 100,
					 hwstat->mp_nthw_stat->mb_is_vswitch, 0);
	assert(cnt_names == cnt_values);

	/* virt/cap same */
	struct flowmatcher_type_fields_s *flm =
		(struct flowmatcher_type_fields_s *)cdata->data;
	if (hwstat->mp_stat_structs_flm) {
		int c;

		for (c = 0; c < nbc; c++) {
			flm->current = hwstat->mp_stat_structs_flm->current;
			flm->learn_done = hwstat->mp_stat_structs_flm->learn_done;
			flm->learn_ignore =
				hwstat->mp_stat_structs_flm->learn_ignore;
			flm->learn_fail = hwstat->mp_stat_structs_flm->learn_fail;
			flm->unlearn_done =
				hwstat->mp_stat_structs_flm->unlearn_done;
			flm->unlearn_ignore =
				hwstat->mp_stat_structs_flm->unlearn_ignore;
			flm->auto_unlearn_done =
				hwstat->mp_stat_structs_flm->auto_unlearn_done;
			flm->auto_unlearn_ignore =
				hwstat->mp_stat_structs_flm->auto_unlearn_ignore;
			flm->auto_unlearn_fail =
				hwstat->mp_stat_structs_flm->auto_unlearn_fail;
			flm->timeout_unlearn_done =
				hwstat->mp_stat_structs_flm->timeout_unlearn_done;
			flm->rel_done = hwstat->mp_stat_structs_flm->rel_done;
			flm->rel_ignore = hwstat->mp_stat_structs_flm->rel_ignore;
			flm->prb_done = hwstat->mp_stat_structs_flm->prb_done;
			flm->prb_ignore = hwstat->mp_stat_structs_flm->prb_ignore;

			flm->sta_done = hwstat->mp_stat_structs_flm->sta_done;
			flm->inf_done = hwstat->mp_stat_structs_flm->inf_done;
			flm->inf_skip = hwstat->mp_stat_structs_flm->inf_skip;
			flm->pck_hit = hwstat->mp_stat_structs_flm->pck_hit;
			flm->pck_miss = hwstat->mp_stat_structs_flm->pck_miss;
			flm->pck_unh = hwstat->mp_stat_structs_flm->pck_unh;
			flm->pck_dis = hwstat->mp_stat_structs_flm->pck_dis;
			flm->csh_hit = hwstat->mp_stat_structs_flm->csh_hit;
			flm->csh_miss = hwstat->mp_stat_structs_flm->csh_miss;
			flm->csh_unh = hwstat->mp_stat_structs_flm->csh_unh;
			flm->cuc_start = hwstat->mp_stat_structs_flm->cuc_start;
			flm->cuc_move = hwstat->mp_stat_structs_flm->cuc_move;
		}
	} else {
		memset(flm, 0, sizeof(*hwstat->mp_stat_structs_flm));
	}
	return nbc * NUM_STAT_RECORD_TYPE_FLOWMATCHER + STAT_INFO_ELEMENTS;
}

static int read_colors(nt4ga_stat_t *hwstat, uint64_t *val, int nbc)
{
	struct ntc_stat_get_data_s *cdata = (struct ntc_stat_get_data_s *)val;

	cdata->nb_counters = (uint64_t)nbc;
	cdata->timestamp = hwstat->last_timestamp;
	cdata->is_virt = hwstat->mp_nthw_stat->mb_is_vswitch;

	/* virt/cap same */
	struct color_type_fields_s *clr =
		(struct color_type_fields_s *)cdata->data;
	int c;

	for (c = 0; c < nbc; c++) {
		clr->pkts = hwstat->mp_stat_structs_color[c].color_packets;
		clr->octets = hwstat->mp_stat_structs_color[c].color_bytes;
		clr->tcp_flgs =
			(uint64_t)hwstat->mp_stat_structs_color[c].tcp_flags;
		clr++;
	}
	return nbc * NUM_STAT_RECORD_TYPE_COLOR + STAT_INFO_ELEMENTS;
}

static int read_queues(nt4ga_stat_t *hwstat, uint64_t *val, int nbq)
{
	struct ntc_stat_get_data_s *qdata = (struct ntc_stat_get_data_s *)val;

	qdata->nb_counters = (uint64_t)nbq;
	qdata->timestamp = hwstat->last_timestamp;
	qdata->is_virt = hwstat->mp_nthw_stat->mb_is_vswitch;

	/* virt/cap same */
	struct queue_type_fields_s *queue =
		(struct queue_type_fields_s *)qdata->data;
	int q;

	for (q = 0; q < nbq; q++) {
		queue->flush_pkts = hwstat->mp_stat_structs_hb[q].flush_packets;
		queue->drop_pkts = hwstat->mp_stat_structs_hb[q].drop_packets;
		queue->fwd_pkts = hwstat->mp_stat_structs_hb[q].fwd_packets;
		queue->dbs_drop_pkts = hwstat->mp_stat_structs_hb[q].dbs_drop_packets;
		queue->flush_octets = hwstat->mp_stat_structs_hb[q].flush_bytes;
		queue->drop_octets = hwstat->mp_stat_structs_hb[q].drop_bytes;
		queue->fwd_octets = hwstat->mp_stat_structs_hb[q].fwd_bytes;
		queue->dbs_drop_octets = hwstat->mp_stat_structs_hb[q].dbs_drop_bytes;
		queue++;
	}
	return nbq * NUM_STAT_RECORD_TYPE_QUEUE + STAT_INFO_ELEMENTS;
}

static void copy_rmon_stat(struct port_counters_v2 *cptr,
			    struct stat_rmon_s *rmon)
{
	rmon->drop_events = cptr->drop_events;
	rmon->pkts = cptr->pkts;
	rmon->octets = cptr->octets;
	rmon->broadcast_pkts = cptr->broadcast_pkts;
	rmon->multicast_pkts = cptr->multicast_pkts;
	rmon->unicast_pkts = cptr->unicast_pkts;
	rmon->pkts_alignment = cptr->pkts_alignment;
	rmon->pkts_code_violation = cptr->pkts_code_violation;
	rmon->pkts_crc = cptr->pkts_crc;
	rmon->undersize_pkts = cptr->undersize_pkts;
	rmon->oversize_pkts = cptr->oversize_pkts;
	rmon->fragments = cptr->fragments;
	rmon->jabbers_not_truncated = cptr->jabbers_not_truncated;
	rmon->jabbers_truncated = cptr->jabbers_truncated;
	rmon->pkts_64_octets = cptr->pkts_64_octets;
	rmon->pkts_65_to_127_octets = cptr->pkts_65_to_127_octets;
	rmon->pkts_128_to_255_octets = cptr->pkts_128_to_255_octets;
	rmon->pkts_256_to_511_octets = cptr->pkts_256_to_511_octets;
	rmon->pkts_512_to_1023_octets = cptr->pkts_512_to_1023_octets;
	rmon->pkts_1024_to_1518_octets = cptr->pkts_1024_to_1518_octets;
	rmon->pkts_1519_to_2047_octets = cptr->pkts_1519_to_2047_octets;
	rmon->pkts_2048_to_4095_octets = cptr->pkts_2048_to_4095_octets;
	rmon->pkts_4096_to_8191_octets = cptr->pkts_4096_to_8191_octets;
	rmon->pkts_8192_to_max_octets = cptr->pkts_8192_to_max_octets;
}

static int read_rx_counters(nt4ga_stat_t *hwstat, uint64_t *val, int nbp)
{
	struct ntc_stat_get_data_s *rxdata = (struct ntc_stat_get_data_s *)val;

	rxdata->nb_counters = (uint64_t)nbp;
	rxdata->timestamp = hwstat->last_timestamp;
	rxdata->is_virt = hwstat->mp_nthw_stat->mb_is_vswitch;

	if (rxdata->is_virt) {
		struct rtx_type_fields_virt_s *rxc =
			(struct rtx_type_fields_virt_s *)rxdata->data;
		int p;

		for (p = 0; p < nbp; p++) {
			rxc->octets =
				hwstat->virt.mp_stat_structs_port_rx[p].octets;
			rxc->pkts = hwstat->virt.mp_stat_structs_port_rx[p].pkts;
			rxc->drop_events =
				hwstat->virt.mp_stat_structs_port_rx[p].drop_events;
			rxc->qos_drop_octets =
				hwstat->virt.mp_stat_structs_port_rx[p]
				.qos_drop_octets;
			rxc->qos_drop_pkts = hwstat->virt.mp_stat_structs_port_rx[p]
					     .qos_drop_pkts;
			rxc++;
		}
		return nbp * NUM_STAT_RECORD_TYPE_RX_PORT_VIRT +
		       STAT_INFO_ELEMENTS;
	} else {
		struct rx_type_fields_cap_s *rxc =
			(struct rx_type_fields_cap_s *)rxdata->data;
		int p;

		for (p = 0; p < nbp; p++) {
			copy_rmon_stat(&hwstat->cap.mp_stat_structs_port_rx[p],
					&rxc->rmon);

			/* Rx only port counters */
			rxc->mac_drop_events =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.mac_drop_events;
			rxc->pkts_lr =
				hwstat->cap.mp_stat_structs_port_rx[p].pkts_lr;
			rxc->duplicate =
				hwstat->cap.mp_stat_structs_port_rx[p].duplicate;
			rxc->pkts_ip_chksum_error =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.pkts_ip_chksum_error;
			rxc->pkts_udp_chksum_error =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.pkts_udp_chksum_error;
			rxc->pkts_tcp_chksum_error =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.pkts_tcp_chksum_error;
			rxc->pkts_giant_undersize =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.pkts_giant_undersize;
			rxc->pkts_baby_giant =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.pkts_baby_giant;
			rxc->pkts_not_isl_vlan_mpls =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.pkts_not_isl_vlan_mpls;
			rxc->pkts_isl =
				hwstat->cap.mp_stat_structs_port_rx[p].pkts_isl;
			rxc->pkts_vlan =
				hwstat->cap.mp_stat_structs_port_rx[p].pkts_vlan;
			rxc->pkts_isl_vlan =
				hwstat->cap.mp_stat_structs_port_rx[p].pkts_isl_vlan;
			rxc->pkts_mpls =
				hwstat->cap.mp_stat_structs_port_rx[p].pkts_mpls;
			rxc->pkts_isl_mpls =
				hwstat->cap.mp_stat_structs_port_rx[p].pkts_isl_mpls;
			rxc->pkts_vlan_mpls = hwstat->cap.mp_stat_structs_port_rx[p]
					      .pkts_vlan_mpls;
			rxc->pkts_isl_vlan_mpls =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.pkts_isl_vlan_mpls;
			rxc->pkts_no_filter = hwstat->cap.mp_stat_structs_port_rx[p]
					      .pkts_no_filter;
			rxc->pkts_dedup_drop =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.pkts_dedup_drop;
			rxc->pkts_filter_drop =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.pkts_filter_drop;
			rxc->pkts_overflow =
				hwstat->cap.mp_stat_structs_port_rx[p].pkts_overflow;
			rxc->pkts_dbs_drop =
				hwstat->cap.mp_stat_structs_port_rx[p].pkts_dbs_drop;
			rxc->octets_no_filter =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.octets_no_filter;
			rxc->octets_dedup_drop =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.octets_dedup_drop;
			rxc->octets_filter_drop =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.octets_filter_drop;
			rxc->octets_overflow =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.octets_overflow;
			rxc->octets_dbs_drop =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.octets_dbs_drop;
			rxc->ipft_first_hit = hwstat->cap.mp_stat_structs_port_rx[p]
					      .ipft_first_hit;
			rxc->ipft_first_not_hit =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.ipft_first_not_hit;
			rxc->ipft_mid_hit =
				hwstat->cap.mp_stat_structs_port_rx[p].ipft_mid_hit;
			rxc->ipft_mid_not_hit =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.ipft_mid_not_hit;
			rxc->ipft_last_hit =
				hwstat->cap.mp_stat_structs_port_rx[p].ipft_last_hit;
			rxc->ipft_last_not_hit =
				hwstat->cap.mp_stat_structs_port_rx[p]
				.ipft_last_not_hit;
			rxc++;
		}
		return nbp * NUM_STAT_RECORD_TYPE_RX_PORT_CAP +
		       STAT_INFO_ELEMENTS;
	}
}

static int read_tx_counters(nt4ga_stat_t *hwstat, uint64_t *val, int nbp)
{
	struct ntc_stat_get_data_s *txdata = (struct ntc_stat_get_data_s *)val;

	txdata->nb_counters = (uint64_t)nbp;
	txdata->timestamp = hwstat->last_timestamp;
	txdata->is_virt = hwstat->mp_nthw_stat->mb_is_vswitch;

	if (txdata->is_virt) {
		struct rtx_type_fields_virt_s *txc =
			(struct rtx_type_fields_virt_s *)txdata->data;
		int p;

		for (p = 0; p < nbp; p++) {
			txc->octets =
				hwstat->virt.mp_stat_structs_port_tx[p].octets;
			txc->pkts = hwstat->virt.mp_stat_structs_port_tx[p].pkts;
			txc->drop_events =
				hwstat->virt.mp_stat_structs_port_tx[p].drop_events;
			txc->qos_drop_octets =
				hwstat->virt.mp_stat_structs_port_tx[p]
				.qos_drop_octets;
			txc->qos_drop_pkts = hwstat->virt.mp_stat_structs_port_tx[p]
					     .qos_drop_pkts;
			txc++;
		}
		return nbp * NUM_STAT_RECORD_TYPE_TX_PORT_VIRT +
		       STAT_INFO_ELEMENTS;
	} else {
		struct tx_type_fields_cap_s *txc =
			(struct tx_type_fields_cap_s *)txdata->data;
		int p;

		for (p = 0; p < nbp; p++) {
			copy_rmon_stat(&hwstat->cap.mp_stat_structs_port_tx[p],
					&txc->rmon);
			txc->rmon.pkts = hwstat->a_port_tx_packets_total[p];
			txc++;
		}
		return nbp * NUM_STAT_RECORD_TYPE_TX_PORT_CAP +
		       STAT_INFO_ELEMENTS;
	}
}

static int func_get_layout_version(void *hdl, int client_id _unused,
				   struct ntconn_header_s *hdr _unused,
				   char **data, int *len)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;

	if (!stat->p_nt4ga_stat || !stat->p_nt4ga_stat->mp_nthw_stat) {
		*data = NULL;
		*len = 0;
		return REQUEST_ERR;
	}
	*data = malloc(sizeof(int));
	if (!*data) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return REQUEST_ERR;
	}

	*(int *)*data = stat->p_nt4ga_stat->mp_nthw_stat->mn_stat_layout_version;
	*len = sizeof(int);
	return REQUEST_OK;
}

static int func_get_flm_layout_version(void *hdl, int client_id _unused,
				       struct ntconn_header_s *hdr _unused,
				       char **data, int *len)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;

	if (!stat->p_nt4ga_stat || !stat->p_nt4ga_stat->mp_nthw_stat) {
		*data = NULL;
		*len = 0;
		return REQUEST_ERR;
	}
	*data = malloc(sizeof(int));
	if (!*data) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return REQUEST_ERR;
	}

	*(int *)*data = (stat->p_nt4ga_stat->flm_stat_ver < 18) ? 1 : 2;
	*len = sizeof(int);
	return REQUEST_OK;
}

/*
 * Return total number of 64bit counters occupied by this stat type
 * additionally, returns total number of records for this type (ie number of queues, ports, etc)
 */
static int get_size(struct stat_hdl *stat, enum stat_type_e type,
		     int *num_records)
{
	int nrec = 0;
	int size = 0;

	switch (type) {
	case STAT_TYPE_COLOR:
		nrec = stat->p_nt4ga_stat->mp_nthw_stat->m_nb_color_counters / 2;
		size = nrec * NUM_STAT_RECORD_TYPE_COLOR;
		break;
	case STAT_TYPE_QUEUE:
		nrec = stat->p_nt4ga_stat->mp_nthw_stat->m_nb_rx_host_buffers;
		size = nrec * NUM_STAT_RECORD_TYPE_QUEUE;
		break;
	case STAT_TYPE_RX:
		nrec = stat->p_nt4ga_stat->mn_rx_ports;
		size = nrec * ((stat->p_nt4ga_stat->mp_nthw_stat->mb_is_vswitch) ?
			       NUM_STAT_RECORD_TYPE_RX_PORT_VIRT :
			       NUM_STAT_RECORD_TYPE_RX_PORT_CAP);
		break;
	case STAT_TYPE_TX:
		nrec = stat->p_nt4ga_stat->mn_tx_ports;
		size = nrec * ((stat->p_nt4ga_stat->mp_nthw_stat->mb_is_vswitch) ?
			       NUM_STAT_RECORD_TYPE_TX_PORT_VIRT :
			       NUM_STAT_RECORD_TYPE_TX_PORT_CAP);
		break;
	case STAT_TYPE_FLOWMATCHER:
		nrec = 1;
		size = nrec * NUM_STAT_RECORD_TYPE_FLOWMATCHER;
		break;
	}

	*num_records = nrec;
	return size + STAT_INFO_ELEMENTS;
}

static int do_get_stats(struct stat_hdl *stat, char **data, int *len,
			enum stat_type_e stype,
			int (*read_counters)(nt4ga_stat_t *, uint64_t *, int))
{
	int nbg;
	int size = get_size(stat, stype, &nbg);

	size *= sizeof(uint64_t);
	uint64_t *val = (uint64_t *)malloc(size);

	if (!val) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return REQUEST_ERR;
	}

	pthread_mutex_lock(&stat->drv->ntdrv.stat_lck);
	read_counters(stat->p_nt4ga_stat, val, nbg);
	pthread_mutex_unlock(&stat->drv->ntdrv.stat_lck);

	*data = (char *)val;
	*len = size;
	return REQUEST_OK;
}

/*
 * Stat Request functions
 */
static int func_get_flm(void *hdl, int client_id _unused,
			struct ntconn_header_s *hdr _unused, char **data,
			int *len)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;

	if (!stat->p_nt4ga_stat || !stat->p_nt4ga_stat->mp_nthw_stat) {
		*data = NULL;
		*len = 0;
		return REQUEST_ERR;
	}
	return do_get_stats(stat, data, len, STAT_TYPE_FLOWMATCHER, read_flm);
}

static int func_get_color(void *hdl, int client_id _unused,
			  struct ntconn_header_s *hdr _unused, char **data,
			  int *len)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;

	if (!stat->p_nt4ga_stat || !stat->p_nt4ga_stat->mp_nthw_stat) {
		*data = NULL;
		*len = 0;
		return REQUEST_ERR;
	}
	return do_get_stats(stat, data, len, STAT_TYPE_COLOR, read_colors);
}

static int func_get_queue(void *hdl, int client_id _unused,
			  struct ntconn_header_s *hdr _unused, char **data,
			  int *len)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;

	if (!stat->p_nt4ga_stat || !stat->p_nt4ga_stat->mp_nthw_stat) {
		*data = NULL;
		*len = 0;
		return REQUEST_ERR;
	}
	return do_get_stats(stat, data, len, STAT_TYPE_QUEUE, read_queues);
}

static int func_get_rx_counters(void *hdl, int client_id _unused,
				struct ntconn_header_s *hdr _unused,
				char **data, int *len)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;

	if (!stat->p_nt4ga_stat || !stat->p_nt4ga_stat->mp_nthw_stat) {
		*data = NULL;
		*len = 0;
		return REQUEST_ERR;
	}
	return do_get_stats(stat, data, len, STAT_TYPE_RX, read_rx_counters);
}

static int func_get_tx_counters(void *hdl, int client_id _unused,
				struct ntconn_header_s *hdr _unused,
				char **data, int *len)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;

	if (!stat->p_nt4ga_stat || !stat->p_nt4ga_stat->mp_nthw_stat) {
		*data = NULL;
		*len = 0;
		return REQUEST_ERR;
	}
	return do_get_stats(stat, data, len, STAT_TYPE_TX, read_tx_counters);
}

/*
 * Snapshot handling. This is to ensure atomic reading of all statistics in one collection
 */

static struct snaps_s *find_client_snap_data(struct stat_hdl *stat,
		int client_id,
		struct snaps_s **parent)
{
	struct snaps_s *snaps = stat->snaps_base;

	if (parent)
		*parent = NULL;
	while (snaps && snaps->client_id != client_id) {
		if (parent)
			*parent = snaps;
		snaps = snaps->next;
	}

	return snaps;
}

static struct snaps_s *get_client_snap_data(struct stat_hdl *stat,
		int client_id)
{
	struct snaps_s *snaps = find_client_snap_data(stat, client_id, NULL);

	if (!snaps) {
		snaps = malloc(sizeof(struct snaps_s)); /* return NULL on malloc failure */
		if (snaps) {
			snaps->client_id = client_id;
			snaps->next = stat->snaps_base;
			stat->snaps_base = snaps;
			snaps->buffer = NULL;
		}
	}
	return snaps;
}

static int func_snapshot(void *hdl, int client_id,
			 struct ntconn_header_s *hdr _unused, char **data,
			 int *len)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;
	int nbc, nbq, nbpr, nbpt;
	struct snaps_s *snaps;

	if (!stat->p_nt4ga_stat || !stat->p_nt4ga_stat->mp_nthw_stat) {
		*data = NULL;
		*len = 0;
		return REQUEST_ERR;
	}
	snaps = get_client_snap_data(stat, client_id);
	if (!snaps)
		goto err_out;

	if (snaps->buffer)
		free(snaps->buffer);

	snaps->snap_addr[SNAP_COLORS].size =
		(unsigned int)get_size(stat, STAT_TYPE_COLOR, &nbc);
	snaps->snap_addr[SNAP_QUEUES].size =
		(unsigned int)get_size(stat, STAT_TYPE_QUEUE, &nbq);
	snaps->snap_addr[SNAP_RX_PORT].size =
		(unsigned int)get_size(stat, STAT_TYPE_RX, &nbpr);
	snaps->snap_addr[SNAP_TX_PORT].size =
		(unsigned int)get_size(stat, STAT_TYPE_TX, &nbpt);

	unsigned int tot_size = snaps->snap_addr[SNAP_COLORS].size +
				snaps->snap_addr[SNAP_QUEUES].size +
				snaps->snap_addr[SNAP_RX_PORT].size +
				snaps->snap_addr[SNAP_TX_PORT].size;

	snaps->buffer = malloc(tot_size * sizeof(uint64_t));
	if (!snaps->buffer) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return REQUEST_ERR;
	}
	uint64_t *val = snaps->buffer;

	snaps->snap_addr[SNAP_COLORS].ptr = val;
	pthread_mutex_lock(&stat->drv->ntdrv.stat_lck);
	unsigned int size = read_colors(stat->p_nt4ga_stat, val, nbc);

	if (size != snaps->snap_addr[SNAP_COLORS].size) {
		NT_LOG(ERR, NTCONNECT, "stat.snapshot: color size mismatch");
		goto err_out;
	}

	val += size;
	snaps->snap_addr[SNAP_QUEUES].ptr = val;
	size = read_queues(stat->p_nt4ga_stat, val, nbq);
	if (size != snaps->snap_addr[SNAP_QUEUES].size) {
		NT_LOG(ERR, NTCONNECT,
		       "stat.snapshot: queue statistic size mismatch");
		goto err_out;
	}

	val += size;
	snaps->snap_addr[SNAP_RX_PORT].ptr = val;
	size = read_rx_counters(stat->p_nt4ga_stat, val, nbpr);
	if (size != snaps->snap_addr[SNAP_RX_PORT].size) {
		NT_LOG(ERR, NTCONNECT,
		       "stat.snapshot: Rx port statistic size mismatch %i, %i",
		       size, snaps->snap_addr[SNAP_RX_PORT].size);
		goto err_out;
	}

	val += size;
	snaps->snap_addr[SNAP_TX_PORT].ptr = val;
	size = read_tx_counters(stat->p_nt4ga_stat, val, nbpt);
	if (size != snaps->snap_addr[SNAP_TX_PORT].size) {
		NT_LOG(ERR, NTCONNECT,
		       "stat.snapshot: Tx port statistic size mismatch");
		goto err_out;
	}

	pthread_mutex_unlock(&stat->drv->ntdrv.stat_lck);

	*data = NULL;
	*len = 0;
	return REQUEST_OK;

err_out:
	pthread_mutex_unlock(&stat->drv->ntdrv.stat_lck);
	return ntconn_error(data, len, "stat",
			    NTCONN_ERR_CODE_INTERNAL_REPLY_ERROR);
}

static int get_snap_data(void *hdl, int client_id, char **data, int *len,
			  enum snap_addr_select_e snap_addr_idx)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;
	struct snaps_s *snaps = find_client_snap_data(stat, client_id, NULL);

	if (!snaps || !snaps->buffer)
		return ntconn_error(data, len, "stat", NTCONN_ERR_CODE_NO_DATA);

	int ln = snaps->snap_addr[snap_addr_idx].size * sizeof(uint64_t);

	*data = malloc(ln);
	if (!data) {
		*len = 0;
		NT_LOG(ERR, NTCONNECT, "memory allocation failed");
		return REQUEST_ERR;
	}
	memcpy(*data, snaps->snap_addr[snap_addr_idx].ptr, ln);
	*len = ln;

	return REQUEST_OK;
}

static int func_get_snap_colors(void *hdl, int client_id,
				struct ntconn_header_s *hdr _unused,
				char **data, int *len)
{
	return get_snap_data(hdl, client_id, data, len, SNAP_COLORS);
}

static int func_get_snap_queues(void *hdl, int client_id,
				struct ntconn_header_s *hdr _unused,
				char **data, int *len)
{
	return get_snap_data(hdl, client_id, data, len, SNAP_QUEUES);
}

static int func_get_snap_rx_port(void *hdl, int client_id,
				 struct ntconn_header_s *hdr _unused,
				 char **data, int *len)
{
	return get_snap_data(hdl, client_id, data, len, SNAP_RX_PORT);
}

static int func_get_snap_tx_port(void *hdl, int client_id,
				 struct ntconn_header_s *hdr _unused,
				 char **data, int *len)
{
	return get_snap_data(hdl, client_id, data, len, SNAP_TX_PORT);
}

/*
 * Stat main request function
 */
static int stat_request(void *hdl, int client_id _unused,
			struct ntconn_header_s *hdr, char *function,
			char **data, int *len)
{
	return execute_function(this_module_name, hdl, client_id, hdr, function,
				stat_entry_funcs, data, len, 0);
}

static void stat_free_data(void *hdl _unused, char *data)
{
	free(data);
}

static void stat_client_cleanup(void *hdl, int client_id)
{
	struct stat_hdl *stat = (struct stat_hdl *)hdl;
	struct snaps_s *snaps_parent;
	struct snaps_s *snaps =
		find_client_snap_data(stat, client_id, &snaps_parent);

	if (!snaps)
		return;

	if (snaps_parent)
		snaps_parent->next = snaps->next;
	else
		stat->snaps_base = snaps->next;

	if (snaps->buffer)
		free(snaps->buffer);
	free(snaps);
}

static const ntconnapi_t ntconn_stat_op = {
	this_module_name, STAT_VERSION_MAJOR, STAT_VERSION_MINOR,
	stat_request,	  stat_free_data,     stat_client_cleanup
};

int ntconn_stat_register(struct drv_s *drv)
{
	stat_hdl.drv = drv;
	stat_hdl.p_nt4ga_stat = &drv->ntdrv.adapter_info.nt4ga_stat;

	/* Check supported Layout_versions by this module */
	size_t i;

	for (i = 0; i < NUM_LAYOUT_VERSIONS_SUPPORTED; i++) {
		if (stat_hdl.p_nt4ga_stat->mp_nthw_stat->mn_stat_layout_version ==
				layout_versions_supported[i])
			break;
	}

	if (i == NUM_LAYOUT_VERSIONS_SUPPORTED) {
		NT_LOG(ERR, NTCONNECT,
		       "stat: layout version %i is not supported. Module will not be activated",
		       stat_hdl.p_nt4ga_stat->mp_nthw_stat->mn_stat_layout_version);
		return -1;
	}

	return register_ntconn_mod(&drv->p_dev->addr, (void *)&stat_hdl,
				   &ntconn_stat_op);
}

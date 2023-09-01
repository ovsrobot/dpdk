/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"
#include "nt_util.h"
#include "nthw_drv.h"
#include "nthw_fpga.h"
#include "nt4ga_adapter.h"

#define NO_FLAGS 0

/* Inline timestamp format s pcap 32:32 bits. Convert to nsecs */
static inline uint64_t timestamp2ns(uint64_t ts)
{
	return ((ts >> 32) * 1000000000) + (ts & 0xffffffff);
}

static int nt4ga_stat_collect_cap_v1_stats(nt4ga_stat_t *p_nt4ga_stat,
				   uint32_t *p_stat_dma_virtual);
static int nt4ga_stat_collect_virt_v1_stats(nt4ga_stat_t *p_nt4ga_stat,
				    uint32_t *p_stat_dma_virtual);

int nt4ga_stat_collect(struct adapter_info_s *p_adapter_info _unused,
		      nt4ga_stat_t *p_nt4ga_stat)
{
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;

	if (p_nthw_stat->mb_is_vswitch) {
		/*
		 * Set all bits in the DMA block timestamp since 9530-42-05 and other Vswitch FPGA
		 * images may only clear all bits in this memory location. TBV
		 * Consequently, last_timestamp must be constructed via a system call.
		 */
		*p_nthw_stat->mp_timestamp = 0xFFFFFFFF;
		p_nt4ga_stat->last_timestamp = NT_OS_GET_TIME_NS();
		nt4ga_stat_collect_virt_v1_stats(p_nt4ga_stat,
						p_nt4ga_stat->p_stat_dma_virtual);
	} else {
		p_nt4ga_stat->last_timestamp =
			timestamp2ns(*p_nthw_stat->mp_timestamp);
		nt4ga_stat_collect_cap_v1_stats(p_nt4ga_stat,
					       p_nt4ga_stat->p_stat_dma_virtual);
	}
	return 0;
}

int nt4ga_stat_init(struct adapter_info_s *p_adapter_info)
{
	const char *const p_adapter_id_str = p_adapter_info->mp_adapter_id_str;
	fpga_info_t *fpga_info = &p_adapter_info->fpga_info;
	nt_fpga_t *p_fpga = fpga_info->mp_fpga;
	nt4ga_stat_t *p_nt4ga_stat = &p_adapter_info->nt4ga_stat;

	if (p_nt4ga_stat) {
		memset(p_nt4ga_stat, 0, sizeof(nt4ga_stat_t));
	} else {
		NT_LOG(ERR, ETHDEV, "%s: ERROR (%s:%d)", p_adapter_id_str,
		       __func__, __LINE__);
		return -1;
	}

	{
		nthw_stat_t *p_nthw_stat = nthw_stat_new();
		nthw_rmc_t *p_nthw_rmc = nthw_rmc_new();

		if (!p_nthw_stat) {
			NT_LOG(ERR, ETHDEV, "%s: ERROR (%s:%d)", p_adapter_id_str,
			       __func__, __LINE__);
			return -1;
		}

		if (!p_nthw_rmc) {
			nthw_stat_delete(p_nthw_stat);

			NT_LOG(ERR, ETHDEV, "%s: ERROR (%s:%d)", p_adapter_id_str,
			       __func__, __LINE__);
			return -1;
		}

		p_nt4ga_stat->mp_nthw_stat = p_nthw_stat;
		nthw_stat_init(p_nthw_stat, p_fpga, 0);

		p_nt4ga_stat->mp_nthw_rmc = p_nthw_rmc;
		nthw_rmc_init(p_nthw_rmc, p_fpga, 0);

		p_nt4ga_stat->mn_rx_host_buffers = p_nthw_stat->m_nb_rx_host_buffers;
		p_nt4ga_stat->mn_tx_host_buffers = p_nthw_stat->m_nb_tx_host_buffers;

		p_nt4ga_stat->mn_rx_ports = p_nthw_stat->m_nb_rx_ports;
		p_nt4ga_stat->mn_tx_ports = p_nthw_stat->m_nb_tx_ports;
	}

	return 0;
}

int nt4ga_stat_setup(struct adapter_info_s *p_adapter_info)
{
	const int n_physical_adapter_no _unused = p_adapter_info->adapter_no;
	nt4ga_stat_t *p_nt4ga_stat = &p_adapter_info->nt4ga_stat;
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;
	nthw_rmc_t *p_nthw_rmc = p_nt4ga_stat->mp_nthw_rmc;

	if (p_nthw_rmc)
		nthw_rmc_block(p_nthw_rmc);

	/* Allocate and map memory for fpga statistics */
	{
		uint32_t n_stat_size =
			(uint32_t)(p_nthw_stat->m_nb_counters * sizeof(uint32_t) +
				   sizeof(p_nthw_stat->mp_timestamp));
		struct nt_dma_s *p_dma;
		int numa_node = p_adapter_info->fpga_info.numa_node;

		/* FPGA needs a 16K alignment on Statistics */
		p_dma = nt_dma_alloc(n_stat_size, 0x4000, numa_node);

		if (!p_dma) {
			NT_LOG(ERR, ETHDEV, "%s: pDma alloc failed\n",
			       __func__);
			return -1;
		}

		NT_LOG(DBG, ETHDEV, "%s: %x @%d %p %" PRIX64 " %" PRIX64 "\n", __func__,
		       n_stat_size, numa_node, p_dma->addr, p_dma->iova);

		NT_LOG(DBG, ETHDEV,
		       "DMA: Physical adapter %02ld, PA = 0x%016" PRIX64
		       " DMA = 0x%016" PRIX64 " size = 0x%" PRIX64 "\n",
		       n_physical_adapter_no, p_dma->iova, p_dma->addr, n_stat_size);

		p_nt4ga_stat->p_stat_dma_virtual = (uint32_t *)p_dma->addr;
		p_nt4ga_stat->n_stat_size = n_stat_size;
		p_nt4ga_stat->p_stat_dma = p_dma;

		memset(p_nt4ga_stat->p_stat_dma_virtual, 0xaa, n_stat_size);
		nthw_stat_set_dma_address(p_nthw_stat, p_dma->iova,
				       p_nt4ga_stat->p_stat_dma_virtual);
	}

	if (p_nthw_rmc)
		nthw_rmc_unblock(p_nthw_rmc, false);

	p_nt4ga_stat->mp_stat_structs_color = calloc(p_nthw_stat->m_nb_color_counters,
						sizeof(struct color_counters));
	if (!p_nt4ga_stat->mp_stat_structs_color) {
		NT_LOG(ERR, GENERAL, "Cannot allocate mem (%s:%d).\n", __func__,
		       __LINE__);
		return -1;
	}

	p_nt4ga_stat->mp_stat_structs_hb =
		calloc(p_nt4ga_stat->mn_rx_host_buffers + p_nt4ga_stat->mn_tx_host_buffers,
		       sizeof(struct host_buffer_counters));
	if (!p_nt4ga_stat->mp_stat_structs_hb) {
		NT_LOG(ERR, GENERAL, "Cannot allocate mem (%s:%d).\n", __func__,
		       __LINE__);
		return -1;
	}

	/*
	 * Separate memory allocation for VSWITCH and Inline to appropriate port counter structures.
	 */
	if (p_nthw_stat->mb_is_vswitch) {
		p_nt4ga_stat->virt.mp_stat_structs_port_rx =
			calloc(p_nthw_stat->m_nb_rx_host_buffers,
			       sizeof(struct port_counters_vswitch_v1));
		if (!p_nt4ga_stat->virt.mp_stat_structs_port_rx) {
			NT_LOG(ERR, GENERAL, "Cannot allocate mem (%s:%d).\n",
			       __func__, __LINE__);
			return -1;
		}
		p_nt4ga_stat->virt.mp_stat_structs_port_tx =
			calloc(p_nthw_stat->m_nb_tx_host_buffers,
			       sizeof(struct port_counters_vswitch_v1));
		if (!p_nt4ga_stat->virt.mp_stat_structs_port_tx) {
			NT_LOG(ERR, GENERAL, "Cannot allocate mem (%s:%d).\n",
			       __func__, __LINE__);
			return -1;
		}
		p_nt4ga_stat->flm_stat_ver = 0;
		p_nt4ga_stat->mp_stat_structs_flm = NULL;
	} else { /* Inline */
		p_nt4ga_stat->cap.mp_stat_structs_port_rx =
			calloc(NUM_ADAPTER_PORTS_MAX,
			       sizeof(struct port_counters_v2));
		if (!p_nt4ga_stat->cap.mp_stat_structs_port_rx) {
			NT_LOG(ERR, GENERAL, "Cannot allocate mem (%s:%d).\n",
			       __func__, __LINE__);
			return -1;
		}
		p_nt4ga_stat->cap.mp_stat_structs_port_tx =
			calloc(NUM_ADAPTER_PORTS_MAX,
			       sizeof(struct port_counters_v2));
		if (!p_nt4ga_stat->cap.mp_stat_structs_port_tx) {
			NT_LOG(ERR, GENERAL, "Cannot allocate mem (%s:%d).\n",
			       __func__, __LINE__);
			return -1;
		}

		p_nt4ga_stat->flm_stat_ver = 0;

		p_nt4ga_stat->mp_stat_structs_flm =
			calloc(1, sizeof(struct flm_counters_v1));
		if (!p_nt4ga_stat->mp_stat_structs_flm) {
			NT_LOG(ERR, GENERAL, "Cannot allocate mem (%s:%d).\n",
			       __func__, __LINE__);
			return -1;
		}
	}

	memset(p_nt4ga_stat->a_stat_structs_color_base, 0,
	       sizeof(struct color_counters) * NT_MAX_COLOR_FLOW_STATS);
	p_nt4ga_stat->last_timestamp = 0;

	nthw_stat_trigger(p_nthw_stat);

	return 0;
}

int nt4ga_stat_stop(struct adapter_info_s *p_adapter_info)
{
	nt4ga_stat_t *p_nt4ga_stat = &p_adapter_info->nt4ga_stat;

	if (p_nt4ga_stat->virt.mp_stat_structs_port_rx) {
		free(p_nt4ga_stat->virt.mp_stat_structs_port_rx);
		p_nt4ga_stat->virt.mp_stat_structs_port_rx = NULL;
	}
	if (p_nt4ga_stat->cap.mp_stat_structs_port_rx) {
		free(p_nt4ga_stat->cap.mp_stat_structs_port_rx);
		p_nt4ga_stat->cap.mp_stat_structs_port_rx = NULL;
	}

	if (p_nt4ga_stat->virt.mp_stat_structs_port_tx) {
		free(p_nt4ga_stat->virt.mp_stat_structs_port_tx);
		p_nt4ga_stat->virt.mp_stat_structs_port_tx = NULL;
	}
	if (p_nt4ga_stat->cap.mp_stat_structs_port_tx) {
		free(p_nt4ga_stat->cap.mp_stat_structs_port_tx);
		p_nt4ga_stat->cap.mp_stat_structs_port_tx = NULL;
	}

	if (p_nt4ga_stat->mp_stat_structs_color) {
		free(p_nt4ga_stat->mp_stat_structs_color);
		p_nt4ga_stat->mp_stat_structs_color = NULL;
	}

	if (p_nt4ga_stat->mp_stat_structs_hb) {
		free(p_nt4ga_stat->mp_stat_structs_hb);
		p_nt4ga_stat->mp_stat_structs_hb = NULL;
	}

	if (p_nt4ga_stat->mp_stat_structs_flm) {
		free(p_nt4ga_stat->mp_stat_structs_flm);
		p_nt4ga_stat->mp_stat_structs_flm = NULL;
	}

	if (p_nt4ga_stat->p_stat_dma) {
		nt_dma_free(p_nt4ga_stat->p_stat_dma);
		p_nt4ga_stat->p_stat_dma = NULL;
	}

	return 0;
}

int nt4ga_stat_dump(struct adapter_info_s *p_adapter_info, FILE *pfh)
{
	const char *const p_adapter_id_str = p_adapter_info->mp_adapter_id_str;
	fpga_info_t *fpga_info = &p_adapter_info->fpga_info;
	nt4ga_stat_t *p_nt4ga_stat = &p_adapter_info->nt4ga_stat;
	int i;

	for (i = 0; i < fpga_info->n_phy_ports; i++) {
		fprintf(pfh,
			"%s: Intf %02d: Rx: %016" PRIX64 " %016" PRIX64
			" %016" PRIX64 " Tx: %016" PRIX64 " %016" PRIX64
			" %016" PRIX64 "\n",
			p_adapter_id_str, i, p_nt4ga_stat->a_port_rx_packets_total[i],
			p_nt4ga_stat->a_port_rx_octets_total[i],
			p_nt4ga_stat->a_port_rx_drops_total[i],
			p_nt4ga_stat->a_port_tx_packets_total[i],
			p_nt4ga_stat->a_port_tx_octets_total[i],
			p_nt4ga_stat->a_port_tx_drops_total[i]);
	}

	return 0;
}

/* Called with stat mutex locked */
static int nt4ga_stat_collect_virt_v1_stats(nt4ga_stat_t *p_nt4ga_stat,
				    uint32_t *p_stat_dma_virtual)
{
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;
	const int n_rx_ports = p_nt4ga_stat->mn_rx_ports;
	const int n_tx_ports = p_nt4ga_stat->mn_tx_ports;
	int c, h, p;

	if (!p_nthw_stat || !p_nt4ga_stat)
		return -1;

	if (p_nthw_stat->mn_stat_layout_version != 6) {
		NT_LOG(ERR, ETHDEV, "HW STA module version not supported");
		return -1;
	}

	/* RX ports */
	for (c = 0; c < p_nthw_stat->m_nb_color_counters / 2; c++) {
		const unsigned int tcp_flags_bits = 6U;
		const uint32_t val_mask_dma = 0xffffffffULL >> tcp_flags_bits;

		p_nt4ga_stat->mp_stat_structs_color[c].color_packets +=
			p_stat_dma_virtual[c * 2] & val_mask_dma;
		p_nt4ga_stat->mp_stat_structs_color[c].tcp_flags |=
			(uint8_t)(p_stat_dma_virtual[c * 2] >>
				  (32 - tcp_flags_bits));
		p_nt4ga_stat->mp_stat_structs_color[c].color_bytes +=
			p_stat_dma_virtual[c * 2 + 1];
	}

	/* Move to Host buffer counters */
	p_stat_dma_virtual += p_nthw_stat->m_nb_color_counters;

	/* Host buffer counters */
	for (h = 0; h < p_nthw_stat->m_nb_rx_host_buffers; h++) {
		p_nt4ga_stat->mp_stat_structs_hb[h].flush_packets +=
			p_stat_dma_virtual[h * 8];
		p_nt4ga_stat->mp_stat_structs_hb[h].drop_packets +=
			p_stat_dma_virtual[h * 8 + 1];
		p_nt4ga_stat->mp_stat_structs_hb[h].fwd_packets +=
			p_stat_dma_virtual[h * 8 + 2];
		p_nt4ga_stat->mp_stat_structs_hb[h].dbs_drop_packets +=
			p_stat_dma_virtual[h * 8 + 3];
		p_nt4ga_stat->mp_stat_structs_hb[h].flush_bytes +=
			p_stat_dma_virtual[h * 8 + 4];
		p_nt4ga_stat->mp_stat_structs_hb[h].drop_bytes +=
			p_stat_dma_virtual[h * 8 + 5];
		p_nt4ga_stat->mp_stat_structs_hb[h].fwd_bytes +=
			p_stat_dma_virtual[h * 8 + 6];
		p_nt4ga_stat->mp_stat_structs_hb[h].dbs_drop_bytes +=
			p_stat_dma_virtual[h * 8 + 7];
	}

	/* Move to Rx Port counters */
	p_stat_dma_virtual += p_nthw_stat->m_nb_rx_hb_counters;

	/* RX ports */
	for (p = 0; p < n_rx_ports; p++) {
		p_nt4ga_stat->virt.mp_stat_structs_port_rx[p].octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters];
		p_nt4ga_stat->virt.mp_stat_structs_port_rx[p].pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 1];
		p_nt4ga_stat->virt.mp_stat_structs_port_rx[p].drop_events +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 2];
		p_nt4ga_stat->virt.mp_stat_structs_port_rx[p].qos_drop_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 3];
		p_nt4ga_stat->virt.mp_stat_structs_port_rx[p].qos_drop_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 4];

		/* Rx totals */
		p_nt4ga_stat->a_port_rx_octets_total[p] +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters];
		p_nt4ga_stat->a_port_rx_packets_total[p] +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 1];
		p_nt4ga_stat->a_port_rx_drops_total[p] +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 2];
	}

	/* Move to Tx Port counters */
	p_stat_dma_virtual += n_rx_ports * p_nthw_stat->m_nb_rx_port_counters;

	/* TX ports */
	for (p = 0; p < n_tx_ports; p++) {
		p_nt4ga_stat->virt.mp_stat_structs_port_tx[p].octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters];
		p_nt4ga_stat->virt.mp_stat_structs_port_tx[p].pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 1];
		p_nt4ga_stat->virt.mp_stat_structs_port_tx[p].drop_events +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 2];
		p_nt4ga_stat->virt.mp_stat_structs_port_tx[p].qos_drop_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 3];
		p_nt4ga_stat->virt.mp_stat_structs_port_tx[p].qos_drop_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 4];

		/* Tx totals */
		p_nt4ga_stat->a_port_tx_octets_total[p] +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters];
		p_nt4ga_stat->a_port_tx_packets_total[p] +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 1];
		p_nt4ga_stat->a_port_tx_drops_total[p] +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 2];
	}

	return 0;
}

/* Called with stat mutex locked */
static int nt4ga_stat_collect_cap_v1_stats(nt4ga_stat_t *p_nt4ga_stat,
					   uint32_t *p_stat_dma_virtual)
{
	nthw_stat_t *p_nthw_stat = p_nt4ga_stat->mp_nthw_stat;

	const int n_rx_ports = p_nt4ga_stat->mn_rx_ports;
	const int n_tx_ports = p_nt4ga_stat->mn_tx_ports;
	int c, h, p;

	if (!p_nthw_stat || !p_nt4ga_stat)
		return -1;

	if (p_nthw_stat->mn_stat_layout_version != 6) {
		NT_LOG(ERR, ETHDEV, "HW STA module version not supported");
		return -1;
	}

	/* RX ports */
	for (c = 0; c < p_nthw_stat->m_nb_color_counters / 2; c++) {
		p_nt4ga_stat->mp_stat_structs_color[c].color_packets +=
			p_stat_dma_virtual[c * 2];
		p_nt4ga_stat->mp_stat_structs_color[c].color_bytes +=
			p_stat_dma_virtual[c * 2 + 1];
	}

	/* Move to Host buffer counters */
	p_stat_dma_virtual += p_nthw_stat->m_nb_color_counters;

	for (h = 0; h < p_nthw_stat->m_nb_rx_host_buffers; h++) {
		p_nt4ga_stat->mp_stat_structs_hb[h].flush_packets +=
			p_stat_dma_virtual[h * 8];
		p_nt4ga_stat->mp_stat_structs_hb[h].drop_packets +=
			p_stat_dma_virtual[h * 8 + 1];
		p_nt4ga_stat->mp_stat_structs_hb[h].fwd_packets +=
			p_stat_dma_virtual[h * 8 + 2];
		p_nt4ga_stat->mp_stat_structs_hb[h].dbs_drop_packets +=
			p_stat_dma_virtual[h * 8 + 3];
		p_nt4ga_stat->mp_stat_structs_hb[h].flush_bytes +=
			p_stat_dma_virtual[h * 8 + 4];
		p_nt4ga_stat->mp_stat_structs_hb[h].drop_bytes +=
			p_stat_dma_virtual[h * 8 + 5];
		p_nt4ga_stat->mp_stat_structs_hb[h].fwd_bytes +=
			p_stat_dma_virtual[h * 8 + 6];
		p_nt4ga_stat->mp_stat_structs_hb[h].dbs_drop_bytes +=
			p_stat_dma_virtual[h * 8 + 7];
	}

	/* Move to Rx Port counters */
	p_stat_dma_virtual += p_nthw_stat->m_nb_rx_hb_counters;

	/* RX ports */
	for (p = 0; p < n_rx_ports; p++) {
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 0];

		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].broadcast_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 1];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].multicast_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 2];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].unicast_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 3];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_alignment +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 4];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_code_violation +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 5];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_crc +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 6];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].undersize_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 7];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].oversize_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 8];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].fragments +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 9];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].jabbers_not_truncated +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 10];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].jabbers_truncated +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 11];

		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_64_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 12];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_65_to_127_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 13];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_128_to_255_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 14];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_256_to_511_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 15];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_512_to_1023_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 16];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p]
		.pkts_1024_to_1518_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 17];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p]
		.pkts_1519_to_2047_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 18];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p]
		.pkts_2048_to_4095_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 19];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p]
		.pkts_4096_to_8191_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 20];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_8192_to_max_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 21];

		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].mac_drop_events +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 22];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_lr +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 23];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].duplicate +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 24];

		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_ip_chksum_error +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 25];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_udp_chksum_error +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 26];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_tcp_chksum_error +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 27];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_giant_undersize +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 28];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_baby_giant +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 29];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_not_isl_vlan_mpls +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 30];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_isl +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 31];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_vlan +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 32];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_isl_vlan +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 33];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_mpls +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 34];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_isl_mpls +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 35];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_vlan_mpls +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 36];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_isl_vlan_mpls +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 37];

		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_no_filter +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 38];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_dedup_drop +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 39];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_filter_drop +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 40];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_overflow +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 41];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts_dbs_drop +=
			p_nthw_stat->m_dbs_present ?
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters +
					  42] :
			0;
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].octets_no_filter +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 43];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].octets_dedup_drop +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 44];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].octets_filter_drop +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 45];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].octets_overflow +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 46];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].octets_dbs_drop +=
			p_nthw_stat->m_dbs_present ?
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters +
					  47] :
			0;

		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].ipft_first_hit +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 48];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].ipft_first_not_hit +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 49];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].ipft_mid_hit +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 50];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].ipft_mid_not_hit +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 51];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].ipft_last_hit +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 52];
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].ipft_last_not_hit +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 53];

		/* Rx totals */
		uint64_t new_drop_events_sum =
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 22] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 38] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 39] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 40] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 41] +
			(p_nthw_stat->m_dbs_present ?
			 p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters +
					   42] :
			 0);

		uint64_t new_packets_sum =
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 7] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 8] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 9] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 10] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 11] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 12] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 13] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 14] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 15] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 16] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 17] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 18] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 19] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 20] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 21];

		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].drop_events +=
			new_drop_events_sum;
		p_nt4ga_stat->cap.mp_stat_structs_port_rx[p].pkts += new_packets_sum;

		p_nt4ga_stat->a_port_rx_octets_total[p] +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 0];
		p_nt4ga_stat->a_port_rx_packets_total[p] += new_packets_sum;
		p_nt4ga_stat->a_port_rx_drops_total[p] += new_drop_events_sum;
	}

	/* Move to Tx Port counters */
	p_stat_dma_virtual += n_rx_ports * p_nthw_stat->m_nb_rx_port_counters;

	for (p = 0; p < n_tx_ports; p++) {
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 0];

		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].broadcast_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 1];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].multicast_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 2];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].unicast_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 3];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_alignment +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 4];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_code_violation +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 5];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_crc +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 6];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].undersize_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 7];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].oversize_pkts +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 8];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].fragments +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 9];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].jabbers_not_truncated +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 10];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].jabbers_truncated +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 11];

		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_64_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 12];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_65_to_127_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 13];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_128_to_255_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 14];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_256_to_511_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 15];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_512_to_1023_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 16];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p]
		.pkts_1024_to_1518_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 17];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p]
		.pkts_1519_to_2047_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 18];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p]
		.pkts_2048_to_4095_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 19];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p]
		.pkts_4096_to_8191_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 20];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_8192_to_max_octets +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 21];

		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].mac_drop_events +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 22];
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts_lr +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 23];

		/* Tx totals */
		uint64_t new_drop_events_sum =
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_rx_port_counters + 22];

		uint64_t new_packets_sum =
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 7] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 8] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 9] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 10] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 11] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 12] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 13] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 14] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 15] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 16] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 17] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 18] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 19] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 20] +
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 21];

		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].drop_events +=
			new_drop_events_sum;
		p_nt4ga_stat->cap.mp_stat_structs_port_tx[p].pkts += new_packets_sum;

		p_nt4ga_stat->a_port_tx_octets_total[p] +=
			p_stat_dma_virtual[p * p_nthw_stat->m_nb_tx_port_counters + 0];
		p_nt4ga_stat->a_port_tx_packets_total[p] += new_packets_sum;
		p_nt4ga_stat->a_port_tx_drops_total[p] += new_drop_events_sum;
	}

	return 0;
}

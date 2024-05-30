/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"
#include "nt_util.h"
#include "nthw_drv.h"
#include "nt4ga_adapter.h"
#include "nt4ga_pci_ta_tg.h"
#include "nthw_pci_ta.h"
#include "nthw_pci_rd_tg.h"
#include "nthw_pci_wr_tg.h"

int nt4ga_pci_ta_tg_init(struct adapter_info_s *p_adapter_info)
{
	const char *const p_adapter_id_str = p_adapter_info->mp_adapter_id_str;
	fpga_info_t *fpga_info = &p_adapter_info->fpga_info;
	nthw_fpga_t *p_fpga = fpga_info->mp_fpga;
	nt4ga_pci_ta_tg_t *p = &p_adapter_info->nt4ga_pci_ta_tg;
	int res;
	int n_err_cnt = 0;

	if (p) {
		memset(p, 0, sizeof(nt4ga_pci_ta_tg_t));

	} else {
		NT_LOG(ERR, NTHW, "%s: %s: null ptr\n", p_adapter_id_str, __func__);
		return -1;
	}

	assert(p_fpga);

	p->mp_nthw_pci_rd_tg = nthw_pci_rd_tg_new();
	assert(p->mp_nthw_pci_rd_tg);
	res = nthw_pci_rd_tg_init(p->mp_nthw_pci_rd_tg, p_fpga, 0);

	if (res) {
		n_err_cnt++;
		NT_LOG(WRN, NTHW, "%s: module PCI_RD_TG not found\n", p_adapter_id_str);
	}

	p->mp_nthw_pci_wr_tg = nthw_pci_wr_tg_new();
	assert(p->mp_nthw_pci_wr_tg);
	res = nthw_pci_wr_tg_init(p->mp_nthw_pci_wr_tg, p_fpga, 0);

	if (res) {
		n_err_cnt++;
		NT_LOG(WRN, NTHW, "%s: module PCI_WR_TG not found\n", p_adapter_id_str);
	}

	p->mp_nthw_pci_ta = nthw_pci_ta_new();
	assert(p->mp_nthw_pci_ta);
	res = nthw_pci_ta_init(p->mp_nthw_pci_ta, p_fpga, 0);

	if (res) {
		n_err_cnt++;
		NT_LOG(WRN, NTHW, "%s: module PCI_TA not found\n", p_adapter_id_str);
	}

	return n_err_cnt;
}

static int nt4ga_pci_ta_tg_ta_write_control_enable(nt4ga_pci_ta_tg_t *p, uint32_t enable)
{
	nthw_pci_ta_set_control_enable(p->mp_nthw_pci_ta, enable);
	return 0;
}

static int nt4ga_pci_ta_tg_ta_read_length_error(nt4ga_pci_ta_tg_t *p, uint32_t *p_data)
{
	nthw_pci_ta_get_length_error(p->mp_nthw_pci_ta, p_data);
	return 0;
}

static int nt4ga_pci_ta_tg_ta_read_packet_bad(nt4ga_pci_ta_tg_t *p, uint32_t *p_data)
{
	nthw_pci_ta_get_packet_bad(p->mp_nthw_pci_ta, p_data);
	return 0;
}

static int nt4ga_pci_ta_tg_ta_read_packet_good(nt4ga_pci_ta_tg_t *p, uint32_t *p_data)
{
	nthw_pci_ta_get_packet_good(p->mp_nthw_pci_ta, p_data);
	return 0;
}

static int nt4ga_pci_ta_tg_ta_read_payload_error(nt4ga_pci_ta_tg_t *p, uint32_t *p_data)
{
	nthw_pci_ta_get_payload_error(p->mp_nthw_pci_ta, p_data);
	return 0;
}

static int nt4ga_pci_ta_tg_rd_tg_setup(nt4ga_pci_ta_tg_t *p, uint64_t iova, int slot_addr,
	uint32_t req_size, bool wait, bool wrap)
{
	const uint64_t n_phys_addr = (iova + (unsigned long)(slot_addr * req_size));
	nthw_pci_rd_tg_set_ram_addr(p->mp_nthw_pci_rd_tg, slot_addr);
	nthw_pci_rd_tg_set_phys_addr(p->mp_nthw_pci_rd_tg, n_phys_addr);
	nthw_pci_rd_tg_set_ram_data(p->mp_nthw_pci_rd_tg, req_size, wait, wrap);
	return 0;
}

static int nt4ga_pci_ta_tg_rd_tg_run(nt4ga_pci_ta_tg_t *p, uint32_t num_iterations)
{
	nthw_pci_rd_tg_set_run(p->mp_nthw_pci_rd_tg, num_iterations);
	return 0;
}

static int nt4ga_pci_ta_tg_rd_tg_wait_ready(nt4ga_pci_ta_tg_t *p)
{
	int poll = 0;
	uint32_t data = 0;

	while (data == 0) {
		/* NOTE: Deliberately start with a sleep - ensures that the FPGA pipe is empty */
		nt_os_wait_usec(1000);
		data = nthw_pci_rd_tg_get_ctrl_rdy(p->mp_nthw_pci_rd_tg);
		poll++;

		if (poll >= 1000) {
			NT_LOG(ERR, NTHW, "%s: FAILED waiting PCI RD TG ready: poll=%d\n",
				__func__, poll);
			return -1;
		}
	}

	return 0;
}

static int nt4ga_pci_ta_tg_wr_tg_setup(nt4ga_pci_ta_tg_t *p, uint64_t iova, int slot_addr,
	uint32_t req_size, bool wait, bool wrap, bool inc)
{
	const uint64_t n_phys_addr = (iova + (unsigned long)(slot_addr * req_size));

	nthw_pci_wr_tg_set_ram_addr(p->mp_nthw_pci_wr_tg, slot_addr);
	nthw_pci_wr_tg_set_phys_addr(p->mp_nthw_pci_wr_tg, n_phys_addr);
	nthw_pci_wr_tg_set_ram_data(p->mp_nthw_pci_wr_tg, req_size, wait, wrap, inc);

	return 0;
}

static int nt4ga_pci_ta_tg_wr_tg_run(nt4ga_pci_ta_tg_t *p, uint32_t num_iterations)
{
	nthw_pci_wr_tg_set_run(p->mp_nthw_pci_wr_tg, num_iterations);
	return 0;
}

static int nt4ga_pci_ta_tg_wr_tg_wait_ready(nt4ga_pci_ta_tg_t *p)
{
	int poll = 0;
	uint32_t data = 0;

	while (data == 0) {
		/* NOTE: Deliberately start with a sleep - ensures that the FPGA pipe is empty */
		nt_os_wait_usec(1000);
		data = nthw_pci_wr_tg_get_ctrl_rdy(p->mp_nthw_pci_wr_tg);
		poll++;

		if (poll >= 1000) {
			NT_LOG(ERR, NTHW, "%s: FAILED waiting PCI WR TG ready: poll=%d\n",
				__func__, poll);
			return -1;
		}
	}

	return 0;
}

int nt4ga_pci_ta_tg_measure_throughput_run(struct adapter_info_s *p_adapter_info,
	struct nthw_hif_end_point_counters *pri,
	struct nthw_hif_end_point_counters *sla)
{
	nt4ga_pci_ta_tg_t *p = &p_adapter_info->nt4ga_pci_ta_tg;

	const int delay = pri->n_tg_delay;
	const int pkt_size = pri->n_tg_pkt_size;
	const int num_pkts = pri->n_tg_num_pkts;
	const int n_direction = pri->n_tg_direction;
	const uint8_t n_numa_node = (uint8_t)pri->n_numa_node;
	const int dma_buf_size = (4 * 1024 * 1024);

	const size_t align_size = nt_util_align_size(dma_buf_size);
	uint32_t *mem_addr;
	uint64_t iova;

	int bo_error = 0;

	nthw_hif *p_master_instance = p_adapter_info->fpga_info.mp_nthw_hif;
	nthw_hif *p_slave_instance = NULL;

	nthw_pcie3 *p_pci_master = p_adapter_info->fpga_info.mp_nthw_pcie3;
	nthw_pcie3 *p_pci_slave = NULL;

	assert(p_master_instance || p_pci_master);

	struct nt_dma_s *p_dma;
	/* FPGA needs a Page alignment (4K on Intel) */
	p_dma = nt_dma_alloc(align_size, 0x1000, n_numa_node);

	if (p_dma == NULL) {
		NT_LOG(DBG, ETHDEV, "%s: vfio_dma_alloc failed\n", __func__);
		return 0;
	}

	mem_addr = (uint32_t *)p_dma->addr;
	iova = p_dma->iova;

	NT_LOG(DBG, NTHW, "%s: Running HIF bandwidth measurements on NUMA node %d\n", __func__,
		n_numa_node);

	bo_error = 0;
	{
		int wrap;

		/* Stop any existing running test */
		bo_error |= nt4ga_pci_ta_tg_rd_tg_run(p, 0);
		bo_error |= nt4ga_pci_ta_tg_rd_tg_wait_ready(p);

		bo_error |= nt4ga_pci_ta_tg_wr_tg_run(p, 0);
		bo_error |= nt4ga_pci_ta_tg_wr_tg_wait_ready(p);

		bo_error |= nt4ga_pci_ta_tg_ta_write_control_enable(p, 0);

		/* Prepare the HIF Traffic generator */
		bo_error |= nt4ga_pci_ta_tg_ta_write_control_enable(p, 1);
		bo_error |= nt4ga_pci_ta_tg_rd_tg_wait_ready(p);
		bo_error |= nt4ga_pci_ta_tg_wr_tg_wait_ready(p);

		/*
		 * Ensure that the hostbuffer memory contain data that can be read -
		 * For this we will ask the FPGA to write data to it. The last wrap packet
		 * does not generate any data it only wraps (unlike the PCIe2 TG)
		 */
		{
			int pkt;

			for (pkt = 0; pkt < num_pkts; pkt++) {
				if (pkt >= (num_pkts - 1))
					wrap = 1;

				else
					wrap = 0;

				bo_error |= nt4ga_pci_ta_tg_wr_tg_setup(p, iova, pkt, pkt_size, 0,
						wrap, 1);
				bo_error |= nt4ga_pci_ta_tg_rd_tg_setup(p, iova, pkt, pkt_size, 0,
						wrap);
			}
		}

		bo_error |= nt4ga_pci_ta_tg_wr_tg_run(p, 1);
		bo_error |= nt4ga_pci_ta_tg_wr_tg_wait_ready(p);

		/* Start WR TG Write once */
		bo_error |= nt4ga_pci_ta_tg_wr_tg_run(p, 1);
		/* Wait until WR TG ready */
		bo_error |= nt4ga_pci_ta_tg_wr_tg_wait_ready(p);

		/* Verify that we have a packet */
		{
			int pkt;

			for (pkt = 0; pkt < num_pkts; pkt++) {
				uint32_t value = 0;
				int poll;

				for (poll = 8; poll < pkt_size; poll += 4, value++) {
					if (*(uint32_t *)((uint8_t *)mem_addr + (pkt * pkt_size) +
							poll) != value) {
						NT_LOG(ERR, NTHW,
							"HIF TG: Prepare failed. Data write failed: #%d.%d:  %016X:%08X\n",
							pkt, poll,
							*(uint32_t *)((uint8_t *)mem_addr +
								(pkt * pkt_size) + poll),
							value);

						/*
						 * Break out of the verification loop on first
						 * compare error
						 */
						bo_error |= 1;
						break;
					}
				}
			}
		}

		switch (n_direction) {
		case 1:	/* Read only test */
			nt4ga_pci_ta_tg_wr_tg_run(p, 0xffff);
			break;

		case 2:	/* Write only test */
			nt4ga_pci_ta_tg_rd_tg_run(p, 0xffff);
			break;

		case 3:	/* Combined read/write test */
			nt4ga_pci_ta_tg_wr_tg_run(p, 0xffff);
			nt4ga_pci_ta_tg_rd_tg_run(p, 0xffff);
			break;

		default:/* stop tests */
			nt4ga_pci_ta_tg_wr_tg_run(p, 0);
			nt4ga_pci_ta_tg_rd_tg_run(p, 0);
			break;
		}

		do {
			/* prep */
			if (p_pci_master)
				nthw_pcie3_end_point_counters_sample_pre(p_pci_master, pri);

			if (p_pci_slave)
				nthw_pcie3_end_point_counters_sample_pre(p_pci_slave, sla);

			/* start measure */
			if (p_master_instance)
				nthw_hif_stat_req_enable(p_master_instance);

			if (p_pci_master)
				nthw_pcie3_stat_req_enable(p_pci_master);

			if (p_slave_instance)
				nthw_hif_stat_req_enable(p_slave_instance);

			if (p_pci_slave)
				nthw_pcie3_stat_req_enable(p_pci_slave);

			/* Wait */
			nt_os_wait_usec(delay);

			/* Stop measure */
			if (p_master_instance)
				nthw_hif_stat_req_disable(p_master_instance);

			if (p_pci_master)
				nthw_pcie3_stat_req_disable(p_pci_master);

			if (p_slave_instance)
				nthw_hif_stat_req_disable(p_slave_instance);

			if (p_pci_slave)
				nthw_pcie3_stat_req_disable(p_pci_slave);

			/* Post process master */
			if (p_master_instance)
				nthw_hif_end_point_counters_sample(p_master_instance, pri);

			if (p_pci_master)
				nthw_pcie3_end_point_counters_sample_post(p_pci_master, pri);

			/* Post process slave */
			if (p_slave_instance)
				nthw_hif_end_point_counters_sample(p_slave_instance, sla);

			if (p_pci_slave)
				nthw_pcie3_end_point_counters_sample_post(p_pci_slave, sla);

			{
				/* Check for TA transmit errors */
				uint32_t dw_good_pkts, dw_bad_pkts, dw_bad_length, dw_bad_payload;
				nt4ga_pci_ta_tg_ta_read_packet_good(p, &dw_good_pkts);
				nt4ga_pci_ta_tg_ta_read_packet_bad(p, &dw_bad_pkts);
				nt4ga_pci_ta_tg_ta_read_length_error(p, &dw_bad_length);
				nt4ga_pci_ta_tg_ta_read_payload_error(p, &dw_bad_payload);

				NT_LOG(DBG, NTHW,
					"%s: NUMA node %u: HIF: TA: Good pkts, Bad pkts, Bad length, Bad payload\n",
					__func__, n_numa_node);
				NT_LOG(DBG, NTHW,
					"%s: NUMA node %u: HIF: TA: 0x%08x 0x%08x 0x%08x 0x%08x\n",
					__func__, n_numa_node, dw_good_pkts, dw_bad_pkts,
					dw_bad_length, dw_bad_payload);

				if (dw_bad_pkts | dw_bad_length | dw_bad_payload) {
					bo_error |= 1;
					NT_LOG(ERR, NTHW,
						"%s: NUMA node %u: HIF: TA: error detected\n",
						__func__, n_numa_node);
					NT_LOG(ERR, NTHW,
						"%s: NUMA node %u: HIF: TA: Good packets received: %u\n",
						__func__, n_numa_node, dw_good_pkts);
					NT_LOG(ERR, NTHW,
						"%s: NUMA node %u: HIF: TA: Bad packets received : %u\n",
						__func__, n_numa_node, dw_bad_pkts);
					NT_LOG(ERR, NTHW,
						"%s: NUMA node %u: HIF: TA: Bad length received  : %u\n",
						__func__, n_numa_node, dw_bad_length);
					NT_LOG(ERR, NTHW,
						"%s: NUMA node %u: HIF: TA: Bad payload received : %u\n",
						__func__, n_numa_node, dw_bad_payload);
				}
			}

			if (bo_error != 0)
				break;

			break;	/* for now only loop once */

			/*
			 * Only do "signalstop" looping if a specific numa node and direction is to
			 * be tested.
			 */
		} while ((bo_error == 0) && (n_numa_node != UINT8_MAX) && (n_direction != -1));

		/* Stop the test */
		bo_error |= nt4ga_pci_ta_tg_wr_tg_run(p, 0);
		bo_error |= nt4ga_pci_ta_tg_wr_tg_wait_ready(p);

		bo_error |= nt4ga_pci_ta_tg_rd_tg_run(p, 0);
		bo_error |= nt4ga_pci_ta_tg_rd_tg_wait_ready(p);

		bo_error |= nt4ga_pci_ta_tg_ta_write_control_enable(p, 0);

		/* PCIe3 sanity checks */
		{
#if defined(DEBUG)
			int do_loop = 1;
#else
			int do_loop = 0;
#endif

			while (do_loop) {
				do_loop = 0;

				if (p_master_instance) {
					nthw_hif_stat_req_enable(p_master_instance);
					nt_os_wait_usec(100);
					nthw_hif_stat_req_disable(p_master_instance);
				}

				if (do_loop == 0)
					break;

				NT_LOG(DBG, NTHW, "%s: WARNING this is wrong - wait again\n",
					__func__);
				nt_os_wait_usec(200 * 1000);
			}
		}
	}

	/* Stop the test */

	bo_error |= nt4ga_pci_ta_tg_wr_tg_run(p, 0);
	bo_error |= nt4ga_pci_ta_tg_wr_tg_wait_ready(p);

	bo_error |= nt4ga_pci_ta_tg_rd_tg_run(p, 0);
	bo_error |= nt4ga_pci_ta_tg_rd_tg_wait_ready(p);

	bo_error |= nt4ga_pci_ta_tg_ta_write_control_enable(p, 0);

	nt_dma_free(p_dma);

	return bo_error;
}

int nt4ga_pci_ta_tg_measure_throughput_main(struct adapter_info_s *p_adapter_info,
	const uint8_t numa_node, const int direction,
	const int n_pkt_size, const int n_batch_count,
	const int n_delay)
{
	/* All numa nodes is indicated by UINT8_MAX */
	const uint8_t numa_begin = (numa_node == UINT8_MAX ? 0 : numa_node);
	const uint8_t numa_end = numa_begin;

	/* sanity check direction param */
	const int dir_begin = (direction <= 0 ? 1 : direction);
	const int dir_end = (direction <= 0 ? 3 : direction);

	int bo_error = 0;
	struct nthw_hif_end_points eps;

	if (n_delay == 0)
		return -1;

	NT_LOG(DBG, NTHW, "HIF adapter throughput:\n");

	/* Only do "signalstop"-looping if a specific numa node is to be tested. */
	{
		uint8_t numa;

		for (numa = numa_begin; numa <= numa_end; numa++) {
			int by_loop;

			for (by_loop = dir_begin; by_loop <= dir_end; by_loop++) {
				struct nthw_hif_end_point_counters *pri = &eps.pri;
				struct nthw_hif_end_point_counters *sla = &eps.sla;

				pri->n_numa_node = numa;
				pri->n_tg_direction = by_loop;
				pri->n_tg_pkt_size = (n_pkt_size > 0 ? n_pkt_size : TG_PKT_SIZE);
				pri->n_tg_num_pkts =
					(n_batch_count > 0 ? n_batch_count : TG_NUM_PACKETS);
				pri->n_tg_delay = (n_delay > 0 ? n_delay : TG_DELAY);
				pri->cur_rx = 0;
				pri->cur_tx = 0;
				pri->n_ref_clk_cnt = -1;
				pri->bo_error = 0;

				sla->n_numa_node = numa;
				sla->n_tg_direction = by_loop;
				sla->n_tg_pkt_size = (n_pkt_size > 0 ? n_pkt_size : TG_PKT_SIZE);
				sla->n_tg_num_pkts =
					(n_batch_count > 0 ? n_batch_count : TG_NUM_PACKETS);
				sla->n_tg_delay = (n_delay > 0 ? n_delay : TG_DELAY);
				sla->cur_rx = 0;
				sla->cur_tx = 0;
				pri->n_ref_clk_cnt = -1;
				sla->bo_error = 0;

				bo_error += nt4ga_pci_ta_tg_measure_throughput_run(p_adapter_info,
						pri, sla);
#if defined(DEBUG) && (1)
				{
					NT_LOG(DBG, NTHW,
						"%s: @ %d: %d %d %d %d: %016lX %016lX : %6ld Mbps %6ld Mbps\n",
						__func__, pri->n_numa_node, pri->n_tg_direction,
						pri->n_tg_num_pkts, pri->n_tg_pkt_size,
						pri->n_tg_delay, pri->cur_rx, pri->cur_tx,
						(pri->cur_rx * 8UL / 1000000UL),
						(pri->cur_tx * 8UL / 1000000UL));
				}
				{
					NT_LOG(DBG, NTHW,
						"%s: @ %d: %d %d %d %d: %016lX %016lX : %6ld Mbps %6ld Mbps\n",
						__func__, sla->n_numa_node, sla->n_tg_direction,
						sla->n_tg_num_pkts, sla->n_tg_pkt_size,
						sla->n_tg_delay, sla->cur_rx, sla->cur_tx,
						(sla->cur_rx * 8UL / 1000000UL),
						(sla->cur_tx * 8UL / 1000000UL));
				}
#endif

				if (pri->bo_error != 0 || sla->bo_error != 0)
					bo_error++;

				if (bo_error)
					break;
			}
		}
	}

	if (bo_error != 0)
		NT_LOG(ERR, NTHW, "%s: error during bandwidth measurement\n", __func__);

	NT_LOG(DBG, NTHW, "HIF adapter throughput: done %s\n", __func__);

	return 0;
}

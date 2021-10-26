/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_common.h>
#include <rte_cycles.h>
#include "otx_ep_common.h"
#include "otx2_ep_vf.h"

static void
otx2_vf_setup_global_iq_reg(struct otx_ep_device *otx_ep, int q_no)
{
	volatile uint64_t reg_val = 0ull;

	/* Select ES, RO, NS, RDSIZE,DPTR Format#0 for IQs
	 * IS_64B is by default enabled.
	 */
	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_IN_CONTROL(q_no));

	reg_val |= SDP_VF_R_IN_CTL_RDSIZE;
	reg_val |= SDP_VF_R_IN_CTL_IS_64B;
	reg_val |= SDP_VF_R_IN_CTL_ESR;

	otx2_write64(reg_val, otx_ep->hw_addr + SDP_VF_R_IN_CONTROL(q_no));
}

static void
otx2_vf_setup_global_oq_reg(struct otx_ep_device *otx_ep, int q_no)
{
	volatile uint64_t reg_val = 0ull;

	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_OUT_CONTROL(q_no));

	reg_val &= ~(SDP_VF_R_OUT_CTL_IMODE);
	reg_val &= ~(SDP_VF_R_OUT_CTL_ROR_P);
	reg_val &= ~(SDP_VF_R_OUT_CTL_NSR_P);
	reg_val &= ~(SDP_VF_R_OUT_CTL_ROR_I);
	reg_val &= ~(SDP_VF_R_OUT_CTL_NSR_I);
	reg_val &= ~(SDP_VF_R_OUT_CTL_ES_I);
	reg_val &= ~(SDP_VF_R_OUT_CTL_ROR_D);
	reg_val &= ~(SDP_VF_R_OUT_CTL_NSR_D);
	reg_val &= ~(SDP_VF_R_OUT_CTL_ES_D);

	/* INFO/DATA ptr swap is required  */
	reg_val |= (SDP_VF_R_OUT_CTL_ES_P);

	otx2_write64(reg_val, otx_ep->hw_addr + SDP_VF_R_OUT_CONTROL(q_no));
}

static void
otx2_vf_setup_global_input_regs(struct otx_ep_device *otx_ep)
{
	uint64_t q_no = 0ull;

	for (q_no = 0; q_no < (otx_ep->sriov_info.rings_per_vf); q_no++)
		otx2_vf_setup_global_iq_reg(otx_ep, q_no);
}

static void
otx2_vf_setup_global_output_regs(struct otx_ep_device *otx_ep)
{
	uint32_t q_no;

	for (q_no = 0; q_no < (otx_ep->sriov_info.rings_per_vf); q_no++)
		otx2_vf_setup_global_oq_reg(otx_ep, q_no);
}

static void
otx2_vf_setup_device_regs(struct otx_ep_device *otx_ep)
{
	otx2_vf_setup_global_input_regs(otx_ep);
	otx2_vf_setup_global_output_regs(otx_ep);
}

static void
otx2_vf_setup_iq_regs(struct otx_ep_device *otx_ep, uint32_t iq_no)
{
	struct otx_ep_instr_queue *iq = otx_ep->instr_queue[iq_no];
	volatile uint64_t reg_val = 0ull;

	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_IN_CONTROL(iq_no));

	/* Wait till IDLE to set to 1, not supposed to configure BADDR
	 * as long as IDLE is 0
	 */
	if (!(reg_val & SDP_VF_R_IN_CTL_IDLE)) {
		do {
			reg_val = otx2_read64(otx_ep->hw_addr +
					      SDP_VF_R_IN_CONTROL(iq_no));
		} while (!(reg_val & SDP_VF_R_IN_CTL_IDLE));
	}

	/* Write the start of the input queue's ring and its size  */
	otx2_write64(iq->base_addr_dma, otx_ep->hw_addr +
		     SDP_VF_R_IN_INSTR_BADDR(iq_no));
	otx2_write64(iq->nb_desc, otx_ep->hw_addr +
		     SDP_VF_R_IN_INSTR_RSIZE(iq_no));

	/* Remember the doorbell & instruction count register addr
	 * for this queue
	 */
	iq->doorbell_reg = (uint8_t *)otx_ep->hw_addr +
			   SDP_VF_R_IN_INSTR_DBELL(iq_no);
	iq->inst_cnt_reg = (uint8_t *)otx_ep->hw_addr +
			   SDP_VF_R_IN_CNTS(iq_no);

	otx_ep_dbg("InstQ[%d]:dbell reg @ 0x%p instcnt_reg @ 0x%p",
		   iq_no, iq->doorbell_reg, iq->inst_cnt_reg);

	do {
		reg_val = rte_read32(iq->inst_cnt_reg);
		rte_write32(reg_val, iq->inst_cnt_reg);
	} while (reg_val != 0);

	/* IN INTR_THRESHOLD is set to max(FFFFFFFF) which disable the IN INTR
	 * to raise
	 */
	otx2_write64(OTX_EP_CLEAR_SDP_IN_INT_LVLS,
		     otx_ep->hw_addr + SDP_VF_R_IN_INT_LEVELS(iq_no));
}

static void
otx2_vf_setup_oq_regs(struct otx_ep_device *otx_ep, uint32_t oq_no)
{
	volatile uint64_t reg_val = 0ull;
	uint64_t oq_ctl = 0ull;
	struct otx_ep_droq *droq = otx_ep->droq[oq_no];

	/* Wait on IDLE to set to 1, supposed to configure BADDR
	 * as log as IDLE is 0
	 */
	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_OUT_CONTROL(oq_no));

	while (!(reg_val & SDP_VF_R_OUT_CTL_IDLE)) {
		reg_val = otx2_read64(otx_ep->hw_addr +
				      SDP_VF_R_OUT_CONTROL(oq_no));
	}

	otx2_write64(droq->desc_ring_dma, otx_ep->hw_addr +
		     SDP_VF_R_OUT_SLIST_BADDR(oq_no));
	otx2_write64(droq->nb_desc, otx_ep->hw_addr +
		     SDP_VF_R_OUT_SLIST_RSIZE(oq_no));

	oq_ctl = otx2_read64(otx_ep->hw_addr + SDP_VF_R_OUT_CONTROL(oq_no));

	/* Clear the ISIZE and BSIZE (22-0) */
	oq_ctl &= ~(OTX_EP_CLEAR_ISIZE_BSIZE);

	/* Populate the BSIZE (15-0) */
	oq_ctl |= (droq->buffer_size & OTX_EP_DROQ_BUFSZ_MASK);

	otx2_write64(oq_ctl, otx_ep->hw_addr + SDP_VF_R_OUT_CONTROL(oq_no));

	/* Mapped address of the pkt_sent and pkts_credit regs */
	droq->pkts_sent_reg = (uint8_t *)otx_ep->hw_addr +
			      SDP_VF_R_OUT_CNTS(oq_no);
	droq->pkts_credit_reg = (uint8_t *)otx_ep->hw_addr +
				SDP_VF_R_OUT_SLIST_DBELL(oq_no);

	rte_write64(OTX_EP_CLEAR_OUT_INT_LVLS,
		    otx_ep->hw_addr + SDP_VF_R_OUT_INT_LEVELS(oq_no));

	/* Clear PKT_CNT register */
	rte_write64(OTX_EP_CLEAR_SDP_OUT_PKT_CNT, (uint8_t *)otx_ep->hw_addr +
		    SDP_VF_R_OUT_PKT_CNT(oq_no));

	/* Clear the OQ doorbell  */
	rte_write32(OTX_EP_CLEAR_SLIST_DBELL, droq->pkts_credit_reg);
	while ((rte_read32(droq->pkts_credit_reg) != 0ull)) {
		rte_write32(OTX_EP_CLEAR_SLIST_DBELL, droq->pkts_credit_reg);
		rte_delay_ms(1);
	}
	otx_ep_dbg("SDP_R[%d]_credit:%x", oq_no,
		   rte_read32(droq->pkts_credit_reg));

	/* Clear the OQ_OUT_CNTS doorbell  */
	reg_val = rte_read32(droq->pkts_sent_reg);
	rte_write32((uint32_t)reg_val, droq->pkts_sent_reg);

	otx_ep_dbg("SDP_R[%d]_sent: %x", oq_no,
		   rte_read32(droq->pkts_sent_reg));

	while (((rte_read32(droq->pkts_sent_reg)) != 0ull)) {
		reg_val = rte_read32(droq->pkts_sent_reg);
		rte_write32((uint32_t)reg_val, droq->pkts_sent_reg);
		rte_delay_ms(1);
	}
	otx_ep_dbg("SDP_R[%d]_sent: %x", oq_no,
		   rte_read32(droq->pkts_sent_reg));
}

static int
otx2_vf_enable_iq(struct otx_ep_device *otx_ep, uint32_t q_no)
{
	uint64_t loop = SDP_VF_BUSY_LOOP_COUNT;
	uint64_t reg_val = 0ull;

	/* Resetting doorbells during IQ enabling also to handle abrupt
	 * guest reboot. IQ reset does not clear the doorbells.
	 */
	otx2_write64(0xFFFFFFFF, otx_ep->hw_addr +
		     SDP_VF_R_IN_INSTR_DBELL(q_no));

	while (((otx2_read64(otx_ep->hw_addr +
		 SDP_VF_R_IN_INSTR_DBELL(q_no))) != 0ull) && loop--) {
		rte_delay_ms(1);
	}

	if (!loop) {
		otx_ep_err("INSTR DBELL not coming back to 0\n");
		return -EIO;
	}

	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_IN_ENABLE(q_no));
	reg_val |= 0x1ull;

	otx2_write64(reg_val, otx_ep->hw_addr + SDP_VF_R_IN_ENABLE(q_no));

	otx_ep_info("IQ[%d] enable done", q_no);

	return 0;
}

static int
otx2_vf_enable_oq(struct otx_ep_device *otx_ep, uint32_t q_no)
{
	uint64_t reg_val = 0ull;

	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_OUT_ENABLE(q_no));
	reg_val |= 0x1ull;
	otx2_write64(reg_val, otx_ep->hw_addr + SDP_VF_R_OUT_ENABLE(q_no));

	otx_ep_info("OQ[%d] enable done", q_no);

	return 0;
}

static int
otx2_vf_enable_io_queues(struct otx_ep_device *otx_ep)
{
	uint32_t q_no = 0;
	int ret;

	for (q_no = 0; q_no < otx_ep->nb_tx_queues; q_no++) {
		ret = otx2_vf_enable_iq(otx_ep, q_no);
		if (ret)
			return ret;
	}

	for (q_no = 0; q_no < otx_ep->nb_rx_queues; q_no++)
		otx2_vf_enable_oq(otx_ep, q_no);

	return 0;
}

static void
otx2_vf_disable_iq(struct otx_ep_device *otx_ep, uint32_t q_no)
{
	uint64_t reg_val = 0ull;

	/* Reset the doorbell register for this Input Queue. */
	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_IN_ENABLE(q_no));
	reg_val &= ~0x1ull;

	otx2_write64(reg_val, otx_ep->hw_addr + SDP_VF_R_IN_ENABLE(q_no));
}

static void
otx2_vf_disable_oq(struct otx_ep_device *otx_ep, uint32_t q_no)
{
	volatile uint64_t reg_val = 0ull;

	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_OUT_ENABLE(q_no));
	reg_val &= ~0x1ull;

	otx2_write64(reg_val, otx_ep->hw_addr + SDP_VF_R_OUT_ENABLE(q_no));
}

static void
otx2_vf_disable_io_queues(struct otx_ep_device *otx_ep)
{
	uint32_t q_no = 0;

	for (q_no = 0; q_no < otx_ep->sriov_info.rings_per_vf; q_no++) {
		otx2_vf_disable_iq(otx_ep, q_no);
		otx2_vf_disable_oq(otx_ep, q_no);
	}
}

static const struct otx_ep_config default_otx2_ep_conf = {
	/* IQ attributes */
	.iq                        = {
		.max_iqs           = OTX_EP_CFG_IO_QUEUES,
		.instr_type        = OTX_EP_64BYTE_INSTR,
		.pending_list_size = (OTX_EP_MAX_IQ_DESCRIPTORS *
				      OTX_EP_CFG_IO_QUEUES),
	},

	/* OQ attributes */
	.oq                        = {
		.max_oqs           = OTX_EP_CFG_IO_QUEUES,
		.info_ptr          = OTX_EP_OQ_INFOPTR_MODE,
		.refill_threshold  = OTX_EP_OQ_REFIL_THRESHOLD,
	},

	.num_iqdef_descs           = OTX_EP_MAX_IQ_DESCRIPTORS,
	.num_oqdef_descs           = OTX_EP_MAX_OQ_DESCRIPTORS,
	.oqdef_buf_size            = OTX_EP_OQ_BUF_SIZE,
};

static const struct otx_ep_config*
otx2_ep_get_defconf(struct otx_ep_device *otx_ep_dev __rte_unused)
{
	const struct otx_ep_config *default_conf = NULL;

	default_conf = &default_otx2_ep_conf;

	return default_conf;
}

int
otx2_ep_vf_setup_device(struct otx_ep_device *otx_ep)
{
	uint64_t reg_val = 0ull;

	/* If application doesn't provide its conf, use driver default conf */
	if (otx_ep->conf == NULL) {
		otx_ep->conf = otx2_ep_get_defconf(otx_ep);
		if (otx_ep->conf == NULL) {
			otx_ep_err("SDP VF default config not found");
			return -ENOENT;
		}
		otx_ep_info("Default config is used");
	}

	/* Get IOQs (RPVF] count */
	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_IN_CONTROL(0));

	otx_ep->sriov_info.rings_per_vf = ((reg_val >> SDP_VF_R_IN_CTL_RPVF_POS)
					  & SDP_VF_R_IN_CTL_RPVF_MASK);

	otx_ep_info("SDP RPVF: %d", otx_ep->sriov_info.rings_per_vf);

	otx_ep->fn_list.setup_iq_regs       = otx2_vf_setup_iq_regs;
	otx_ep->fn_list.setup_oq_regs       = otx2_vf_setup_oq_regs;

	otx_ep->fn_list.setup_device_regs   = otx2_vf_setup_device_regs;

	otx_ep->fn_list.enable_io_queues    = otx2_vf_enable_io_queues;
	otx_ep->fn_list.disable_io_queues   = otx2_vf_disable_io_queues;

	otx_ep->fn_list.enable_iq           = otx2_vf_enable_iq;
	otx_ep->fn_list.disable_iq          = otx2_vf_disable_iq;

	otx_ep->fn_list.enable_oq           = otx2_vf_enable_oq;
	otx_ep->fn_list.disable_oq          = otx2_vf_disable_oq;

	return 0;
}

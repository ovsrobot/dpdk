/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell.
 */

#include "otx2_common.h"
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

#if defined(BUFPTR_ONLY_MODE)
	reg_val &= ~(SDP_VF_R_OUT_CTL_IMODE);
#else
	reg_val |= (SDP_VF_R_OUT_CTL_IMODE);
#endif

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

static int
otx2_vf_setup_device_regs(struct otx_ep_device *otx_ep)
{
	otx2_vf_setup_global_input_regs(otx_ep);
	otx2_vf_setup_global_output_regs(otx_ep);

	return 0;
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
			otx2_err("SDP VF default config not found");
			return -ENOMEM;
		}
		otx2_info("Default config is used");
	}

	/* Get IOQs (RPVF] count */
	reg_val = otx2_read64(otx_ep->hw_addr + SDP_VF_R_IN_CONTROL(0));

	otx_ep->sriov_info.rings_per_vf = ((reg_val >> SDP_VF_R_IN_CTL_RPVF_POS)
					  & SDP_VF_R_IN_CTL_RPVF_MASK);

	otx2_info("SDP RPVF: %d", otx_ep->sriov_info.rings_per_vf);

	otx_ep->fn_list.setup_device_regs   = otx2_vf_setup_device_regs;

	return 0;
}

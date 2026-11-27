/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#include <rte_memzone.h>

#include "qat_logs.h"
#include "qat_comp.h"
#include "qat_comp_pmd.h"
#include "qat_comp_pmd_gens.h"
#include "icp_qat_hw_gen4_comp.h"

static const struct rte_compressdev_capabilities
qat_gen6_comp_capabilities[] = {
	{/* COMPRESSION - deflate */
	 .algo = RTE_COMP_ALGO_DEFLATE,
	 .comp_feature_flags = RTE_COMP_FF_MULTI_PKT_CHECKSUM |
				RTE_COMP_FF_CRC32_CHECKSUM |
				RTE_COMP_FF_ADLER32_CHECKSUM |
				RTE_COMP_FF_CRC32_ADLER32_CHECKSUM |
				RTE_COMP_FF_SHAREABLE_PRIV_XFORM |
				RTE_COMP_FF_HUFFMAN_DYNAMIC |
				RTE_COMP_FF_HUFFMAN_FIXED |
				RTE_COMP_FF_OOP_SGL_IN_SGL_OUT |
				RTE_COMP_FF_OOP_SGL_IN_LB_OUT |
				RTE_COMP_FF_OOP_LB_IN_SGL_OUT,
	 .window_size = {.min = 15, .max = 15, .increment = 0} },
	 RTE_COMP_END_OF_CAPABILITIES_LIST() };

static struct rte_compressdev_ops qat_comp_ops_gen6 = {

	/* Device related operations */
	.dev_configure		= qat_comp_dev_config_gen4,
	.dev_start		= qat_comp_dev_start,
	.dev_stop		= qat_comp_dev_stop,
	.dev_close		= qat_comp_dev_close,
	.dev_infos_get		= qat_comp_dev_info_get,

	.stats_get		= qat_comp_stats_get,
	.stats_reset		= qat_comp_stats_reset,
	.queue_pair_setup	= qat_comp_qp_setup,
	.queue_pair_release	= qat_comp_qp_release,

	/* Compression related operations */
	.private_xform_create	= qat_comp_private_xform_create,
	.private_xform_free	= qat_comp_private_xform_free,
	.stream_create		= qat_comp_stream_create,
	.stream_free		= qat_comp_stream_free
};

/* GEN6 specific. */
int
qat_comp_create_templates_gen6(struct qat_comp_xform *qat_xform,
			       __rte_unused const struct rte_memzone *interm_buff_mz,
			       const struct rte_comp_xform *xform,
			       __rte_unused const struct qat_comp_stream *stream,
			       enum rte_comp_op_type op_type,
			       enum qat_device_gen qat_dev_gen)
{
	struct icp_qat_fw_comp_req *comp_req;
	int res;

	if (unlikely(qat_xform == NULL)) {
		QAT_LOG(ERR, "Session was not created for this device");
		return -EINVAL;
	}

	/* Template below carries no stream state, so stateful ops would run stateless. */
	if (unlikely(op_type == RTE_COMP_OP_STATEFUL)) {
		QAT_LOG(ERR, "QAT GEN6 PMD does not support stateful operations");
		return -ENOTSUP;
	}

	comp_req = &qat_xform->qat_comp_req_tmpl;

	/* Initialize header */
	if (qat_xform->qat_comp_request_type == QAT_COMP_REQUEST_FIXED_COMP_STATELESS ||
	    qat_xform->qat_comp_request_type == QAT_COMP_REQUEST_DYNAMIC_COMP_STATELESS)
		comp_req->comn_hdr.service_cmd_id = ICP_QAT_GEN6_FW_COMP_CMD_DEFLATE_COMP;
	else if (qat_xform->qat_comp_request_type == QAT_COMP_REQUEST_DECOMPRESS)
		comp_req->comn_hdr.service_cmd_id = ICP_QAT_GEN6_FW_COMP_CMD_DEFLATE_DECOMP;

	comp_req->comn_hdr.service_type = ICP_QAT_FW_COMN_REQ_CPM_FW_COMP;

	comp_req->comn_hdr.hdr_flags =
	    ICP_QAT_FW_COMN_HDR_FLAGS_BUILD(ICP_QAT_FW_COMN_REQ_FLAG_SET);

	comp_req->comn_hdr.serv_specif_flags = 0;

	comp_req->comn_hdr.comn_req_flags = ICP_QAT_FW_COMN_FLAGS_BUILD(
		QAT_COMN_CD_FLD_TYPE_16BYTE_DATA, QAT_COMN_PTR_TYPE_FLAT);

	res = qat_comp_gen_dev_ops[qat_dev_gen].qat_comp_set_slice_cfg_word(
			qat_xform, xform, op_type,
			comp_req->cd_pars.sl.comp_slice_cfg_word);
	if (res != 0)
		return res;

	comp_req->comp_pars.initial_adler = 1;
	comp_req->comp_pars.initial_crc32 = 0;
	comp_req->comp_pars.req_par_flags =
		(ICP_QAT_FW_COMP_BFINAL << ICP_QAT_FW_COMP_BFINAL_BITPOS);

#if RTE_LOG_DP_LEVEL >= RTE_LOG_DEBUG
	QAT_DP_HEXDUMP_LOG(DEBUG, "qat compression message template:", comp_req,
		    sizeof(struct icp_qat_fw_comp_req));
#endif
	return 0;
}

static struct qat_comp_capabilities_info
qat_comp_cap_get_gen6(struct qat_pci_device *qat_dev __rte_unused)
{
	struct qat_comp_capabilities_info capa_info = {
		.data = qat_gen6_comp_capabilities,
		.size = sizeof(qat_gen6_comp_capabilities)
	};
	return capa_info;
}

RTE_INIT(qat_comp_pmd_gen6_init)
{
	qat_comp_gen_dev_ops[QAT_GEN6].compressdev_ops =
			&qat_comp_ops_gen6;
	qat_comp_gen_dev_ops[QAT_GEN6].qat_comp_get_capabilities =
			qat_comp_cap_get_gen6;
	qat_comp_gen_dev_ops[QAT_GEN6].qat_comp_get_num_im_bufs_required =
			qat_comp_get_num_im_bufs_required_gen4;
	qat_comp_gen_dev_ops[QAT_GEN6].qat_comp_get_ram_bank_flags =
			qat_comp_get_ram_bank_flags_gen4;
	qat_comp_gen_dev_ops[QAT_GEN6].qat_comp_set_slice_cfg_word =
			qat_comp_set_slice_cfg_word_gen4;
	qat_comp_gen_dev_ops[QAT_GEN6].qat_comp_get_feature_flags =
			qat_comp_get_features_gen1;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include "qat_sym_pmd.h"
#include "qat_sym_session.h"
#include "qat_sym.h"

#define MIXED_CRYPTO_MIN_FW_VER 0x04090000

static int qat_sym_qp_setup_gen2(struct rte_cryptodev *dev, uint16_t qp_id,
	const struct rte_cryptodev_qp_conf *qp_conf,
	int socket_id)
{
	int ret;
	struct qat_qp_config qat_qp_conf = { };
	const struct qat_qp_hw_data *sym_hw_qps = NULL;
	struct qat_sym_dev_private *qat_sym_private = dev->data->dev_private;
	struct qat_pci_device *qat_dev = qat_sym_private->qat_dev;
	struct qat_qp *qp;

	sym_hw_qps = qat_gen_config[qat_dev->qat_dev_gen]
		.qp_hw_data[QAT_SERVICE_SYMMETRIC];
	qat_qp_conf.hw = sym_hw_qps + qp_id;

	if (qat_sym_qp_setup(dev, qp_id, qp_conf, qat_qp_conf, socket_id)) {
		return -1;
	}
	qp = qat_sym_private->qat_dev->qps_in_use[QAT_SERVICE_SYMMETRIC][qp_id];
	ret = qat_cq_get_fw_version(qp);
	if (ret < 0) {
		qat_sym_qp_release(dev, qp_id);
		return ret;
	}

	if (ret != 0)
		QAT_LOG(DEBUG, "QAT firmware version: %d.%d.%d",
				(ret >> 24) & 0xff,
				(ret >> 16) & 0xff,
				(ret >> 8) & 0xff);
	else
		QAT_LOG(DEBUG, "unknown QAT firmware version");

	/* set capabilities based on the fw version */
	qat_sym_private->internal_capabilities = QAT_SYM_CAP_VALID |
			((ret >= MIXED_CRYPTO_MIN_FW_VER) ?
					QAT_SYM_CAP_MIXED_CRYPTO : 0);
	return 0;
}

struct rte_cryptodev_ops crypto_qat_gen2_ops = {

		/* Device related operations */
		.dev_configure		= qat_sym_dev_config,
		.dev_start		= qat_sym_dev_start,
		.dev_stop		= qat_sym_dev_stop,
		.dev_close		= qat_sym_dev_close,
		.dev_infos_get		= qat_sym_dev_info_get,

		.stats_get		= qat_sym_stats_get,
		.stats_reset		= qat_sym_stats_reset,
		.queue_pair_setup	= qat_sym_qp_setup_gen2,
		.queue_pair_release	= qat_sym_qp_release,

		/* Crypto related operations */
		.sym_session_get_size	= qat_sym_session_get_private_size,
		.sym_session_configure	= qat_sym_session_configure,
		.sym_session_clear	= qat_sym_session_clear,

		/* Raw data-path API related operations */
		.sym_get_raw_dp_ctx_size = qat_sym_get_dp_ctx_size,
		.sym_configure_raw_dp_ctx = qat_sym_configure_dp_ctx,
};

RTE_INIT(qat_sym_pmd_gen2)
{
	QAT_CRYPTODEV_OPS[QAT_GEN2] = &crypto_qat_gen2_ops;
}

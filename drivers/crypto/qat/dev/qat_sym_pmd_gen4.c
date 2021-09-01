/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include "qat_sym_pmd.h"
#include "qat_sym_session.h"
#include "qat_sym.h"

static struct rte_cryptodev_capabilities qat_gen4_sym_capabilities[] = {
	QAT_BASE_GEN4_SYM_CAPABILITIES,
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

static int
qat_select_valid_queue(struct qat_pci_device *qat_dev, int qp_id,
			enum qat_service_type service_type)
{
	int i = 0, valid_qps = 0;

	for (; i < QAT_GEN4_BUNDLE_NUM; i++) {
		if (qat_dev->qp_gen4_data[i][0].service_type ==
			service_type) {
			if (valid_qps == qp_id)
				return i;
			++valid_qps;
		}
	}
	return -1;
}

static int qat_sym_qp_setup_gen4(struct rte_cryptodev *dev, uint16_t qp_id,
	const struct rte_cryptodev_qp_conf *qp_conf,
	int socket_id)
{
	int ret = 0;
	int ring_pair;
	struct qat_qp_config qat_qp_conf = { };
	struct qat_sym_dev_private *qat_sym_private = dev->data->dev_private;
	struct qat_pci_device *qat_dev = qat_sym_private->qat_dev;

	ring_pair =
		qat_select_valid_queue(qat_sym_private->qat_dev, qp_id,
			QAT_SERVICE_SYMMETRIC);
	if (ring_pair < 0) {
		QAT_LOG(ERR,
			"qp_id %u invalid for this device, no enough services allocated for GEN4 device",
			qp_id);
		return -EINVAL;
	}
	qat_qp_conf.hw =
		&qat_dev->qp_gen4_data[ring_pair][0];

	ret = qat_sym_qp_setup(dev, qp_id, qp_conf, qat_qp_conf, socket_id);

	return ret;
}

struct rte_cryptodev_ops crypto_qat_gen4_ops = {

		/* Device related operations */
		.dev_configure		= qat_sym_dev_config,
		.dev_start		= qat_sym_dev_start,
		.dev_stop		= qat_sym_dev_stop,
		.dev_close		= qat_sym_dev_close,
		.dev_infos_get		= qat_sym_dev_info_get,

		.stats_get		= qat_sym_stats_get,
		.stats_reset		= qat_sym_stats_reset,
		.queue_pair_setup	= qat_sym_qp_setup_gen4,
		.queue_pair_release	= qat_sym_qp_release,

		/* Crypto related operations */
		.sym_session_get_size	= qat_sym_session_get_private_size,
		.sym_session_configure	= qat_sym_session_configure,
		.sym_session_clear	= qat_sym_session_clear,

		/* Raw data-path API related operations */
		.sym_get_raw_dp_ctx_size = qat_sym_get_dp_ctx_size,
		.sym_configure_raw_dp_ctx = qat_sym_configure_dp_ctx,
};

static struct
qat_capabilities_info get_capabilties_gen4(
			struct qat_pci_device *qat_dev __rte_unused)
{
	struct qat_capabilities_info capa_info;

	capa_info.data = qat_gen4_sym_capabilities;
	capa_info.size = sizeof(qat_gen4_sym_capabilities);
	return capa_info;
}

static struct
qat_sym_pmd_dev_ops qat_sym_pmd_ops_gen4 = {
	.qat_sym_get_capabilities	= get_capabilties_gen4,
};

RTE_INIT(qat_sym_pmd_gen4_init)
{
	QAT_CRYPTODEV_OPS[QAT_GEN4]	= &crypto_qat_gen4_ops;
	qat_sym_pmd_ops[QAT_GEN4]	= &qat_sym_pmd_ops_gen4;
}

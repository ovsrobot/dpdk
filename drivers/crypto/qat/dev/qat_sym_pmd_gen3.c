/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include "qat_sym_pmd.h"
#include "qat_sym_session.h"
#include "qat_sym.h"
#include "qat_sym_pmd_gen1.h"

static struct rte_cryptodev_capabilities qat_gen3_sym_capabilities[] = {
	QAT_BASE_GEN1_SYM_CAPABILITIES,
	QAT_EXTRA_GEN2_SYM_CAPABILITIES,
	QAT_EXTRA_GEN3_SYM_CAPABILITIES,
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

struct rte_cryptodev_ops crypto_qat_gen3_ops = {

		/* Device related operations */
		.dev_configure		= qat_sym_dev_config,
		.dev_start		= qat_sym_dev_start,
		.dev_stop		= qat_sym_dev_stop,
		.dev_close		= qat_sym_dev_close,
		.dev_infos_get		= qat_sym_dev_info_get,

		.stats_get		= qat_sym_stats_get,
		.stats_reset		= qat_sym_stats_reset,
		.queue_pair_setup	= qat_sym_qp_setup_gen1,
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
qat_capabilities_info get_capabilties_gen3(
			struct qat_pci_device *qat_dev __rte_unused)
{
	struct qat_capabilities_info capa_info;
	capa_info.data = qat_gen3_sym_capabilities;
	capa_info.size = sizeof(qat_gen3_sym_capabilities);
	return capa_info;
}

static struct
qat_sym_pmd_dev_ops qat_sym_pmd_ops_gen3 = {
	.qat_sym_get_capabilities	= get_capabilties_gen3,
};


RTE_INIT(qat_sym_pmd_gen3_init)
{
	QAT_CRYPTODEV_OPS[QAT_GEN3]	= &crypto_qat_gen3_ops;
	qat_sym_pmd_ops[QAT_GEN3]	= &qat_sym_pmd_ops_gen3;
}

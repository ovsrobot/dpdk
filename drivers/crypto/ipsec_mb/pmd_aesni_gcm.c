/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2021 Intel Corporation
 */

#include "pmd_aesni_gcm_priv.h"
#include "pmd_aesni_mb_priv.h"

struct rte_cryptodev_ops aesni_gcm_pmd_ops = {
	.dev_configure = ipsec_mb_config,
	.dev_start = ipsec_mb_start,
	.dev_stop = ipsec_mb_stop,
	.dev_close = ipsec_mb_close,

	.stats_get = ipsec_mb_stats_get,
	.stats_reset = ipsec_mb_stats_reset,

	.dev_infos_get = ipsec_mb_info_get,

	.queue_pair_setup = ipsec_mb_qp_setup,
	.queue_pair_release = ipsec_mb_qp_release,

	.sym_cpu_process = aesni_mb_process_bulk,

	.sym_session_get_size = ipsec_mb_sym_session_get_size,
	.sym_session_configure = ipsec_mb_sym_session_configure,
	.sym_session_clear = ipsec_mb_sym_session_clear
};

static int
aesni_gcm_probe(struct rte_vdev_device *vdev)
{
	return ipsec_mb_create(vdev, IPSEC_MB_PMD_TYPE_AESNI_GCM);
}

static struct rte_vdev_driver cryptodev_aesni_gcm_pmd_drv = {
	.probe = aesni_gcm_probe,
	.remove = ipsec_mb_remove
};

static struct cryptodev_driver aesni_gcm_crypto_drv;

RTE_PMD_REGISTER_VDEV(CRYPTODEV_NAME_AESNI_GCM_PMD,
		      cryptodev_aesni_gcm_pmd_drv);
RTE_PMD_REGISTER_ALIAS(CRYPTODEV_NAME_AESNI_GCM_PMD, cryptodev_aesni_gcm_pmd);
RTE_PMD_REGISTER_PARAM_STRING(CRYPTODEV_NAME_AESNI_GCM_PMD,
			      "max_nb_queue_pairs=<int> socket_id=<int>");
RTE_PMD_REGISTER_CRYPTO_DRIVER(aesni_gcm_crypto_drv,
			       cryptodev_aesni_gcm_pmd_drv.driver,
			       pmd_driver_id_aesni_gcm);

/* Constructor function to register aesni-gcm PMD */
RTE_INIT(ipsec_mb_register_aesni_gcm)
{
	struct ipsec_mb_internals *aesni_gcm_data =
		&ipsec_mb_pmds[IPSEC_MB_PMD_TYPE_AESNI_GCM];

	aesni_gcm_data->caps = aesni_gcm_capabilities;
	aesni_gcm_data->dequeue_burst = aesni_mb_dequeue_burst;
	aesni_gcm_data->feature_flags =
		RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
		RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
		RTE_CRYPTODEV_FF_IN_PLACE_SGL |
		RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT |
		RTE_CRYPTODEV_FF_OOP_LB_IN_LB_OUT |
		RTE_CRYPTODEV_FF_SYM_CPU_CRYPTO |
		RTE_CRYPTODEV_FF_SYM_SESSIONLESS;
	aesni_gcm_data->internals_priv_size = 0;
	aesni_gcm_data->ops = &aesni_gcm_pmd_ops;
	aesni_gcm_data->qp_priv_size = sizeof(struct aesni_gcm_qp_data);
	aesni_gcm_data->queue_pair_configure = NULL;
	aesni_gcm_data->session_configure = aesni_mb_session_configure;
	aesni_gcm_data->session_priv_size = sizeof(struct aesni_mb_session);
}

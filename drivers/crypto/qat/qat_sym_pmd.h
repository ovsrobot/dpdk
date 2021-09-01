/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2018 Intel Corporation
 */

#ifndef _QAT_SYM_PMD_H_
#define _QAT_SYM_PMD_H_

#ifdef BUILD_QAT_SYM

#include <rte_ether.h>
#include <rte_cryptodev.h>
#ifdef RTE_LIB_SECURITY
#include <rte_security.h>
#endif

#include "qat_sym_capabilities.h"
#include "qat_device.h"
#include "qat_qp.h"

/** Intel(R) QAT Symmetric Crypto PMD driver name */
#define CRYPTODEV_NAME_QAT_SYM_PMD	crypto_qat

/* Internal capabilities */
#define QAT_SYM_CAP_MIXED_CRYPTO	(1 << 0)
#define QAT_SYM_CAP_VALID		(1 << 31)

extern uint8_t qat_sym_driver_id;

extern struct rte_cryptodev_ops *QAT_CRYPTODEV_OPS[];

/** private data structure for a QAT device.
 * This QAT device is a device offering only symmetric crypto service,
 * there can be one of these on each qat_pci_device (VF).
 */
struct qat_sym_dev_private {
	struct qat_pci_device *qat_dev;
	/**< The qat pci device hosting the service */
	uint8_t sym_dev_id;
	/**< Device instance for this rte_cryptodev */
	const struct rte_cryptodev_capabilities *qat_dev_capabilities;
	/* QAT device symmetric crypto capabilities */
	const struct rte_memzone *capa_mz;
	/* Shared memzone for storing capabilities */
	uint16_t min_enq_burst_threshold;
	uint32_t internal_capabilities; /* see flags QAT_SYM_CAP_xxx */
};

int
qat_sym_dev_create(struct qat_pci_device *qat_pci_dev,
		struct qat_dev_cmd_param *qat_dev_cmd_param);

int
qat_sym_dev_destroy(struct qat_pci_device *qat_pci_dev);

int qat_sym_qp_release(struct rte_cryptodev *dev, uint16_t queue_pair_id);

int qat_sym_qp_setup(struct rte_cryptodev *dev, uint16_t qp_id,
	const struct rte_cryptodev_qp_conf *qp_conf, struct qat_qp_config qat_qp_conf,
	int socket_id);

void qat_sym_stats_reset(struct rte_cryptodev *dev);

void qat_sym_stats_get(struct rte_cryptodev *dev,
		struct rte_cryptodev_stats *stats);

void qat_sym_dev_info_get(struct rte_cryptodev *dev,
			struct rte_cryptodev_info *info);

int qat_sym_dev_config(__rte_unused struct rte_cryptodev *dev,
		__rte_unused struct rte_cryptodev_config *config);
int qat_sym_dev_close(struct rte_cryptodev *dev);
void qat_sym_dev_stop(__rte_unused struct rte_cryptodev *dev);
int qat_sym_dev_start(__rte_unused struct rte_cryptodev *dev);

#endif
#endif /* _QAT_SYM_PMD_H_ */

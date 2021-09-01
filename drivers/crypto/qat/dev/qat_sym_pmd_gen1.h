/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <rte_cryptodev.h>
#include <stdint.h>

#ifndef _QAT_DEV_GEN_H_
#define _QAT_DEV_GEN_H_

int qat_sym_qp_setup_gen1(struct rte_cryptodev *dev, uint16_t qp_id,
	const struct rte_cryptodev_qp_conf *qp_conf,
	int socket_id);

#endif

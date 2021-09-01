/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#ifndef _QAT_DEV_GEN_H_
#define _QAT_DEV_GEN_H_

#include <stdint.h>

struct qat_dev_gen4_extra;

enum qat_service_type qat_dev4_get_qp_serv(
		struct qat_dev_gen4_extra *dev_extra, int ring_pair);

const struct qat_qp_hw_data *qat_dev4_get_hw(
		struct qat_dev_gen4_extra *dev_extra, int ring_pair);

#endif

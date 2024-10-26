/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_COMP_H_
#define _ZSDA_COMP_H_

#include <rte_compressdev.h>

#include "zsda_common.h"
#include "zsda_device.h"
#include "zsda_qp.h"

struct zsda_comp_xform {
	enum rte_comp_xform_type type;
	enum rte_comp_checksum_type checksum_type;
};

struct compress_cfg {
} __rte_packed;

struct zsda_wqe_comp {
	uint8_t valid;
	uint8_t op_code;
	uint16_t sid;
	uint8_t resv[3];
	uint8_t rx_sgl_type : 4;
	uint8_t tx_sgl_type : 4;
	uint64_t rx_addr;
	uint32_t rx_length;
	uint64_t tx_addr;
	uint32_t tx_length;
	struct compress_cfg cfg;
} __rte_packed;

/* For situations where err0 are reported but the results are correct */
#define DECOMP_RIGHT_ERR0_0 0xc710
#define DECOMP_RIGHT_ERR0_1 0xc727
#define DECOMP_RIGHT_ERR0_2 0xc729
#define CQE_ERR0_RIGHT(value)                                                  \
	(value == DECOMP_RIGHT_ERR0_0 || value == DECOMP_RIGHT_ERR0_1 ||       \
	 value == DECOMP_RIGHT_ERR0_2)

int zsda_comp_match(const void *op_in);

int zsda_decomp_match(const void *op_in);

int zsda_build_comp_request(void *op_in, const struct zsda_queue *queue,
		       void **op_cookies, const uint16_t new_tail);

int zsda_build_decomp_request(void *op_in, const struct zsda_queue *queue,
			 void **op_cookies, const uint16_t new_tail);
#endif /* _ZSDA_COMP_H_ */

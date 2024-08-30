/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_SYM_H_
#define _ZSDA_SYM_H_

#include "zsda_common.h"
#include "zsda_qp.h"

int zsda_build_cipher_request(void *op_in, const struct zsda_queue *queue,
			 void **op_cookies, const uint16_t new_tail);

int zsda_build_hash_request(void *op_in, const struct zsda_queue *queue,
		       void **op_cookies, const uint16_t new_tail);

int zsda_encry_match(const void *op_in);
int zsda_decry_match(const void *op_in);
int zsda_hash_match(const void *op_in);

void zsda_reverse_memcpy(uint8_t *dst, const uint8_t *src, size_t n);

void zsda_crypto_callback(void *cookie_in, const struct zsda_cqe *cqe);

#endif /* _ZSDA_SYM_H_ */

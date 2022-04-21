/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2021 Atomic Rules LLC
 */

#ifndef _ARK_BBDEV_CUSTOM_H_
#define _ARK_BBDEV_CUSTOM_H_

#include <stdint.h>

/* Forward declarations */
struct rte_bbdev;
struct rte_bbdev_driver_info;
struct rte_bbdev_enc_op;
struct rte_bbdev_dec_op;
struct rte_mbuf;

void ark_bbdev_info_get(struct rte_bbdev *dev,
			struct rte_bbdev_driver_info *dev_info);

int ark_bb_user_enqueue_ldpc_dec(struct rte_bbdev_dec_op *enc_op,
				 uint32_t *meta, uint8_t *meta_cnt);
int ark_bb_user_dequeue_ldpc_dec(struct rte_bbdev_dec_op *enc_op,
				 const uint32_t *usermeta);

int ark_bb_user_enqueue_ldpc_enc(struct rte_bbdev_enc_op *enc_op,
				 uint32_t *meta, uint8_t *meta_cnt);
int ark_bb_user_dequeue_ldpc_enc(struct rte_bbdev_enc_op *enc_op,
				 const uint32_t *usermeta);

#endif

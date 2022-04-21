/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Atomic Rules LLC
 */

#ifndef _ARK_BBEXT_H_
#define _ARK_BBEXT_H_

#include <rte_bbdev.h>
#include <rte_bbdev_pmd.h>

/* The following section lists function prototypes for Arkville's
 * baseband dynamic PMD extension. User's who create an extension
 * must include this file and define the necessary and desired
 * functions. Only 1 function is required for an extension,
 * rte_pmd_ark_bbdev_init(); all other functions prototypes in this
 * section are optional.
 * See documentation for compiling and use of extensions.
 */

/**
 * Extension prototype, required implementation if extensions are used.
 * Called during device probe to initialize the user structure
 * passed to other extension functions.  This is called once for each
 * port of the device.
 *
 * @param dev
 *   current device.
 * @param a_bar
 *   access to PCIe device bar (application bar) and hence access to
 *   user's portion of FPGA.
 * @return user_data
 *   which will be passed to other extension functions.
 */
void *rte_pmd_ark_bbdev_init(struct rte_bbdev *dev, void *a_bar);

/**
 * Extension prototype, optional implementation.
 * Called during device uninit.
 *
 * @param dev
 *   current device.
 * @param user_data
 *   user argument from dev_init() call.
 */
int rte_pmd_ark_bbdev_uninit(struct rte_bbdev *dev, void *user_data);

/**
 * Extension prototype, optional implementation.
 * Called during rte_bbdev_start().
 *
 * @param dev
 *   current device.
 * @param user_data
 *   user argument from dev_init() call.
 * @return (0) if successful.
 */
int rte_pmd_ark_bbdev_start(struct rte_bbdev *dev, void *user_data);

/**
 * Extension prototype, optional implementation.
 * Called during  rte_bbdev_stop().
 *
 * @param dev
 *   current device.
 * @param user_data
 *   user argument from dev_init() call.
 * @return (0) if successful.
 */
int rte_pmd_ark_bbdev_stop(struct rte_bbdev *dev, void *user_data);

/**
 * Extension prototype, optional implementation.
 * Called during rte_bbdev_dequeue_ldpc_dec_ops
 *
 * @param dev
 *   current device.
 * @param user_data
 *   user argument from dev_init() call.
 * @return (0) if successful.
 */
int rte_pmd_ark_bbdev_dequeue_ldpc_dec(struct rte_bbdev *dev,
				  struct rte_bbdev_dec_op *this_op,
				  uint32_t *usermeta,
				  void *user_data);

/**
 * Extension prototype, optional implementation.
 * Called during rte_bbdev_dequeue_ldpc_enc_ops
 *
 * @param dev
 *   current device.
 * @param user_data
 *   user argument from dev_init() call.
 * @return (0) if successful.
 */
int rte_pmd_ark_bbdev_dequeue_ldpc_enc(struct rte_bbdev *dev,
				  struct rte_bbdev_enc_op *this_op,
				  uint32_t *usermeta,
				  void *user_data);

/**
 * Extension prototype, optional implementation.
 * Called during rte_bbdev_enqueue_ldpc_dec_ops
 *
 * @param dev
 *   current device.
 * @param user_data
 *   user argument from dev_init() call.
 * @return (0) if successful.
 */
int rte_pmd_ark_bbdev_enqueue_ldpc_dec(struct rte_bbdev *dev,
					struct rte_bbdev_dec_op *this_op,
					uint32_t *usermeta,
					uint8_t *meta_cnt,
					void *user_data);

/**
 * Extension prototype, optional implementation.
 * Called during rte_bbdev_enqueue_ldpc_enc_ops
 *
 * @param dev
 *   current device.
 * @param user_data
 *   user argument from dev_init() call.
 * @return (0) if successful.
 */
int rte_pmd_ark_bbdev_enqueue_ldpc_enc(struct rte_bbdev *dev,
					struct rte_bbdev_enc_op *this_op,
					uint32_t *usermeta,
					uint8_t *meta_cnt,
					void *user_data);


struct arkbb_user_ext {
	void *(*dev_init)(struct rte_bbdev *dev, void *abar);
	int (*dev_uninit)(struct rte_bbdev *dev, void *udata);
	int (*dev_start)(struct rte_bbdev *dev, void *udata);
	int (*dev_stop)(struct rte_bbdev *dev, void *udata);
	int (*dequeue_ldpc_dec)(struct rte_bbdev *dev,
				 struct rte_bbdev_dec_op *op,
				 uint32_t *v,
				 void *udata);
	int (*dequeue_ldpc_enc)(struct rte_bbdev *dev,
				 struct rte_bbdev_enc_op *op,
				 uint32_t *v,
				 void *udata);
	int (*enqueue_ldpc_dec)(struct rte_bbdev *dev,
				 struct rte_bbdev_dec_op *op,
				 uint32_t *v,
				 uint8_t *v1,
				 void *udata);
	int (*enqueue_ldpc_enc)(struct rte_bbdev *dev,
				 struct rte_bbdev_enc_op *op,
				 uint32_t *v,
				 uint8_t *v1,
				 void *udata);
};





#endif

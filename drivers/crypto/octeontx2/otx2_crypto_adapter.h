/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell International Ltd.
 */

#ifndef _OTX2_CRYPTO_ADAPTER_H_
#define _OTX2_CRYPTO_ADAPTER_H_

__rte_internal
int otx2_ca_caps_get(const struct rte_eventdev *dev,
		const struct rte_cryptodev *cdev, uint32_t *caps);

__rte_internal
int otx2_ca_qp_add(const struct rte_eventdev *dev,
		const struct rte_cryptodev *cdev, int32_t queue_pair_id,
		const struct rte_event *event);

__rte_internal
int otx2_ca_qp_del(const struct rte_eventdev *dev,
		const struct rte_cryptodev *cdev, int32_t queue_pair_id);

#endif /* _OTX2_CRYPTO_ADAPTER_H_ */

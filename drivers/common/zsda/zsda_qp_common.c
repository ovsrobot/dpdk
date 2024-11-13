/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include "zsda_qp_common.h"

static void
zsda_queue_delete(const struct zsda_queue *queue)
{
	const struct rte_memzone *mz;

	if (queue == NULL) {
		ZSDA_LOG(DEBUG, "Invalid queue");
		return;
	}

	mz = rte_memzone_lookup(queue->memz_name);
	if (mz != NULL) {
		memset(queue->base_addr, 0x0,
		       (uint16_t)(queue->queue_size * queue->msg_size));
		rte_memzone_free(mz);
	} else
		ZSDA_LOG(DEBUG, "queue %s doesn't exist", queue->memz_name);
}

int
zsda_queue_pair_release(struct zsda_qp **qp_addr)
{
	struct zsda_qp *qp = *qp_addr;
	uint32_t i;
	enum zsda_service_type type;

	if (qp == NULL) {
		ZSDA_LOG(DEBUG, "qp already freed");
		return 0;
	}

	for (type = 0; type < ZSDA_SERVICE_INVALID; type++) {
		if (!qp->srv[type].used)
			continue;

		zsda_queue_delete(&(qp->srv[type].tx_q));
		zsda_queue_delete(&(qp->srv[type].rx_q));
		qp->srv[type].used = false;
		for (i = 0; i < qp->srv[type].nb_descriptors; i++)
			rte_mempool_put(qp->srv[type].op_cookie_pool,
					qp->srv[type].op_cookies[i]);

		rte_mempool_free(qp->srv[type].op_cookie_pool);
		rte_free(qp->srv[type].op_cookies);
	}

	rte_free(qp);
	*qp_addr = NULL;

	return ZSDA_SUCCESS;
}

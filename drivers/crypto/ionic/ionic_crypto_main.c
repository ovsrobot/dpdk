/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2024 Advanced Micro Devices, Inc.
 */

#include <inttypes.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_bitops.h>

#include "ionic_crypto.h"

int iocpt_logtype;

uint32_t
iocpt_cq_service(struct iocpt_cq *cq, uint32_t work_to_do,
		 iocpt_cq_cb cb, void *cb_arg)
{
	uint32_t work_done = 0;

	if (work_to_do == 0)
		return 0;

	while (cb(cq, cq->tail_idx, cb_arg)) {
		cq->tail_idx = Q_NEXT_TO_SRVC(cq, 1);
		if (cq->tail_idx == 0)
			cq->done_color = !cq->done_color;

		if (++work_done == work_to_do)
			break;
	}

	return work_done;
}

struct ionic_doorbell *
iocpt_db_map(struct iocpt_dev *dev, struct iocpt_queue *q)
{
	return dev->db_pages + q->hw_type;
}

RTE_LOG_REGISTER_DEFAULT(iocpt_logtype, NOTICE);

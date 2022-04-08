/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Ericsson AB
 */

#include <rte_seqlock.h>

void
rte_seqlock_init(rte_seqlock_t *seqlock)
{
	seqlock->sn = 0;
	rte_spinlock_init(&seqlock->lock);
}

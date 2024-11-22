/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Intel Corporation
 */

#ifndef IETH_RXTX_H_
#define IETH_RXTX_H_

#include <stdint.h>
#include <rte_mbuf.h>

/**
 * Structure associated with each descriptor of the TX ring of a TX queue.
 */
struct ieth_tx_entry
{
	struct rte_mbuf *mbuf; /* mbuf associated with TX desc, if any. */
	uint16_t next_id; /* Index of next descriptor in ring. */
	uint16_t last_id; /* Index of last scattered descriptor. */
};

/**
 * Structure associated with each descriptor of the TX ring of a TX queue in vector Tx.
 */
struct ieth_vec_tx_entry
{
	struct rte_mbuf *mbuf; /* mbuf associated with TX desc, if any. */
};

#endif /* IETH_RXTX_H_ */

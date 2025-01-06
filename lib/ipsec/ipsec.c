/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Intel Corporation
 */

#include "rte_ipsec.h"

uint16_t
rte_ipsec_pkt_crypto_prepare(const struct rte_ipsec_session *ss,
	struct rte_mbuf *mb[], struct rte_crypto_op *cop[], uint16_t num)
{
	return ss->pkt_func.prepare.async(ss, mb, cop, num);
}

uint16_t
rte_ipsec_pkt_process(const struct rte_ipsec_session *ss, struct rte_mbuf *mb[],
	uint16_t num)
{
	return ss->pkt_func.process(ss, mb, num);
}

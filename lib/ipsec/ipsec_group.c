/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_security.h>

#include "rte_ipsec_group.h"

uint16_t
rte_ipsec_pkt_crypto_group(const struct rte_crypto_op *cop[],
	struct rte_mbuf *mb[], struct rte_ipsec_group grp[], uint16_t num)
{
	uint32_t i, j, k, n;
	void *ns, *ps;
	struct rte_mbuf *m, **dr;

	j = 0;
	k = 0;
	n = 0;
	ps = NULL;
	dr = alloca(sizeof(struct rte_mbuf *) * num);

	for (i = 0; i != num; i++) {

		m = cop[i]->sym[0].m_src;
		ns = cop[i]->sym[0].session;

		m->ol_flags |= RTE_MBUF_F_RX_SEC_OFFLOAD;
		if (cop[i]->status != RTE_CRYPTO_OP_STATUS_SUCCESS)
			m->ol_flags |= RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED;

		/* no valid session found */
		if (ns == NULL) {
			dr[k++] = m;
			continue;
		}

		/* different SA */
		if (ps != ns) {

			/*
			 * we already have an open group - finalize it,
			 * then open a new one.
			 */
			if (ps != NULL) {
				grp[n].id.ptr =
					rte_ipsec_ses_from_crypto(cop[i - 1]);
				grp[n].cnt = mb + j - grp[n].m;
				n++;
			}

			/* start new group */
			grp[n].m = mb + j;
			ps = ns;
		}

		mb[j++] = m;
	}

	/* finalise last group */
	if (ps != NULL) {
		grp[n].id.ptr = rte_ipsec_ses_from_crypto(cop[i - 1]);
		grp[n].cnt = mb + j - grp[n].m;
		n++;
	}

	/* copy mbufs with unknown session beyond recognised ones */
	if (k != 0 && k != num) {
		for (i = 0; i != k; i++)
			mb[j + i] = dr[i];
	}

	return n;
}

struct rte_ipsec_session *
rte_ipsec_ses_from_crypto(const struct rte_crypto_op *cop)
{
	void *ses;

	if (cop->sess_type == RTE_CRYPTO_OP_SECURITY_SESSION) {
		ses = cop->sym[0].session;
		return (struct rte_ipsec_session *)(uintptr_t)
			rte_security_session_opaque_data_get(ses);
	} else if (cop->sess_type == RTE_CRYPTO_OP_WITH_SESSION) {
		ses = cop->sym[0].session;
		return (struct rte_ipsec_session *)(uintptr_t)
			rte_cryptodev_sym_session_opaque_data_get(ses);
	}
	return NULL;
}

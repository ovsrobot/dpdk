/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * Capture filters.  The client compiles the filter, so it arrives as
 * cBPF and has to be converted to the DPDK form that pdump takes.
 */

#include <stdlib.h>

#include <pcap/pcap.h>

#include <rte_bpf.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_pdump.h>

#include "rpcap-protocol.h"
#include "rpcapd.h"

#define MAX_FILTER_INSNS              4096

/*
 * Read the optional capture filter that follows a start-capture request,
 * and convert it for pdump. Client passes cBPF.
 */
int
read_filter(const struct conn *c, uint32_t plen, struct session *s)
{
	struct rpcap_filterbpf_insn winsn;
	struct rpcap_filter filter;
	struct bpf_program bf;
	struct bpf_insn *insns;
	uint32_t i, nitems;

	if (plen == 0)
		return 0;		/* no filter: capture everything */

	if (plen < sizeof(filter)) {
		if (rpcap_discard(c, plen) < 0)
			return -1;
		return rpcap_send_error(c, 0, "short filter header") < 0 ? -1 : 1;
	}

	if (recv_full(c, &filter, sizeof(filter)) < 0)
		return -1;
	plen -= sizeof(filter);

	if (rte_be_to_cpu_16(filter.filtertype) != RPCAP_UPDATEFILTER_BPF) {
		if (rpcap_discard(c, plen) < 0)
			return -1;
		return rpcap_send_error(c, 0, "unsupported filter type") < 0 ? -1 : 1;
	}

	/* nitems is client-supplied; bound it before trusting the length. */
	nitems = rte_be_to_cpu_32(filter.nitems);
	if (nitems == 0)
		return rpcap_discard(c, plen) < 0 ? -1 : 0;

	if (nitems > MAX_FILTER_INSNS || plen < nitems * sizeof(winsn)) {
		if (rpcap_discard(c, plen) < 0)
			return -1;
		return rpcap_send_error(c, 0, "bad filter length") < 0 ? -1 : 1;
	}

	insns = calloc(nitems, sizeof(*insns));
	if (insns == NULL) {
		if (rpcap_discard(c, plen) < 0)
			return -1;
		return rpcap_send_error(c, 0, "out of memory") < 0 ? -1 : 1;
	}

	for (i = 0; i < nitems; i++) {
		if (recv_full(c, &winsn, sizeof(winsn)) < 0) {
			free(insns);
			return -1;
		}
		insns[i].code = rte_be_to_cpu_16(winsn.code);
		insns[i].jt   = winsn.jt;
		insns[i].jf   = winsn.jf;
		insns[i].k    = rte_be_to_cpu_32(winsn.k);
	}
	plen -= nitems * sizeof(winsn);

	/* Anything after the instructions is padding we do not need. */
	if (rpcap_discard(c, plen) < 0) {
		free(insns);
		return -1;
	}

	bf.bf_len = nitems;
	bf.bf_insns = insns;

	/* Reject a malformed program here */
	if (!bpf_validate(bf.bf_insns, bf.bf_len)) {
		free(insns);
		return rpcap_send_error(c, 0, "invalid filter program") < 0 ? -1 : 1;
	}

	/* A filter recorded by an earlier UPDATEFILTER may still be here */
	rte_free(s->prm);
	s->prm = rte_bpf_convert(&bf);
	free(insns);
	if (s->prm == NULL) {
		RPCAPD_LOG(ERR, "rte_bpf_convert failed: %s",
			rte_strerror(rte_errno));
		return rpcap_send_error(c, 0, "cannot convert filter") < 0 ? -1 : 1;
	}

	RPCAPD_LOG(DEBUG, "capture filter: %u instructions", nitems);
	return 0;
}

/*
 * UPDATEFILTER_REQ: replace the capture filter.
 *
 * pdump takes its filter when the callback is setup.
 * To replace need to drop old callback and put in new one.
 * Packets already in the ring are kept.
 *
 * Before the capture starts this just records the filter for the
 * eventual STARTCAP.
 */
int
handle_updatefilter(const struct conn *c, uint32_t plen, struct session *s)
{
	struct rte_bpf_prm *old = s->prm;
	int ret;

	s->prm = NULL;
	ret = read_filter(c, plen, s);
	if (ret != 0) {
		/* Malformed request: keep running with the old filter. */
		rte_free(s->prm);
		s->prm = old;
		return ret < 0 ? -1 : 0;	/* error already reported */
	}

	if (!s->capture_on) {
		rte_free(old);
		return rpcap_send_msg(c, RPCAP_MSG_UPDATEFILTER_REPLY, 0, NULL, 0);
	}

	rte_pdump_disable(s->port, RTE_PDUMP_ALL_QUEUES, s->pdump_flags);
	s->capture_on = false;

	if (rte_pdump_enable_bpf(s->port, RTE_PDUMP_ALL_QUEUES,
				 s->pdump_flags | RTE_PDUMP_FLAG_PCAPNG,
				 s->snaplen, s->ring, s->mp, s->prm) < 0) {
		RPCAPD_LOG(ERR, "rte_pdump_enable_bpf port %u failed: %s",
			s->port, rte_strerror(rte_errno));
		rte_free(old);
		/* The capture cannot be resumed */
		stop_capture(s);
		return rpcap_send_error(c, 0, "cannot apply filter");
	}
	s->capture_on = true;

	/* Safe now that the old program is no longer referenced. */
	rte_free(old);

	RPCAPD_LOG(DEBUG, "capture filter updated on %s", s->name);
	return rpcap_send_msg(c, RPCAP_MSG_UPDATEFILTER_REPLY, 0, NULL, 0);
}

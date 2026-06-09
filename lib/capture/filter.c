/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <pcap/pcap.h>

#include <rte_bpf.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "capture_impl.h"

struct rte_capture_filter {
	struct rte_bpf *bpf;
	struct rte_bpf_jit jit;
	char expr[];	/* original filter text */
};

/*
 * Convert text string into an eBPF program
 */
struct rte_capture_filter *
__rte_capture_filter_create(const char *filter)
{
	struct rte_capture_filter *flt = NULL;
	struct rte_bpf_prm *prm = NULL;

	/* libpcap needs a handle */
	pcap_t *pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);
	if (!pcap) {
		CAPTURE_LOG(ERR, "pcap: can not open handle");
		return NULL;
	}

	flt = rte_zmalloc("capture_filter", sizeof(*flt) + strlen(filter) + 1, 0);
	if (flt == NULL) {
		CAPTURE_LOG(ERR, "capture filter alloc failed");
		goto error;
	}

	/* convert string to cBPF program */
	struct bpf_program bf;
	if (pcap_compile(pcap, &bf, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
		CAPTURE_LOG(ERR, "pcap: can not compile filter: %s",
			    pcap_geterr(pcap));
		goto error;
	}
	strcpy(flt->expr, filter);

	/* convert cBPF to eBPF */
	prm = rte_bpf_convert(&bf);
	pcap_freecode(&bf); /* drop the cBPF program */

	if (prm == NULL)  {
		CAPTURE_LOG(ERR, "BPF convert interface %s(%d)",
			    rte_strerror(rte_errno), rte_errno);
		goto error;
	}

	flt->bpf = rte_bpf_load(prm);
	if (flt->bpf == NULL) {
		CAPTURE_LOG(ERR, "BPF load failed: %s(%d)",
			    rte_strerror(rte_errno), rte_errno);
		goto error;
	}

	rte_bpf_get_jit(flt->bpf, &flt->jit);
	if (flt->jit.func == NULL)
		CAPTURE_LOG(NOTICE, "No JIT available for filter");

	pcap_close(pcap);
	rte_free(prm);
	return flt;

error:
	pcap_close(pcap);
	rte_free(prm);
	rte_free(flt);
	return NULL;
}

const char *__rte_capture_filter_string(struct rte_capture_filter *filter)
{
	return filter ? filter->expr : NULL;
}

void __rte_capture_filter_free(struct rte_capture_filter *filter)
{
	if (filter == NULL)
		return;

	rte_bpf_destroy(filter->bpf);
	rte_free(filter);
}

uint64_t __rte_capture_filter(const struct rte_capture_filter *filter, struct rte_mbuf *mb)
{
	if (filter->jit.func)
		return filter->jit.func(mb);
	else
		return rte_bpf_exec(filter->bpf, mb);
}

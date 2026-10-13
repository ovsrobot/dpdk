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
#include <rte_string_fns.h>

#include "private.h"

/*
 * Compiled filter, split in two because of where rte_bpf puts things.
 * rte_bpf_convert() returns the eBPF instructions in rte_malloc memory, which
 * is shared and position independent and references no external symbols.
 * rte_bpf_load() puts the rte_bpf object in a MAP_PRIVATE mapping and the JIT
 * output has to be privately executable, so neither can be shared.
 *
 * The instructions are therefore compiled once, by whoever starts the
 * capture, and each process loads its own program from them. Only the process
 * doing the compile needs libpcap.
 */
struct rte_capture_filter {
	struct ebpf_insn *ins;	/* eBPF program, shared */
	uint32_t nb_ins;
	char expr[];		/* original filter text */
};

/* Per-process loaded form of the above, not shared. */
struct capture_filter_prog {
	struct rte_bpf *bpf;
	struct rte_bpf_jit jit;
};

/*
 * Convert text string into an eBPF program
 */
struct rte_capture_filter *
__rte_capture_filter_create(const char *filter)
{
	struct rte_bpf_prm *prm = NULL;

	/* libpcap needs a handle */
	pcap_t *pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);
	if (!pcap) {
		CAPTURE_LOG(ERR, "pcap: can not open handle");
		return NULL;
	}

	size_t filter_len = strlen(filter) + 1;
	struct rte_capture_filter *flt;
	flt = rte_zmalloc("capture_filter", sizeof(*flt) + filter_len, 0);
	if (flt == NULL) {
		CAPTURE_LOG(ERR, "could not allocate for filter");
		goto error;
	}

	/* convert string to cBPF program */
	struct bpf_program bf;
	if (pcap_compile(pcap, &bf, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
		CAPTURE_LOG(ERR, "pcap: can not compile filter: %s",
			    pcap_geterr(pcap));
		goto error;
	}
	strlcpy(flt->expr, filter, filter_len);

	/* convert cBPF to eBPF */
	prm = rte_bpf_convert(&bf);
	pcap_freecode(&bf); /* drop the cBPF program */

	if (prm == NULL)  {
		CAPTURE_LOG(ERR, "BPF convert interface %s(%d)",
			    rte_strerror(rte_errno), rte_errno);
		goto error;
	}

	/*
	 * Keep the instructions in shared memory. Only the primary has libpcap
	 * do the compile; every process loads the result from here.
	 */
	flt->ins = rte_malloc("capture_filter_ins",
			      prm->nb_ins * sizeof(*flt->ins), 0);
	if (flt->ins == NULL) {
		CAPTURE_LOG(ERR, "could not allocate for filter program");
		goto error;
	}
	memcpy(flt->ins, prm->ins, prm->nb_ins * sizeof(*flt->ins));
	flt->nb_ins = prm->nb_ins;

	pcap_close(pcap);
	rte_free(prm);
	return flt;

error:
	pcap_close(pcap);
	rte_free(prm);
	if (flt != NULL)
		rte_free(flt->ins);
	rte_free(flt);
	return NULL;
}

/*
 * Load the shared program into this process. The JIT-ed code and the rte_bpf
 * object are process private mappings, so each process that runs the filter
 * needs its own.
 */
struct capture_filter_prog *
__rte_capture_filter_load(const struct rte_capture_filter *filter)
{
	struct rte_bpf_prm prm = {
		.ins = filter->ins,
		.nb_ins = filter->nb_ins,
		.prog_arg = {
			.type = RTE_BPF_ARG_PTR_MBUF,
			.size = sizeof(struct rte_mbuf),
		},
	};
	struct capture_filter_prog *prog;

	prog = calloc(1, sizeof(*prog));
	if (prog == NULL) {
		CAPTURE_LOG(ERR, "could not allocate filter program");
		return NULL;
	}

	prog->bpf = rte_bpf_load(&prm);
	if (prog->bpf == NULL) {
		CAPTURE_LOG(ERR, "BPF load failed: %s(%d)",
			    rte_strerror(rte_errno), rte_errno);
		free(prog);
		return NULL;
	}

	rte_bpf_get_jit(prog->bpf, &prog->jit);
	if (prog->jit.func == NULL)
		CAPTURE_LOG(NOTICE, "No JIT available for filter");

	return prog;
}

void
__rte_capture_filter_unload(struct capture_filter_prog *prog)
{
	if (prog == NULL)
		return;

	rte_bpf_destroy(prog->bpf);
	free(prog);
}

const char *__rte_capture_filter_string(struct rte_capture_filter *filter)
{
	return filter ? filter->expr : NULL;
}

void __rte_capture_filter_free(struct rte_capture_filter *filter)
{
	if (filter == NULL)
		return;

	rte_free(filter->ins);
	rte_free(filter);
}

uint64_t __rte_capture_filter(const struct capture_filter_prog *prog, struct rte_mbuf *mb)
{
	if (prog->jit.func)
		return prog->jit.func(mb);
	else
		return rte_bpf_exec(prog->bpf, mb);
}

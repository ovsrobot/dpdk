/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef __CN10K_WORKER_H__
#define __CN10K_WORKER_H__

#include "cnxk_ethdev.h"
#include "cnxk_eventdev.h"
#include "cnxk_worker.h"

#include "cn10k_ethdev.h"
#include "cn10k_rx.h"

/* SSO Operations */

static __rte_always_inline uint8_t
cn10k_sso_hws_new_event(struct cn10k_sso_hws *ws, const struct rte_event *ev)
{
	const uint32_t tag = (uint32_t)ev->event;
	const uint8_t new_tt = ev->sched_type;
	const uint64_t event_ptr = ev->u64;
	const uint16_t grp = ev->queue_id;

	rte_atomic_thread_fence(__ATOMIC_ACQ_REL);
	if (ws->xaq_lmt <= *ws->fc_mem)
		return 0;

	cnxk_sso_hws_add_work(event_ptr, tag, new_tt, ws->grps_base[grp]);
	return 1;
}

static __rte_always_inline void
cn10k_sso_hws_fwd_swtag(struct cn10k_sso_hws *ws, const struct rte_event *ev)
{
	const uint32_t tag = (uint32_t)ev->event;
	const uint8_t new_tt = ev->sched_type;
	const uint8_t cur_tt = CNXK_TT_FROM_TAG(plt_read64(ws->tag_wqe_op));

	/* CNXK model
	 * cur_tt/new_tt     SSO_TT_ORDERED SSO_TT_ATOMIC SSO_TT_UNTAGGED
	 *
	 * SSO_TT_ORDERED        norm           norm             untag
	 * SSO_TT_ATOMIC         norm           norm		   untag
	 * SSO_TT_UNTAGGED       norm           norm             NOOP
	 */

	if (new_tt == SSO_TT_UNTAGGED) {
		if (cur_tt != SSO_TT_UNTAGGED)
			cnxk_sso_hws_swtag_untag(ws->swtag_untag_op);
	} else {
		cnxk_sso_hws_swtag_norm(tag, new_tt, ws->swtag_norm_op);
	}
	ws->swtag_req = 1;
}

static __rte_always_inline void
cn10k_sso_hws_fwd_group(struct cn10k_sso_hws *ws, const struct rte_event *ev,
			const uint16_t grp)
{
	const uint32_t tag = (uint32_t)ev->event;
	const uint8_t new_tt = ev->sched_type;

	plt_write64(ev->u64, ws->updt_wqe_op);
	cnxk_sso_hws_swtag_desched(tag, new_tt, grp, ws->swtag_desched_op);
}

static __rte_always_inline void
cn10k_sso_hws_forward_event(struct cn10k_sso_hws *ws,
			    const struct rte_event *ev)
{
	const uint8_t grp = ev->queue_id;

	/* Group hasn't changed, Use SWTAG to forward the event */
	if (CNXK_GRP_FROM_TAG(plt_read64(ws->tag_wqe_op)) == grp)
		cn10k_sso_hws_fwd_swtag(ws, ev);
	else
		/*
		 * Group has been changed for group based work pipelining,
		 * Use deschedule/add_work operation to transfer the event to
		 * new group/core
		 */
		cn10k_sso_hws_fwd_group(ws, ev, grp);
}

static __rte_always_inline void
cn10k_wqe_to_mbuf(uint64_t wqe, const uint64_t mbuf, uint8_t port_id,
		  const uint32_t tag, const uint32_t flags,
		  const void *const lookup_mem)
{
	union mbuf_initializer mbuf_init = {
		.fields = {.data_off = RTE_PKTMBUF_HEADROOM,
			   .refcnt = 1,
			   .nb_segs = 1,
			   .port = port_id},
	};

	cn10k_nix_cqe_to_mbuf((struct nix_cqe_hdr_s *)wqe, tag,
			      (struct rte_mbuf *)mbuf, lookup_mem,
			      mbuf_init.value, flags);
}

static __rte_always_inline uint16_t
cn10k_sso_hws_get_work(struct cn10k_sso_hws *ws, struct rte_event *ev,
		       const uint32_t flags, void *lookup_mem)
{
	union {
		__uint128_t get_work;
		uint64_t u64[2];
	} gw;
	uint64_t mbuf;

	gw.get_work = ws->gw_wdata;
#if defined(RTE_ARCH_ARM64) && !defined(__clang__)
	asm volatile(
		PLT_CPU_FEATURE_PREAMBLE
		"caspl %[wdata], %H[wdata], %[wdata], %H[wdata], [%[gw_loc]]\n"
		"sub %[mbuf], %H[wdata], #0x80				\n"
		: [wdata] "+r"(gw.get_work), [mbuf] "=&r"(mbuf)
		: [gw_loc] "r"(ws->getwrk_op)
		: "memory");
#else
	plt_write64(gw.u64[0], ws->getwrk_op);
	do {
		roc_load_pair(gw.u64[0], gw.u64[1], ws->tag_wqe_op);
	} while (gw.u64[0] & BIT_ULL(63));
	mbuf = (uint64_t)((char *)gw.u64[1] - sizeof(struct rte_mbuf));
#endif
	gw.u64[0] = (gw.u64[0] & (0x3ull << 32)) << 6 |
		    (gw.u64[0] & (0x3FFull << 36)) << 4 |
		    (gw.u64[0] & 0xffffffff);

	if (CNXK_TT_FROM_EVENT(gw.u64[0]) != SSO_TT_EMPTY) {
		if (CNXK_EVENT_TYPE_FROM_TAG(gw.u64[0]) ==
		    RTE_EVENT_TYPE_ETHDEV) {
			uint8_t port = CNXK_SUB_EVENT_FROM_TAG(gw.u64[0]);

			gw.u64[0] = CNXK_CLR_SUB_EVENT(gw.u64[0]);
			cn10k_wqe_to_mbuf(gw.u64[1], mbuf, port,
					  gw.u64[0] & 0xFFFFF, flags,
					  lookup_mem);
			gw.u64[1] = mbuf;
		}
	}

	ev->event = gw.u64[0];
	ev->u64 = gw.u64[1];

	return !!gw.u64[1];
}

/* Used in cleaning up workslot. */
static __rte_always_inline uint16_t
cn10k_sso_hws_get_work_empty(struct cn10k_sso_hws *ws, struct rte_event *ev)
{
	union {
		__uint128_t get_work;
		uint64_t u64[2];
	} gw;
	uint64_t mbuf;

#ifdef RTE_ARCH_ARM64
	asm volatile(PLT_CPU_FEATURE_PREAMBLE
		     "		ldp %[tag], %[wqp], [%[tag_loc]]	\n"
		     "		tbz %[tag], 63, done%=			\n"
		     "		sevl					\n"
		     "rty%=:	wfe					\n"
		     "		ldp %[tag], %[wqp], [%[tag_loc]]	\n"
		     "		tbnz %[tag], 63, rty%=			\n"
		     "done%=:	dmb ld					\n"
		     "		sub %[mbuf], %[wqp], #0x80		\n"
		     : [tag] "=&r"(gw.u64[0]), [wqp] "=&r"(gw.u64[1]),
		       [mbuf] "=&r"(mbuf)
		     : [tag_loc] "r"(ws->tag_wqe_op)
		     : "memory");
#else
	do {
		roc_load_pair(gw.u64[0], gw.u64[1], ws->tag_wqe_op);
	} while (gw.u64[0] & BIT_ULL(63));
	mbuf = (uint64_t)((char *)gw.u64[1] - sizeof(struct rte_mbuf));
#endif

	gw.u64[0] = (gw.u64[0] & (0x3ull << 32)) << 6 |
		    (gw.u64[0] & (0x3FFull << 36)) << 4 |
		    (gw.u64[0] & 0xffffffff);

	if (CNXK_TT_FROM_EVENT(gw.u64[0]) != SSO_TT_EMPTY) {
		if (CNXK_EVENT_TYPE_FROM_TAG(gw.u64[0]) ==
		    RTE_EVENT_TYPE_ETHDEV) {
			uint8_t port = CNXK_SUB_EVENT_FROM_TAG(gw.u64[0]);

			gw.u64[0] = CNXK_CLR_SUB_EVENT(gw.u64[0]);
			cn10k_wqe_to_mbuf(gw.u64[1], mbuf, port,
					  gw.u64[0] & 0xFFFFF, 0, NULL);
			gw.u64[1] = mbuf;
		}
	}

	ev->event = gw.u64[0];
	ev->u64 = gw.u64[1];

	return !!gw.u64[1];
}

/* CN10K Fastpath functions. */
uint16_t __rte_hot cn10k_sso_hws_enq(void *port, const struct rte_event *ev);
uint16_t __rte_hot cn10k_sso_hws_enq_burst(void *port,
					   const struct rte_event ev[],
					   uint16_t nb_events);
uint16_t __rte_hot cn10k_sso_hws_enq_new_burst(void *port,
					       const struct rte_event ev[],
					       uint16_t nb_events);
uint16_t __rte_hot cn10k_sso_hws_enq_fwd_burst(void *port,
					       const struct rte_event ev[],
					       uint16_t nb_events);

#define R(name, f3, f2, f1, f0, flags)                                         \
	uint16_t __rte_hot cn10k_sso_hws_deq_##name(                           \
		void *port, struct rte_event *ev, uint64_t timeout_ticks);     \
	uint16_t __rte_hot cn10k_sso_hws_deq_burst_##name(                     \
		void *port, struct rte_event ev[], uint16_t nb_events,         \
		uint64_t timeout_ticks);                                       \
	uint16_t __rte_hot cn10k_sso_hws_tmo_deq_##name(                       \
		void *port, struct rte_event *ev, uint64_t timeout_ticks);     \
	uint16_t __rte_hot cn10k_sso_hws_tmo_deq_burst_##name(                 \
		void *port, struct rte_event ev[], uint16_t nb_events,         \
		uint64_t timeout_ticks);                                       \
	uint16_t __rte_hot cn10k_sso_hws_deq_seg_##name(                       \
		void *port, struct rte_event *ev, uint64_t timeout_ticks);     \
	uint16_t __rte_hot cn10k_sso_hws_deq_seg_burst_##name(                 \
		void *port, struct rte_event ev[], uint16_t nb_events,         \
		uint64_t timeout_ticks);                                       \
	uint16_t __rte_hot cn10k_sso_hws_tmo_deq_seg_##name(                   \
		void *port, struct rte_event *ev, uint64_t timeout_ticks);     \
	uint16_t __rte_hot cn10k_sso_hws_tmo_deq_seg_burst_##name(             \
		void *port, struct rte_event ev[], uint16_t nb_events,         \
		uint64_t timeout_ticks);

NIX_RX_FASTPATH_MODES
#undef R

#endif

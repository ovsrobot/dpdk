/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell International Ltd.
 */

#include "cn10k_worker.h"
#include "cnxk_eventdev.h"
#include "cnxk_worker.h"

uint16_t __rte_hot
cn10k_sso_hws_enq(void *port, const struct rte_event *ev)
{
	struct cn10k_sso_hws *ws = port;

	switch (ev->op) {
	case RTE_EVENT_OP_NEW:
		return cn10k_sso_hws_new_event(ws, ev);
	case RTE_EVENT_OP_FORWARD:
		cn10k_sso_hws_forward_event(ws, ev);
		break;
	case RTE_EVENT_OP_RELEASE:
		cnxk_sso_hws_swtag_flush(ws->tag_wqe_op, ws->swtag_flush_op);
		break;
	default:
		return 0;
	}

	return 1;
}

uint16_t __rte_hot
cn10k_sso_hws_enq_burst(void *port, const struct rte_event ev[],
			uint16_t nb_events)
{
	RTE_SET_USED(nb_events);
	return cn10k_sso_hws_enq(port, ev);
}

uint16_t __rte_hot
cn10k_sso_hws_enq_new_burst(void *port, const struct rte_event ev[],
			    uint16_t nb_events)
{
	struct cn10k_sso_hws *ws = port;
	uint16_t i, rc = 1;

	for (i = 0; i < nb_events && rc; i++)
		rc = cn10k_sso_hws_new_event(ws, &ev[i]);

	return nb_events;
}

uint16_t __rte_hot
cn10k_sso_hws_enq_fwd_burst(void *port, const struct rte_event ev[],
			    uint16_t nb_events)
{
	struct cn10k_sso_hws *ws = port;

	RTE_SET_USED(nb_events);
	cn10k_sso_hws_forward_event(ws, ev);

	return 1;
}

#define R(name, f3, f2, f1, f0, flags)                                         \
	uint16_t __rte_hot cn10k_sso_hws_deq_##name(                           \
		void *port, struct rte_event *ev, uint64_t timeout_ticks)      \
	{                                                                      \
		struct cn10k_sso_hws *ws = port;                               \
                                                                               \
		RTE_SET_USED(timeout_ticks);                                   \
                                                                               \
		if (ws->swtag_req) {                                           \
			ws->swtag_req = 0;                                     \
			cnxk_sso_hws_swtag_wait(ws->tag_wqe_op);               \
			return 1;                                              \
		}                                                              \
                                                                               \
		return cn10k_sso_hws_get_work(ws, ev, flags, ws->lookup_mem);  \
	}                                                                      \
                                                                               \
	uint16_t __rte_hot cn10k_sso_hws_deq_burst_##name(                     \
		void *port, struct rte_event ev[], uint16_t nb_events,         \
		uint64_t timeout_ticks)                                        \
	{                                                                      \
		RTE_SET_USED(nb_events);                                       \
                                                                               \
		return cn10k_sso_hws_deq_##name(port, ev, timeout_ticks);      \
	}                                                                      \
                                                                               \
	uint16_t __rte_hot cn10k_sso_hws_tmo_deq_##name(                       \
		void *port, struct rte_event *ev, uint64_t timeout_ticks)      \
	{                                                                      \
		struct cn10k_sso_hws *ws = port;                               \
		uint16_t ret = 1;                                              \
		uint64_t iter;                                                 \
                                                                               \
		if (ws->swtag_req) {                                           \
			ws->swtag_req = 0;                                     \
			cnxk_sso_hws_swtag_wait(ws->tag_wqe_op);               \
			return ret;                                            \
		}                                                              \
                                                                               \
		ret = cn10k_sso_hws_get_work(ws, ev, flags, ws->lookup_mem);   \
		for (iter = 1; iter < timeout_ticks && (ret == 0); iter++)     \
			ret = cn10k_sso_hws_get_work(ws, ev, flags,            \
						     ws->lookup_mem);          \
                                                                               \
		return ret;                                                    \
	}                                                                      \
                                                                               \
	uint16_t __rte_hot cn10k_sso_hws_tmo_deq_burst_##name(                 \
		void *port, struct rte_event ev[], uint16_t nb_events,         \
		uint64_t timeout_ticks)                                        \
	{                                                                      \
		RTE_SET_USED(nb_events);                                       \
                                                                               \
		return cn10k_sso_hws_tmo_deq_##name(port, ev, timeout_ticks);  \
	}                                                                      \
                                                                               \
	uint16_t __rte_hot cn10k_sso_hws_deq_seg_##name(                       \
		void *port, struct rte_event *ev, uint64_t timeout_ticks)      \
	{                                                                      \
		struct cn10k_sso_hws *ws = port;                               \
                                                                               \
		RTE_SET_USED(timeout_ticks);                                   \
                                                                               \
		if (ws->swtag_req) {                                           \
			ws->swtag_req = 0;                                     \
			cnxk_sso_hws_swtag_wait(ws->tag_wqe_op);               \
			return 1;                                              \
		}                                                              \
                                                                               \
		return cn10k_sso_hws_get_work(                                 \
			ws, ev, flags | NIX_RX_MULTI_SEG_F, ws->lookup_mem);   \
	}                                                                      \
                                                                               \
	uint16_t __rte_hot cn10k_sso_hws_deq_seg_burst_##name(                 \
		void *port, struct rte_event ev[], uint16_t nb_events,         \
		uint64_t timeout_ticks)                                        \
	{                                                                      \
		RTE_SET_USED(nb_events);                                       \
                                                                               \
		return cn10k_sso_hws_deq_seg_##name(port, ev, timeout_ticks);  \
	}                                                                      \
                                                                               \
	uint16_t __rte_hot cn10k_sso_hws_tmo_deq_seg_##name(                   \
		void *port, struct rte_event *ev, uint64_t timeout_ticks)      \
	{                                                                      \
		struct cn10k_sso_hws *ws = port;                               \
		uint16_t ret = 1;                                              \
		uint64_t iter;                                                 \
                                                                               \
		if (ws->swtag_req) {                                           \
			ws->swtag_req = 0;                                     \
			cnxk_sso_hws_swtag_wait(ws->tag_wqe_op);               \
			return ret;                                            \
		}                                                              \
                                                                               \
		ret = cn10k_sso_hws_get_work(ws, ev, flags, ws->lookup_mem);   \
		for (iter = 1; iter < timeout_ticks && (ret == 0); iter++)     \
			ret = cn10k_sso_hws_get_work(ws, ev, flags,            \
						     ws->lookup_mem);          \
                                                                               \
		return ret;                                                    \
	}                                                                      \
                                                                               \
	uint16_t __rte_hot cn10k_sso_hws_tmo_deq_seg_burst_##name(             \
		void *port, struct rte_event ev[], uint16_t nb_events,         \
		uint64_t timeout_ticks)                                        \
	{                                                                      \
		RTE_SET_USED(nb_events);                                       \
                                                                               \
		return cn10k_sso_hws_tmo_deq_seg_##name(port, ev,              \
							timeout_ticks);        \
	}

NIX_RX_FASTPATH_MODES
#undef R

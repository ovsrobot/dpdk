#include "l3fwd_event.h"

/* One eventdev loop for single and burst using acl. */
static __rte_always_inline void
acl_event_loop(struct l3fwd_event_resources *evt_rsrc,
		const uint8_t flags)
{
	uint32_t i, lcore_id, nb_deq, nb_enq;
	int32_t socketid;
	uint16_t hops[MAX_PKT_BURST];
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	struct rte_event events[MAX_PKT_BURST];

	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[
			evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	const uint16_t deq_len = RTE_MIN(evt_rsrc->deq_depth, MAX_PKT_BURST);

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();
	socketid = rte_lcore_to_socket_id(lcore_id);

	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);

	nb_deq = 0;
	nb_enq = 0;

	while (!force_quit) {
		/* Read events from RX queues. */
		nb_deq = rte_event_dequeue_burst(event_d_id, event_p_id,
				events, deq_len, 0);
		if (nb_deq == 0) {
			rte_pause();
			continue;
		}

		for (i = 0; i != nb_deq; i++) {
			pkts[i] = events[i].mbuf;
			if (flags & L3FWD_EVENT_TX_ENQ) {
				events[i].queue_id = tx_q_id;
				events[i].op = RTE_EVENT_OP_FORWARD;
			}
			rte_event_eth_tx_adapter_txq_set(pkts[i], 0);
		}

		acl_process_pkts(pkts, hops, nb_deq, socketid);

		for (i = 0; i != nb_deq; i++) {
			process_packet(pkts[i], &hops[i]);
			pkts[i]->port = (hops[i] != BAD_PORT) ?
				       hops[i] : pkts[i]->port;
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			nb_enq = rte_event_enqueue_burst(event_d_id, event_p_id,
					events, nb_deq);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_enqueue_burst(event_d_id,
						event_p_id, events + nb_enq,
						nb_deq - nb_enq);
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			nb_enq = rte_event_eth_tx_adapter_enqueue(event_d_id,
					event_p_id, events, nb_deq, 0);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_eth_tx_adapter_enqueue(
						event_d_id, event_p_id,
						events + nb_enq,
						nb_deq - nb_enq, 0);
		}
	}

	l3fwd_event_worker_cleanup(event_d_id, event_p_id, events, nb_enq,
				   nb_deq, 0);
}

int __rte_noinline
acl_event_main_loop_tx_d(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
			l3fwd_get_eventdev_rsrc();

	acl_event_loop(evt_rsrc, L3FWD_EVENT_TX_DIRECT);
	return 0;
}

int __rte_noinline
acl_event_main_loop_tx_d_burst(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
			l3fwd_get_eventdev_rsrc();

	acl_event_loop(evt_rsrc, L3FWD_EVENT_TX_DIRECT);
	return 0;
}

int __rte_noinline
acl_event_main_loop_tx_q(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
			l3fwd_get_eventdev_rsrc();

	acl_event_loop(evt_rsrc, L3FWD_EVENT_TX_ENQ);
	return 0;
}

int __rte_noinline
acl_event_main_loop_tx_q_burst(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
			l3fwd_get_eventdev_rsrc();

	acl_event_loop(evt_rsrc, L3FWD_EVENT_TX_ENQ);
	return 0;
}

static __rte_always_inline void
acl_process_event_vector(struct rte_event_vector *vec, uint16_t *hops,
	int32_t socketid)
{
	uint32_t i, k;

	for (i = 0; i != vec->nb_elem; i += k) {
		k = RTE_MIN(vec->nb_elem - i, (uint32_t)MAX_PKT_BURST);
		acl_process_pkts(vec->mbufs + i, hops + i, k, socketid);
	}

#if defined ACL_SEND_MULTI
	k = RTE_ALIGN_FLOOR(vec->nb_elem, FWDSTEP);

	for (i = 0; i != k; i += FWDSTEP)
		processx4_step3(&vec->mbufs[i], &hops[i]);
	for (; i < vec->nb_elem; i++)
		process_packet(vec->mbufs[i], &hops[i]);
#else
	for (i = 0; i < vec->nb_elem; i++)
		process_packet(vec->mbufs[i], &hops[i]);
#endif

	process_event_vector(vec, hops);
}

static __rte_always_inline void
acl_event_loop_vector(struct l3fwd_event_resources *evt_rsrc,
		      const uint8_t flags)
{
	uint16_t *hops;
	int32_t socketid;
	uint32_t i, lcore_id, nb_deq, nb_enq;
	struct rte_event events[MAX_PKT_BURST];

	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id =
		evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	const uint16_t deq_len = evt_rsrc->deq_depth;

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();
	socketid = rte_lcore_to_socket_id(lcore_id);

	hops = rte_zmalloc_socket(NULL, sizeof(hops[0]) * evt_rsrc->vector_size,
			RTE_CACHE_LINE_SIZE, socketid);
	if (hops == NULL) {
		RTE_LOG(ERR, L3FWD,
			"%s: failed to alloc internal buffers on lcore %u\n",
			__func__, lcore_id);
		return;
	}

	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);

	nb_deq = 0;
	nb_enq = 0;

	while (!force_quit) {
		/* Read events from RX queues. */
		nb_deq = rte_event_dequeue_burst(event_d_id, event_p_id, events,
						 deq_len, 0);
		if (nb_deq == 0) {
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_deq; i++) {
			if (flags & L3FWD_EVENT_TX_ENQ) {
				events[i].queue_id = tx_q_id;
				events[i].op = RTE_EVENT_OP_FORWARD;
			}

			acl_process_event_vector(events[i].vec, hops, socketid);
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			nb_enq = rte_event_enqueue_burst(event_d_id, event_p_id,
							 events, nb_deq);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_enqueue_burst(
					event_d_id, event_p_id, events + nb_enq,
					nb_deq - nb_enq);
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			nb_enq = rte_event_eth_tx_adapter_enqueue(
				event_d_id, event_p_id, events, nb_deq, 0);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_eth_tx_adapter_enqueue(
					event_d_id, event_p_id, events + nb_enq,
					nb_deq - nb_enq, 0);
		}
	}

	l3fwd_event_worker_cleanup(event_d_id, event_p_id, events, nb_enq,
				   nb_deq, 1);
	rte_free(hops);
}

int __rte_noinline
acl_event_main_loop_tx_d_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	acl_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_DIRECT);
	return 0;
}

int __rte_noinline
acl_event_main_loop_tx_d_burst_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	acl_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_DIRECT);
	return 0;
}

int __rte_noinline
acl_event_main_loop_tx_q_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	acl_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_ENQ);
	return 0;
}

int __rte_noinline
acl_event_main_loop_tx_q_burst_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	acl_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_ENQ);
	return 0;
}

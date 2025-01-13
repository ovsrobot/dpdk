#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <rte_lcore_var.h>

#include "rte_common.h"
#include "test_order_common.h"

#define IDLE_TIMEOUT 1
#define NB_QUEUES 2

static rte_spinlock_t *atomic_locks;

struct event_data {
	union {
		struct {
			uint32_t flow;
			uint32_t seq;
		};
		uint64_t raw;
	};
};

static inline uint64_t
event_data_create(flow_id_t flow, uint32_t seq)
{
	struct event_data data = {.flow = flow, .seq = seq};
	return data.raw;
}

static inline uint32_t
event_data_get_seq(struct rte_event *const ev)
{
	struct event_data data = {.raw = ev->u64};
	return data.seq;
}

static inline uint32_t
event_data_get_flow(struct rte_event *const ev)
{
	struct event_data data = {.raw = ev->u64};
	return data.flow;
}

static inline uint32_t
get_lock_idx(int queue, flow_id_t flow, uint32_t nb_flows)
{
	return (queue * nb_flows) + flow;
}

static inline bool
atomic_spinlock_trylock(uint32_t queue, uint32_t flow, uint32_t nb_flows)
{
	return rte_spinlock_trylock(&atomic_locks[get_lock_idx(queue, flow, nb_flows)]);
}

static inline void
atomic_spinlock_unlock(uint32_t queue, uint32_t flow, uint32_t nb_flows)
{
	rte_spinlock_unlock(&atomic_locks[get_lock_idx(queue, flow, nb_flows)]);
}

static inline bool
test_done(struct test_order *const t)
{
	return t->err || t->result == EVT_TEST_SUCCESS;
}

static inline int
atomic_producer(void *arg)
{
	struct prod_data *p = arg;
	struct test_order *t = p->t;
	struct evt_options *opt = t->opt;
	const uint8_t dev_id = p->dev_id;
	const uint8_t port = p->port_id;
	const uint64_t nb_pkts = t->nb_pkts;
	uint32_t *producer_flow_seq = t->producer_flow_seq;
	const uint32_t nb_flows = t->nb_flows;
	uint64_t count = 0;
	struct rte_event ev;

	if (opt->verbose_level > 1)
		printf("%s(): lcore %d dev_id %d port=%d queue=%d\n",
			__func__, rte_lcore_id(), dev_id, port, p->queue_id);

	ev = (struct rte_event) {
		.event = 0,
		.op = RTE_EVENT_OP_NEW,
		.queue_id = p->queue_id,
		.sched_type = RTE_SCHED_TYPE_ATOMIC,
		.priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
		.event_type = RTE_EVENT_TYPE_CPU
	};

	while (count < nb_pkts && t->err == false) {
		const flow_id_t flow = rte_rand_max(nb_flows);

		/* Maintain seq number per flow */
		ev.u64 = event_data_create(flow, producer_flow_seq[flow]++);
		ev.flow_id = flow;

		while (rte_event_enqueue_burst(dev_id, port, &ev, 1) != 1) {
			if (t->err)
				break;
			rte_pause();
		}

		count++;
	}

	if (!evt_is_maintenance_free(dev_id)) {
		while (!test_done(t)) {
			rte_event_maintain(dev_id, port, RTE_EVENT_DEV_MAINT_OP_FLUSH);
			rte_pause();
		}
	}

	return 0;
}

static inline void
atomic_lock_verify(struct test_order *const t, uint32_t flow, uint32_t nb_flows, uint32_t port,
		uint32_t queue_id)
{
	if (!atomic_spinlock_trylock(queue_id, flow, nb_flows)) {
		evt_err("q=%u, flow=%x atomicity error: port %u tried to take locked spinlock",
				queue_id, flow, port);
		t->err = true;
	}
}

static inline void
atomic_process_stage_0(struct test_order *const t, struct rte_event *const ev, uint32_t nb_flows,
		uint32_t port)
{
	const uint32_t flow = event_data_get_flow(ev);

	atomic_lock_verify(t, flow, nb_flows, port, 0);

	ev->queue_id = 1;
	ev->op = RTE_EVENT_OP_FORWARD;
	ev->sched_type = RTE_SCHED_TYPE_ATOMIC;
	ev->event_type = RTE_EVENT_TYPE_CPU;

	atomic_spinlock_unlock(0, flow, nb_flows);
}

static inline void
atomic_process_stage_1(struct test_order *const t, struct rte_event *const ev, uint32_t nb_flows,
		uint32_t *const expected_flow_seq, RTE_ATOMIC(uint64_t) *const outstand_pkts,
		uint32_t port)
{
	const uint32_t flow = event_data_get_flow(ev);

	atomic_lock_verify(t, flow, nb_flows, port, 1);

	/* compare the seqn against expected value */
	if (event_data_get_seq(ev) != expected_flow_seq[flow]) {
		evt_err("flow=%x seqn mismatch got=%lx expected=%x",
				flow, ev->u64, expected_flow_seq[flow]);
		t->err = true;
	}

	expected_flow_seq[flow]++;
	rte_atomic_fetch_sub_explicit(outstand_pkts, 1, rte_memory_order_relaxed);

	ev->op = RTE_EVENT_OP_RELEASE;

	atomic_spinlock_unlock(1, flow, nb_flows);
}

static int
atomic_queue_worker_burst(void *arg, bool flow_id_cap, uint32_t max_burst)
{
	ORDER_WORKER_INIT;
	struct rte_event ev[BURST_SIZE];
	uint16_t i;

	while (t->err == false) {

		uint16_t const nb_rx = rte_event_dequeue_burst(dev_id, port, ev, max_burst, 0);

		if (nb_rx == 0) {
			if (rte_atomic_load_explicit(outstand_pkts, rte_memory_order_relaxed) <=
					0) {
				break;
			}
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_rx; i++) {
			if (!flow_id_cap) {
				ev[i].flow_id = event_data_get_flow(&ev[i]);
			}

			switch (ev[i].queue_id) {
			case 0:
				atomic_process_stage_0(t, &ev[i], nb_flows, port);
				break;
			case 1:
				atomic_process_stage_1(t, &ev[i], nb_flows, expected_flow_seq,
						outstand_pkts, port);
				break;
			default:
				order_process_stage_invalid(t, &ev[i]);
				break;
			}
		}

		uint16_t total_enq = 0;

		do {
			total_enq += rte_event_enqueue_burst(
					dev_id, port, ev + total_enq, nb_rx - total_enq);
		} while (total_enq < nb_rx);
	}

	return 0;
}

static int
worker_wrapper(void *arg)
{
	struct worker_data *w = arg;
	int max_burst = evt_has_burst_mode(w->dev_id) ? BURST_SIZE : 1;
	const bool flow_id_cap = evt_has_flow_id(w->dev_id);

	return atomic_queue_worker_burst(arg, flow_id_cap, max_burst);
}

static int
atomic_queue_launch_lcores(struct evt_test *test, struct evt_options *opt)
{
	int ret, lcore_id;
	struct test_order *t = evt_test_priv(test);

	/* launch workers */

	int wkr_idx = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (!(opt->wlcores[lcore_id]))
			continue;

		ret = rte_eal_remote_launch(worker_wrapper, &t->worker[wkr_idx], lcore_id);
		if (ret) {
			evt_err("failed to launch worker %d", lcore_id);
			return ret;
		}
		wkr_idx++;
	}

	/* launch producer */
	int plcore = evt_get_first_active_lcore(opt->plcores);

	ret = rte_eal_remote_launch(atomic_producer, &t->prod, plcore);
	if (ret) {
		evt_err("failed to launch order_producer %d", plcore);
		return ret;
	}

	uint64_t prev_time = rte_get_timer_cycles();
	int64_t prev_outstanding_pkts = -1;

	while (t->err == false) {
		uint64_t current_time = rte_get_timer_cycles();
		int64_t outstanding_pkts = rte_atomic_load_explicit(
				&t->outstand_pkts, rte_memory_order_relaxed);

		if (outstanding_pkts <= 0) {
			t->result = EVT_TEST_SUCCESS;
			break;
		}

		if (current_time - prev_time > rte_get_timer_hz() * IDLE_TIMEOUT) {
			printf(CLGRN "\r%" PRId64 "" CLNRM, outstanding_pkts);
			fflush(stdout);
			if (prev_outstanding_pkts == outstanding_pkts) {
				rte_event_dev_dump(opt->dev_id, stdout);
				evt_err("No schedules for seconds, deadlock");
				t->err = true;
				break;
			}
			prev_outstanding_pkts = outstanding_pkts;
			prev_time = current_time;
		}
	}
	printf("\r");

	rte_free(atomic_locks);

	return 0;
}

static int
atomic_queue_eventdev_setup(struct evt_test *test, struct evt_options *opt)
{
	int ret;

	const uint8_t nb_workers = evt_nr_active_lcores(opt->wlcores);
	/* number of active worker cores + 1 producer */
	const uint8_t nb_ports = nb_workers + 1;

	ret = evt_configure_eventdev(opt, NB_QUEUES, nb_ports);
	if (ret) {
		evt_err("failed to configure eventdev %d", opt->dev_id);
		return ret;
	}

	/* q0 configuration */
	struct rte_event_queue_conf q0_atomic_conf = {
			.priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
			.schedule_type = RTE_SCHED_TYPE_ATOMIC,
			.nb_atomic_flows = opt->nb_flows,
			.nb_atomic_order_sequences = opt->nb_flows,
	};
	ret = rte_event_queue_setup(opt->dev_id, 0, &q0_atomic_conf);
	if (ret) {
		evt_err("failed to setup queue0 eventdev %d err %d", opt->dev_id, ret);
		return ret;
	}

	/* q1 configuration */
	struct rte_event_queue_conf q1_atomic_conf = {
			.priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
			.schedule_type = RTE_SCHED_TYPE_ATOMIC,
			.nb_atomic_flows = opt->nb_flows,
			.nb_atomic_order_sequences = opt->nb_flows,
	};
	ret = rte_event_queue_setup(opt->dev_id, 1, &q1_atomic_conf);
	if (ret) {
		evt_err("failed to setup queue0 eventdev %d err %d", opt->dev_id, ret);
		return ret;
	}

	/* setup one port per worker, linking to all queues */
	ret = order_event_dev_port_setup(test, opt, nb_workers, NB_QUEUES);
	if (ret)
		return ret;

	if (!evt_has_distributed_sched(opt->dev_id)) {
		uint32_t service_id;
		rte_event_dev_service_id_get(opt->dev_id, &service_id);
		ret = evt_service_setup(service_id);
		if (ret) {
			evt_err("No service lcore found to run event dev.");
			return ret;
		}
	}

	ret = rte_event_dev_start(opt->dev_id);
	if (ret) {
		evt_err("failed to start eventdev %d", opt->dev_id);
		return ret;
	}

	const uint32_t num_locks = NB_QUEUES * opt->nb_flows;

	atomic_locks = rte_calloc(NULL, num_locks, sizeof(rte_spinlock_t), 0);

	for (uint32_t i = 0; i < num_locks; i++) {
		rte_spinlock_init(&atomic_locks[i]);
	}

	return 0;
}

static void
atomic_queue_opt_dump(struct evt_options *opt)
{
	order_opt_dump(opt);
	evt_dump("nb_evdev_queues", "%d", NB_QUEUES);
}

static bool
atomic_queue_capability_check(struct evt_options *opt)
{
	struct rte_event_dev_info dev_info;

	rte_event_dev_info_get(opt->dev_id, &dev_info);
	if (dev_info.max_event_queues < NB_QUEUES ||
			dev_info.max_event_ports < order_nb_event_ports(opt)) {
		evt_err("not enough eventdev queues=%d/%d or ports=%d/%d", NB_QUEUES,
				dev_info.max_event_queues, order_nb_event_ports(opt),
				dev_info.max_event_ports);
		return false;
	}

	return true;
}

static const struct evt_test_ops atomic_queue = {
		.cap_check = atomic_queue_capability_check,
		.opt_check = order_opt_check,
		.opt_dump = atomic_queue_opt_dump,
		.test_setup = order_test_setup,
		.mempool_setup = order_mempool_setup,
		.eventdev_setup = atomic_queue_eventdev_setup,
		.launch_lcores = atomic_queue_launch_lcores,
		.eventdev_destroy = order_eventdev_destroy,
		.mempool_destroy = order_mempool_destroy,
		.test_result = order_test_result,
		.test_destroy = order_test_destroy,
};

EVT_TEST_REGISTER(atomic_queue);

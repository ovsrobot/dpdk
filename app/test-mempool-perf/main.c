/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include <rte_argparse.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_random.h>
#include <rte_ring.h>
#include <rte_string_fns.h>

#define DEFAULT_CACHE_SIZE          512
#define DEFAULT_RAND_FACTOR         8
#define DEFAULT_BURST_SIZE          32
#define DEFAULT_NB_BUFS_PER_LCORE   1024

/* match the element size used by rte_pktmbuf_pool_create with default dataroom */
#define ELEM_SIZE           (sizeof(struct rte_mbuf) + RTE_MBUF_DEFAULT_BUF_SIZE)
#define TEST_DURATION_SEC   5
#define RESHUFFLE_INTERVAL  100
#define PIPELINE_RING_SIZE  1024

struct test_config {
	char     mempool_type[RTE_MEMPOOL_NAMESIZE];
	uint32_t nb_bufs;
	uint32_t cache_size;
	uint32_t nb_threads;
	uint32_t rand_factor;
	uint32_t burst_size;
	bool     access_on_alloc;
	bool     pipeline_mode;
};

static struct test_config cfg = {
	.mempool_type   = "",
	.nb_bufs        = 0,  /* 0 means: compute from lcore count */
	.cache_size     = DEFAULT_CACHE_SIZE,
	.nb_threads     = 0,  /* 0 means: use all worker lcores */
	.rand_factor    = DEFAULT_RAND_FACTOR,
	.burst_size     = DEFAULT_BURST_SIZE,
	.access_on_alloc = true,
	.pipeline_mode  = false,
};

static void
apply_defaults(void)
{
	unsigned int nb_workers;

	nb_workers = rte_lcore_count() > 1 ? rte_lcore_count() - 1 : 1;

	if (cfg.nb_bufs == 0)
		cfg.nb_bufs = DEFAULT_NB_BUFS_PER_LCORE * rte_lcore_count();
	if (cfg.nb_threads == 0)
		cfg.nb_threads = nb_workers;
}

static bool
is_valid_mempool_type(const char *name)
{
	uint32_t i;

	for (i = 0; i < rte_mempool_ops_table.num_ops; i++)
		if (strcmp(name, rte_mempool_ops_table.ops[i].name) == 0)
			return true;
	return false;
}

static void
list_mempool_types(void)
{
	uint32_t i;

	printf("Available mempool types:\n");
	for (i = 0; i < rte_mempool_ops_table.num_ops; i++)
		printf("  [%u] %s\n", i, rte_mempool_ops_table.ops[i].name);
}

static void
print_config(void)
{
	printf("\n=== test-mempool-perf configuration ===\n");
	printf("  Mempool type     : %s\n", cfg.mempool_type);
	printf("  Num buffers      : %" PRIu32 "\n", cfg.nb_bufs);
	printf("  Cache size       : %" PRIu32 "\n", cfg.cache_size);
	printf("  Thread count     : %" PRIu32 "\n", cfg.nb_threads);
	printf("  Randomness factor: %" PRIu32 "\n", cfg.rand_factor);
	printf("  Burst size       : %" PRIu32 "\n", cfg.burst_size);
	printf("  Access on alloc  : %s\n", cfg.access_on_alloc ? "yes" : "no");
	printf("  Pipeline mode    : %s\n", cfg.pipeline_mode ? "yes" : "no");
	printf("========================================\n\n");
}

static void
print_reproduce_cmd(void)
{
	if (cfg.pipeline_mode)
		printf("Reproduce using parameters:"
			" -M %s -n %" PRIu32 " -c %" PRIu32 " -t %" PRIu32 " -b %" PRIu32 " %s -p\n\n",
				cfg.mempool_type, cfg.nb_bufs, cfg.cache_size, cfg.nb_threads,
				cfg.burst_size, cfg.access_on_alloc ? "-A" : "-N");
	else
		printf("Reproduce using parameters:"
			" -M %s -n %" PRIu32 " -c %" PRIu32 " -t %" PRIu32 " -r %" PRIu32 " -b %" PRIu32 " %s\n\n",
				cfg.mempool_type, cfg.nb_bufs, cfg.cache_size, cfg.nb_threads,
				cfg.rand_factor, cfg.burst_size, cfg.access_on_alloc ? "-A" : "-N");
}

static void
trim_newline(char *s)
{
	size_t len = strlen(s);

	if (len > 0 && s[len - 1] == '\n')
		s[len - 1] = '\0';
}

static int
prompt_uint32(const char *prompt, uint32_t *val)
{
	char buf[64];
	char *end;
	unsigned long v;

	fputs(prompt, stdout);
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) == NULL)
		return -1;
	trim_newline(buf);
	if (buf[0] == '\0')
		return 0;  /* keep default */

	v = strtoul(buf, &end, 0);
	if (*end != '\0') {
		fprintf(stderr, "Invalid number: %s\n", buf);
		return -1;
	}
	*val = (uint32_t)v;
	return 1;
}

static int
run_interactive_mode(void)
{
	char prompt[128];
	char buf[RTE_MEMPOOL_NAMESIZE];

	printf("\n=== test-mempool-perf interactive setup ===\n");
	printf("Press Enter to accept the default value.\n\n");

	list_mempool_types();
	printf("\n");

	/* Mempool type is required; loop until a valid name is entered */
	for (;;) {
		printf("Mempool type (required): ");
		fflush(stdout);
		if (fgets(buf, sizeof(buf), stdin) == NULL)
			return -1;
		trim_newline(buf);
		if (buf[0] == '\0') {
			printf("  A mempool type is required; please enter one of the names above.\n");
			continue;
		}
		if (is_valid_mempool_type(buf))
			break;
		printf("  Unknown mempool type '%s'; please enter one of the names above.\n", buf);
	}
	rte_strscpy(cfg.mempool_type, buf, sizeof(cfg.mempool_type));

	/* Compute numeric defaults now that EAL is initialised */
	apply_defaults();

	/* Number of buffers */
	snprintf(prompt, sizeof(prompt),
		 "Number of buffers [%" PRIu32 "]: ", cfg.nb_bufs);
	if (prompt_uint32(prompt, &cfg.nb_bufs) < 0)
		return -1;

	/* Cache size */
	snprintf(prompt, sizeof(prompt),
		 "Cache size [%" PRIu32 "]: ", cfg.cache_size);
	if (prompt_uint32(prompt, &cfg.cache_size) < 0)
		return -1;

	/* Thread count */
	snprintf(prompt, sizeof(prompt),
		 "Thread count [%" PRIu32 "]: ", cfg.nb_threads);
	if (prompt_uint32(prompt, &cfg.nb_threads) < 0)
		return -1;

	/* Pipeline mode */
	printf("Pipeline mode (producer/consumer pairs) [%s]: ",
	       cfg.pipeline_mode ? "yes" : "no");
	fflush(stdout);
	{
		char yn[16];

		if (fgets(yn, sizeof(yn), stdin) == NULL)
			return -1;
		trim_newline(yn);
		if (yn[0] == 'y' || yn[0] == 'Y')
			cfg.pipeline_mode = true;
		else if (yn[0] == 'n' || yn[0] == 'N')
			cfg.pipeline_mode = false;
		/* else keep default */
	}

	/* Randomness factor (not used in pipeline mode) */
	if (!cfg.pipeline_mode) {
		snprintf(prompt, sizeof(prompt),
			 "Randomness factor [%" PRIu32 "]: ", cfg.rand_factor);
		if (prompt_uint32(prompt, &cfg.rand_factor) < 0)
			return -1;
	}

	/* Burst size */
	snprintf(prompt, sizeof(prompt),
		 "Burst size [%" PRIu32 "]: ", cfg.burst_size);
	if (prompt_uint32(prompt, &cfg.burst_size) < 0)
		return -1;
	/* Access on allocation */
	printf("Access buffers on allocation [%s]: ",
	       cfg.access_on_alloc ? "yes" : "no");
	fflush(stdout);
	{
		char yn[16];

		if (fgets(yn, sizeof(yn), stdin) == NULL)
			return -1;
		trim_newline(yn);
		if (yn[0] == 'y' || yn[0] == 'Y')
			cfg.access_on_alloc = true;
		else if (yn[0] == 'n' || yn[0] == 'N')
			cfg.access_on_alloc = false;
		/* else keep default */
	}

	return 0;
}

struct worker_stats {
	uint64_t get_success;
	uint64_t get_fail;
	uint64_t put_count;
} __rte_cache_aligned;

static struct worker_stats lcore_stats[RTE_MAX_LCORE];
static bool summary_only;
static bool pipeline_producer[RTE_MAX_LCORE];
static RTE_ATOMIC(uint32_t) test_running;

struct pipeline_arg {
	struct rte_mempool *mp;
	struct rte_ring    *ring;
};

/*
 * Shuffle delta[] (half +1, half -1) then rotate it so the running sum
 * of held batches never goes negative.  Works by finding the last index
 * where the prefix sum reaches its minimum and rotating to start just
 * after that point, which is guaranteed to keep all prefix sums >= 0.
 */
static void
shuffle_and_validate(int8_t *delta, int8_t *tmp, uint32_t rf)
{
	uint32_t i, j, rot;
	int32_t running, min_val;
	uint32_t min_idx;

	/* Fisher-Yates shuffle */
	for (i = rf - 1; i > 0; i--) {
		j = (uint32_t)rte_rand_max(i + 1);
		int8_t t = delta[i];
		delta[i] = delta[j];
		delta[j] = t;
	}

	/* find last position where prefix sum reaches its minimum */
	running = 0;
	min_val = 0;
	min_idx = 0;
	for (i = 0; i < rf; i++) {
		running += delta[i];
		if (running <= min_val) { /* <= keeps the last occurrence */
			min_val = running;
			min_idx = i;
		}
	}

	if (min_val >= 0)
		return; /* already valid, no rotation needed */

	rot = (min_idx + 1) % rf;
	if (rot == 0)
		return;

	/* apply rotation via tmp buffer */
	memcpy(tmp,           delta + rot, (rf - rot) * sizeof(*tmp));
	memcpy(tmp + rf - rot, delta,       rot        * sizeof(*tmp));
	memcpy(delta, tmp, rf * sizeof(*tmp));
}

static void
access_object(void *obj)
{
	volatile uint64_t *p = (volatile uint64_t *)obj;
	uint64_t acc = 0;
	uint32_t i;

	for (i = 0; i < ELEM_SIZE / sizeof(uint64_t); i++)
		acc += p[i];
	for (i = 0; i < RTE_CACHE_LINE_SIZE / sizeof(uint64_t); i++)
		p[i] = acc;
}

static int
worker_main(void *arg)
{
	struct rte_mempool *mp = arg;
	unsigned int id = rte_lcore_id();
	struct worker_stats *stats = &lcore_stats[id];
	/* rf must be even so alloc count == free count; minimum 2 */
	uint32_t rf = RTE_MAX(2u, (cfg.rand_factor / 2) * 2);
	uint32_t bs = cfg.burst_size;
	uint32_t hold_count = 0;
	uint32_t run = RESHUFFLE_INTERVAL; /* trigger shuffle on first entry */
	void **hold_objs;
	int8_t *delta, *tmp;
	uint32_t i, k;

	hold_objs = malloc(bs * (rf / 2) * sizeof(*hold_objs));
	delta     = malloc(rf * sizeof(*delta));
	tmp       = malloc(rf * sizeof(*tmp));
	if (hold_objs == NULL || delta == NULL || tmp == NULL) {
		free(hold_objs);
		free(delta);
		free(tmp);
		return -ENOMEM;
	}

	/* +1 = alloc a burst, -1 = free a burst */
	for (i = 0; i < rf / 2; i++) delta[i] = +1;
	for (i = rf / 2; i < rf; i++) delta[i] = -1;

	while (rte_atomic_load_explicit(&test_running, rte_memory_order_relaxed)) {
		if (run >= RESHUFFLE_INTERVAL) {
			shuffle_and_validate(delta, tmp, rf);
			run = 0;
		}

		for (i = 0; i < rf; i++) {
			if (delta[i] > 0) {
				if (rte_mempool_get_bulk(mp,
						hold_objs + hold_count, bs) != 0) {
					stats->get_fail++;
					continue;
				}
				if (cfg.access_on_alloc) {
					for (k = 0; k < bs; k++)
						access_object(hold_objs[hold_count + k]);
				}
				hold_count += bs;
				stats->get_success += bs;
			} else {
				hold_count -= bs;
				rte_mempool_put_bulk(mp, hold_objs + hold_count, bs);
				stats->put_count += bs;
			}
		}
		run++;
	}

	if (hold_count > 0)
		rte_mempool_put_bulk(mp, hold_objs, hold_count);

	free(tmp);
	free(delta);
	free(hold_objs);
	return 0;
}

static int
producer_main(void *arg)
{
	struct pipeline_arg *parg = arg;
	struct rte_mempool *mp = parg->mp;
	struct rte_ring *ring = parg->ring;
	unsigned int id = rte_lcore_id();
	struct worker_stats *stats = &lcore_stats[id];
	uint32_t bs = cfg.burst_size;
	uint32_t i;
	void **objs;

	objs = malloc(bs * sizeof(*objs));
	if (objs == NULL)
		return -ENOMEM;

	while (rte_atomic_load_explicit(&test_running, rte_memory_order_relaxed)) {
		if (rte_mempool_get_bulk(mp, objs, bs) != 0) {
			stats->get_fail++;
			continue;
		}
		for (i = 0; i < bs; i++)
			access_object(objs[i]);
		/* spin until ring has space, or bail out if test ends */
		while (rte_ring_enqueue_bulk(ring, objs, bs, NULL) == 0) {
			rte_pause();
			if (!rte_atomic_load_explicit(&test_running, rte_memory_order_relaxed)) {
				rte_mempool_put_bulk(mp, objs, bs);
				goto done;
			}
		}
		stats->get_success += bs;
	}
done:
	free(objs);
	return 0;
}

static int
consumer_main(void *arg)
{
	struct pipeline_arg *parg = arg;
	struct rte_mempool *mp = parg->mp;
	struct rte_ring *ring = parg->ring;
	unsigned int id = rte_lcore_id();
	struct worker_stats *stats = &lcore_stats[id];
	uint32_t bs = cfg.burst_size;
	uint32_t i;
	void **objs;

	objs = malloc(bs * sizeof(*objs));
	if (objs == NULL)
		return -ENOMEM;

	while (rte_atomic_load_explicit(&test_running, rte_memory_order_relaxed)) {
		if (rte_ring_dequeue_bulk(ring, objs, bs, NULL) == 0) {
			rte_pause();
			continue;
		}
		for (i = 0; i < bs; i++)
			access_object(objs[i]);
		rte_mempool_put_bulk(mp, objs, bs);
		stats->get_success += bs;
		stats->put_count   += bs;
	}
	free(objs);
	return 0;
}

static struct rte_mempool *
create_mempool(void)
{
	struct rte_mempool *mp;
	int ret;

	mp = rte_mempool_create_empty("perf_pool", cfg.nb_bufs, ELEM_SIZE,
				      cfg.cache_size, 0,
				      rte_socket_id(), 0);
	if (mp == NULL) {
		fprintf(stderr, "Failed to create empty mempool: %s\n",
			rte_strerror(rte_errno));
		return NULL;
	}

	ret = rte_mempool_set_ops_byname(mp, cfg.mempool_type, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to set ops '%s': %s\n",
			cfg.mempool_type, rte_strerror(-ret));
		rte_mempool_free(mp);
		return NULL;
	}

	ret = rte_mempool_populate_default(mp);
	if (ret < 0) {
		fprintf(stderr, "Failed to populate mempool: %s\n",
			rte_strerror(-ret));
		rte_mempool_free(mp);
		return NULL;
	}

	return mp;
}

static void
print_results(double elapsed_secs)
{
	uint64_t total_get = 0, total_fail = 0;
	unsigned int id;

	printf("\n%-8s %12s %12s %12s\n",
	       "lcore", "get (Mops/s)", "fail/burst", "put (Mops/s)");
	printf("%-8s %12s %12s %12s\n",
	       "------", "------------", "----------", "------------");

	RTE_LCORE_FOREACH_WORKER(id) {
		if (lcore_stats[id].get_success == 0 &&
		    lcore_stats[id].get_fail == 0)
			continue;
		if (!summary_only)
			printf("%-8u %12.3f %12" PRIu64 " %12.3f\n",
			       id,
			       lcore_stats[id].get_success / elapsed_secs / 1e6,
			       lcore_stats[id].get_fail,
			       lcore_stats[id].put_count / elapsed_secs / 1e6);
		total_get  += lcore_stats[id].get_success;
		total_fail += lcore_stats[id].get_fail;
	}

	printf("%-8s %12.3f %12" PRIu64 "\n\n",
	       "Total",
	       total_get / elapsed_secs / 1e6,
	       total_fail);
}

static void
print_pipeline_results(double elapsed_secs)
{
	uint64_t total_cons = 0, total_fail = 0;
	unsigned int id;

	printf("\n%-8s %-10s %12s %12s\n",
	       "lcore", "role", "Mops/s", "fail/burst");
	printf("%-8s %-10s %12s %12s\n",
	       "------", "----------", "------------", "----------");

	RTE_LCORE_FOREACH_WORKER(id) {
		if (lcore_stats[id].get_success == 0 &&
		    lcore_stats[id].put_count   == 0 &&
		    lcore_stats[id].get_fail    == 0)
			continue;
		if (pipeline_producer[id]) {
			if (!summary_only)
				printf("%-8u %-10s %12.3f %12" PRIu64 "\n",
				       id, "producer",
				       lcore_stats[id].get_success / elapsed_secs / 1e6,
				       lcore_stats[id].get_fail);
			total_fail += lcore_stats[id].get_fail;
		} else {
			if (!summary_only)
				printf("%-8u %-10s %12.3f %12" PRIu64 "\n",
				       id, "consumer",
				       lcore_stats[id].put_count / elapsed_secs / 1e6,
				       lcore_stats[id].get_fail);
			total_cons += lcore_stats[id].put_count;
		}
	}

	/* pipeline throughput = consumer completion rate (the end-to-end bottleneck) */
	printf("%-8s %-10s %12.3f %12" PRIu64 "\n\n",
	       "Total", "",
	       total_cons / elapsed_secs / 1e6,
	       total_fail);
}

static void
run_test(struct rte_mempool *mp)
{
	uint64_t start, end;
	unsigned int id;
	uint32_t launched = 0;

	memset(lcore_stats, 0, sizeof(lcore_stats));
	rte_atomic_store_explicit(&test_running, 1, rte_memory_order_release);

	RTE_LCORE_FOREACH_WORKER(id) {
		if (launched >= cfg.nb_threads)
			break;
		rte_eal_remote_launch(worker_main, mp, id);
		launched++;
	}

	printf("Running test for %d seconds with %" PRIu32 " worker(s)...\n",
	       TEST_DURATION_SEC, launched);

	start = rte_get_timer_cycles();
	rte_delay_ms((uint32_t)(TEST_DURATION_SEC * 1000));

	rte_atomic_store_explicit(&test_running, 0, rte_memory_order_release);
	end = rte_get_timer_cycles();
	rte_eal_mp_wait_lcore();

	double elapsed_s = (double)(end - start) / rte_get_timer_hz();
	print_results(elapsed_s);
}

static void
run_pipeline_test(struct rte_mempool *mp)
{
	unsigned int worker_lcores[RTE_MAX_LCORE];
	char ring_name[RTE_RING_NAMESIZE];
	struct pipeline_arg *pargs;
	struct rte_ring **rings;
	void *drain[64];
	uint64_t start, end;
	uint32_t nb_workers = 0;
	uint32_t nb_pairs;
	uint32_t n, i;
	unsigned int id;

	RTE_LCORE_FOREACH_WORKER(id) {
		if (nb_workers >= cfg.nb_threads)
			break;
		worker_lcores[nb_workers++] = id;
	}

	nb_pairs = nb_workers / 2;
	if (nb_pairs == 0)
		rte_exit(EXIT_FAILURE,
			 "Pipeline mode needs at least 2 worker lcores\n");

	pargs = malloc(nb_pairs * sizeof(*pargs));
	rings = malloc(nb_pairs * sizeof(*rings));
	if (pargs == NULL || rings == NULL)
		rte_exit(EXIT_FAILURE, "Failed to allocate pipeline resources\n");

	for (i = 0; i < nb_pairs; i++) {
		snprintf(ring_name, sizeof(ring_name), "pipe_ring_%u", i);
		rings[i] = rte_ring_create(ring_name, PIPELINE_RING_SIZE,
					   rte_socket_id(),
					   RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (rings[i] == NULL)
			rte_exit(EXIT_FAILURE,
				 "Failed to create pipeline ring %u: %s\n",
				 i, rte_strerror(rte_errno));
		pargs[i].mp   = mp;
		pargs[i].ring = rings[i];
	}

	memset(lcore_stats, 0, sizeof(lcore_stats));
	memset(pipeline_producer, 0, sizeof(pipeline_producer));
	rte_atomic_store_explicit(&test_running, 1, rte_memory_order_release);

	for (i = 0; i < nb_pairs; i++) {
		id = worker_lcores[i];
		pipeline_producer[id] = true;
		rte_eal_remote_launch(producer_main, &pargs[i], id);
	}
	for (i = 0; i < nb_pairs; i++) {
		id = worker_lcores[nb_pairs + i];
		rte_eal_remote_launch(consumer_main, &pargs[i], id);
	}

	printf("Pipeline test: %" PRIu32 " producer/consumer pair(s), "
	       "%d seconds...\n", nb_pairs, TEST_DURATION_SEC);

	start = rte_get_timer_cycles();
	rte_delay_ms((uint32_t)(TEST_DURATION_SEC * 1000));
	rte_atomic_store_explicit(&test_running, 0, rte_memory_order_release);
	end = rte_get_timer_cycles();
	rte_eal_mp_wait_lcore();

	/* drain objects left in rings after workers exit, then release rings */
	for (i = 0; i < nb_pairs; i++) {
		while ((n = rte_ring_dequeue_burst(rings[i], drain, RTE_DIM(drain), NULL)) > 0)
			rte_mempool_put_bulk(mp, drain, n);
		rte_ring_free(rings[i]);
	}

	print_pipeline_results((double)(end - start) / rte_get_timer_hz());

	free(pargs);
	free(rings);
}

/* receives the --mempool-type string from argparse */
static const char *mempool_type_arg;

static int
parse_args(int argc, char **argv)
{
	static struct rte_argparse obj = {
		.prog_name = "test-mempool-perf",
		.usage = "[EAL options] -- [options]",
		.descriptor = "Mempool performance tester",
		.exit_on_error = true,
		.args = {
			{ "--mempool-type", "-M",
			  "Mempool driver to test (required in non-interactive mode)",
			  (void *)&mempool_type_arg, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_STR,
			},
			{ "--nb-bufs", "-n",
			  "Number of buffers in the pool (default: 1024 * lcore count)",
			  (void *)&cfg.nb_bufs, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--cache-size", "-c",
			  "Per-lcore object cache size (default: 512)",
			  (void *)&cfg.cache_size, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--nb-threads", "-t",
			  "Number of worker threads to use (default: all worker lcores)",
			  (void *)&cfg.nb_threads, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--rand-factor", "-r",
			  "Randomness factor for alloc/free burst sizes (default: 8)",
			  (void *)&cfg.rand_factor, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--burst-size", "-b",
			  "Number of objects per alloc/free burst (default: 32)",
			  (void *)&cfg.burst_size, NULL,
			  RTE_ARGPARSE_VALUE_REQUIRED, RTE_ARGPARSE_VALUE_TYPE_U32,
			},
			{ "--access-on-alloc", "-A",
			  "Enable touching buffer memory on allocation (default: enabled)",
			  (void *)&cfg.access_on_alloc, (void *)true,
			  RTE_ARGPARSE_VALUE_NONE, RTE_ARGPARSE_VALUE_TYPE_BOOL,
			},
			{ "--no-access-on-alloc", "-N",
			  "Disable touching buffer memory on allocation",
			  (void *)&cfg.access_on_alloc, (void *)false,
			  RTE_ARGPARSE_VALUE_NONE, RTE_ARGPARSE_VALUE_TYPE_BOOL,
			},
			{ "--summary", "-s",
			  "Print only the aggregate total, not per-lcore results",
			  (void *)&summary_only, (void *)true,
			  RTE_ARGPARSE_VALUE_NONE, RTE_ARGPARSE_VALUE_TYPE_BOOL,
			},
			{ "--pipeline", "-p",
			  "Pipeline mode: pair threads as producers and consumers connected by rings",
			  (void *)&cfg.pipeline_mode, (void *)true,
			  RTE_ARGPARSE_VALUE_NONE, RTE_ARGPARSE_VALUE_TYPE_BOOL,
			},
			ARGPARSE_ARG_END(),
		},
	};
	int ret;

	ret = rte_argparse_parse(&obj, argc, argv);
	if (ret < 0)
		return ret;

	if (mempool_type_arg != NULL)
		rte_strscpy(cfg.mempool_type, mempool_type_arg,
			    sizeof(cfg.mempool_type));

	return 0;
}

int
main(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	if (argc == 1) {
		/* No app-specific arguments: enter interactive configuration */
		ret = run_interactive_mode();
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Interactive configuration failed\n");
		print_reproduce_cmd();
	} else {
		ret = parse_args(argc, argv);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Invalid application arguments\n");

		if (cfg.mempool_type[0] == '\0') {
			fprintf(stderr,
				"Error: --mempool-type is required in non-interactive mode\n");
			list_mempool_types();
			rte_exit(EXIT_FAILURE, "Mempool type not specified\n");
		}
		if (!is_valid_mempool_type(cfg.mempool_type)) {
			fprintf(stderr, "Error: unknown mempool type '%s'\n",
				cfg.mempool_type);
			list_mempool_types();
			rte_exit(EXIT_FAILURE, "Invalid mempool type\n");
		}

		apply_defaults();
	}

	print_config();

	struct rte_mempool *mp = create_mempool();
	if (mp == NULL)
		rte_exit(EXIT_FAILURE, "Failed to create mempool\n");

	if (cfg.pipeline_mode)
		run_pipeline_test(mp);
	else
		run_test(mp);

	rte_mempool_free(mp);
	rte_eal_cleanup();
	return 0;
}

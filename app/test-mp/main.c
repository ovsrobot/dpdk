#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <rte_test.h>

static rte_atomic32_t g_count;

static int
done(const struct rte_mp_msg *msg __rte_unused, const void *arg __rte_unused)
{
	rte_atomic32_dec(&g_count);
	return 0;
}

int
main(int argc, char **argv)
{
	void *p;
	int ret;

	ret = rte_eal_init(argc, argv);
	RTE_TEST_ASSERT(ret >= 0, "init failed\n");

	rte_atomic32_set(&g_count, atoi(argv[++ret]));

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = rte_mp_action_register("done", done);
		RTE_TEST_ASSERT_SUCCESS(ret, "register action failed\n");
	}

	p = rte_malloc(NULL, 0x1000000, 0x1000);
	RTE_TEST_ASSERT_NOT_NULL(p, "allocation failed\n");

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		uint64_t timeout = rte_rdtsc() + 5 * rte_get_tsc_hz();

		while (rte_atomic32_read(&g_count) > 0)
			RTE_TEST_ASSERT(rte_rdtsc() < timeout, "timeout\n");
	} else {
		struct rte_mp_msg msg = { .name = "done" };

		rte_mp_sendmsg(&msg);
	}

	rte_eal_cleanup();
	return 0;
}

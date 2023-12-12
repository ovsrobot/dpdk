#include <stdio.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_launch.h>
#include <rte_eal.h>

rte_atomic32_t g_count;

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
	assert(ret >= 0);

	rte_atomic32_set(&g_count, atoi(argv[++ret]));

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ret = rte_mp_action_register("done", done);
		assert(ret == 0);
	}

	p = rte_malloc(NULL, 0x1000000, 0x1000);
	assert(p);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		uint64_t timeout = rte_rdtsc() + 5 * rte_get_tsc_hz();

		while (rte_atomic32_read(&g_count) > 0)
			assert(rte_rdtsc() < timeout);
	} else {
		struct rte_mp_msg msg = { .name = "done" };

		rte_mp_sendmsg(&msg);
	}

	rte_eal_cleanup();
	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Red Hat, Inc.
 */

#include <stdio.h>

#include "test.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#ifndef RTE_EXEC_ENV_LINUX

static int
test_dev_hotplug_api(void)
{
	printf("Hotplug API test only supported on Linux, skipping\n");
	return TEST_SKIPPED;
}

int
test_dev_hotplug_mp(void)
{
	printf("Hotplug MP test only supported on Linux, skipping\n");
	return TEST_SKIPPED;
}

#else

#include <sys/wait.h>

#include <rte_bus.h>
#include <rte_dev.h>
#include <rte_devargs.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_memzone.h>
#include <rte_stdatomic.h>

#include "process.h"

#define HOTPLUG_TEST_DEV "net_null0"

static struct rte_device *
find_device_by_name(const char *name)
{
	struct rte_dev_iterator it;
	struct rte_device *dev;
	struct rte_devargs da;
	char filter[32];

	memset(&da, 0, sizeof(da));
	if (rte_devargs_parse(&da, name) != 0)
		return NULL;

	snprintf(filter, sizeof(filter), "bus=%s", rte_bus_name(da.bus));
	rte_devargs_reset(&da);

	RTE_DEV_FOREACH(dev, filter, &it) {
		if (strcmp(rte_dev_name(dev), name) == 0 && rte_dev_is_probed(dev))
			return dev;
	}
	return NULL;
}

/*
 * Scenario A: Basic hotplug API test (single process)
 *
 * Tests that rte_dev_probe() and rte_dev_remove() work correctly.
 * This test runs in a single process and validates basic API functionality.
 */
static int
test_dev_hotplug_api(void)
{
	struct rte_device *dev;
	int ret;

	printf("== Testing rte_dev_probe/rte_dev_remove API ==\n");

	dev = find_device_by_name(HOTPLUG_TEST_DEV);
	if (dev != NULL) {
		printf("Device %s already exists, cannot run test\n", HOTPLUG_TEST_DEV);
		return TEST_FAILED;
	}

	printf("Probing device %s\n", HOTPLUG_TEST_DEV);
	ret = rte_dev_probe(HOTPLUG_TEST_DEV);
	if (ret != 0) {
		printf("rte_dev_probe(%s) failed: %d (%s)\n",
		       HOTPLUG_TEST_DEV, ret, rte_strerror(-ret));
		return TEST_FAILED;
	}

	dev = find_device_by_name(HOTPLUG_TEST_DEV);
	if (dev == NULL) {
		printf("Device %s not found after probe\n", HOTPLUG_TEST_DEV);
		return TEST_FAILED;
	}
	printf("Device %s probed successfully\n", HOTPLUG_TEST_DEV);

	printf("Removing device %s\n", HOTPLUG_TEST_DEV);
	ret = rte_dev_remove(dev);
	if (ret != 0) {
		printf("rte_dev_remove(%s) failed: %d (%s)\n",
		       HOTPLUG_TEST_DEV, ret, rte_strerror(-ret));
		return TEST_FAILED;
	}

	dev = find_device_by_name(HOTPLUG_TEST_DEV);
	if (dev != NULL) {
		printf("Device %s still exists after remove\n", HOTPLUG_TEST_DEV);
		return TEST_FAILED;
	}
	printf("Device %s removed successfully\n", HOTPLUG_TEST_DEV);

	printf("== Hotplug API test passed ==\n");
	return TEST_SUCCESS;
}

/*
 * Scenario B: Hotplug with multi-process notification
 *
 * Tests that when primary probes a device, running secondaries receive
 * the MP notification and can see the device.
 *
 * Sequence:
 * 1. Primary creates coordination memzone
 * 2. Primary spawns secondary (via fork+exec)
 * 3. Secondary signals ready via memzone
 * 4. Primary probes device
 * 5. Secondary should receive MP notification and see device
 * 6. Secondary signals result via memzone
 * 7. Primary collects result and cleans up
 */

#define MZ_HOTPLUG_STATE "hotplug_test_state"

/* States for inter-process coordination */
enum hotplug_test_state {
	STATE_SECONDARY_READY = 1,
	STATE_SECONDARY_CHECK_DEVICE,
	STATE_SECONDARY_DONE,
};

struct hotplug_state {
	RTE_ATOMIC(int) state;
	RTE_ATOMIC(int) secondary_result;
};

static void
signal_state(struct hotplug_state *state, int new_state)
{
	rte_atomic_store_explicit(&state->state, new_state, rte_memory_order_release);
}

static void
wait_for_state(RTE_ATOMIC(int) *state_ptr, int expected_state)
{
	while (rte_atomic_load_explicit(state_ptr, rte_memory_order_acquire) != expected_state)
		usleep(10000);
}

static int
run_secondary_hotplug_test(void)
{
	const struct rte_memzone *mz;
	struct hotplug_state *state;
	struct rte_device *dev;
	int ret = TEST_FAILED;

	printf("Secondary: starting MP hotplug test\n");

	mz = rte_memzone_lookup(MZ_HOTPLUG_STATE);
	if (mz == NULL) {
		printf("Secondary: cannot find coordination memzone\n");
		return TEST_FAILED;
	}
	state = mz->addr;

	printf("Secondary: signaling ready\n");
	signal_state(state, STATE_SECONDARY_READY);

	printf("Secondary: waiting for device probe\n");
	wait_for_state(&state->state, STATE_SECONDARY_CHECK_DEVICE);

	/*
	 * Primary has probed the device. If MP notification worked correctly,
	 * we should be able to find the device in our local device list.
	 */
	printf("Secondary: checking for device %s\n", HOTPLUG_TEST_DEV);
	dev = find_device_by_name(HOTPLUG_TEST_DEV);
	if (dev != NULL) {
		printf("Secondary: device found - MP notification worked!\n");
		ret = TEST_SUCCESS;
	} else {
		printf("Secondary: device NOT found - MP notification failed!\n");
		ret = TEST_FAILED;
	}

	rte_atomic_store_explicit(&state->secondary_result, ret, rte_memory_order_relaxed);
	signal_state(state, STATE_SECONDARY_DONE);

	return ret;
}

static int
run_primary_hotplug_test(void)
{
	const struct rte_memzone *mz = NULL;
	int test_result = TEST_FAILED;
	struct hotplug_state *state;
	struct rte_device *dev;
	pid_t pid = -1;
	int ret;

	printf("Primary: starting MP hotplug test\n");

	mz = rte_memzone_reserve(MZ_HOTPLUG_STATE, sizeof(struct hotplug_state),
				 rte_socket_id(), 0);
	if (mz == NULL) {
		printf("Primary: cannot create coordination memzone: %s\n",
		       rte_strerror(rte_errno));
		goto out;
	}
	state = mz->addr;
	memset(state, 0, sizeof(*state));

	printf("Primary: spawning secondary process\n");
	pid = fork();
	if (pid < 0) {
		printf("Primary: fork failed: %s\n", strerror(errno));
		goto out;
	}

	if (pid == 0) {
		/* Child: exec as secondary */
		const char *prefix;
		char core_str[16];
		char *argv[6];

		prefix = file_prefix_arg();
		snprintf(core_str, sizeof(core_str), "%u", rte_get_main_lcore());

		argv[0] = strdup(prgname);
		argv[1] = strdup("-l");
		argv[2] = strdup(core_str);
		argv[3] = strdup("--proc-type=secondary");
		argv[4] = strdup(prefix);
		argv[5] = NULL;

		if (setenv(RECURSIVE_ENV_VAR, "run_hotplug_secondary", 1) == 0)
			execv(argv[0], argv);
		exit(TEST_FAILED);
	}

	/* Parent: continue as primary */

	printf("Primary: waiting for secondary to be ready\n");
	wait_for_state(&state->state, STATE_SECONDARY_READY);
	printf("Primary: secondary is ready\n");

	/* Probe device - this should send MP notification to secondary */
	printf("Primary: probing device %s\n", HOTPLUG_TEST_DEV);
	ret = rte_dev_probe(HOTPLUG_TEST_DEV);
	if (ret != 0) {
		printf("Primary: rte_dev_probe failed: %d (%s)\n", ret, rte_strerror(-ret));
		goto out;
	}

	printf("Primary: device probed, signaling secondary\n");
	signal_state(state, STATE_SECONDARY_CHECK_DEVICE);

	printf("Primary: waiting for secondary result\n");
	wait_for_state(&state->state, STATE_SECONDARY_DONE);

	test_result = rte_atomic_load_explicit(&state->secondary_result, rte_memory_order_acquire);
	printf("Primary: secondary reported %s\n",
	       test_result == TEST_SUCCESS ? "SUCCESS" : "FAILURE");

	dev = find_device_by_name(HOTPLUG_TEST_DEV);
	if (dev != NULL) {
		printf("Primary: removing device %s\n", HOTPLUG_TEST_DEV);
		rte_dev_remove(dev);
	}

out:
	if (pid > 0) {
		int wstatus;

		waitpid(pid, &wstatus, 0);
		if (WIFEXITED(wstatus))
			printf("Primary: secondary exited with status %d\n", WEXITSTATUS(wstatus));
	}
	rte_memzone_free(mz);

	if (test_result == TEST_SUCCESS)
		printf("== MP hotplug test passed ==\n");
	else
		printf("== MP hotplug test FAILED ==\n");

	return test_result;
}

int
test_dev_hotplug_mp(void)
{
	printf("== Testing hotplug with multi-process notification ==\n");

	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		return run_primary_hotplug_test();

	return run_secondary_hotplug_test();
}

#endif /* RTE_EXEC_ENV_LINUX */

REGISTER_FAST_TEST(dev_hotplug_api_autotest, NOHUGE_OK, ASAN_OK, test_dev_hotplug_api);
REGISTER_FAST_TEST(dev_hotplug_mp_autotest, NOHUGE_SKIP, ASAN_SKIP, test_dev_hotplug_mp);

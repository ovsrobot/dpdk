/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell
 */

#include <setjmp.h>
#include <signal.h>

#include <rte_config.h>
#include <rte_oops.h>

#include "test.h"

static jmp_buf pc;
static bool detected_segfault;

static void
segv_handler(int sig, siginfo_t *info, void *ctx)
{
	detected_segfault = true;
	rte_oops_decode(sig, info, (ucontext_t *)ctx);
	longjmp(pc, 1);
}

/* OS specific way install the signal segfault handler*/
static int
segv_handler_install(void)
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = &segv_handler;
	sa.sa_flags = SA_SIGINFO;

	return sigaction(SIGSEGV, &sa, NULL);
}

static int
test_oops_generate(void)
{
	int rc;

	rc = segv_handler_install();
	TEST_ASSERT_EQUAL(rc, 0, "rc=%d\n", rc);

	detected_segfault = false;
	rc = setjmp(pc); /* Save the execution state */
	if (rc == 0) {
		/* Generate a segfault */
		*(volatile int *)0x05 = 0;
	} else { /* logjump from segv_handler */
		if (detected_segfault)
			return TEST_SUCCESS;

	}
	return TEST_FAILED;
}

static int
test_signal_handler_installed(int count, int *signals)
{
	int i, rc, verified = 0;
	struct sigaction sa;

	for (i = 0; i < count; i++) {
		rc = sigaction(signals[i], NULL, &sa);
		if (rc) {
			printf("Failed to get sigaction for %d", signals[i]);
			continue;
		}
		if (sa.sa_handler != SIG_DFL)
			verified++;
	}
	TEST_ASSERT_EQUAL(count, verified, "count=%d verified=%d\n", count,
			  verified);
	return TEST_SUCCESS;
}

static int
test_oops_signals_enabled(void)
{
	int *signals = NULL;
	int i, rc;

	rc = rte_oops_signals_enabled(signals);
	TEST_ASSERT_NOT_EQUAL(rc, 0, "rc=%d\n", rc);

	signals = malloc(sizeof(int) * rc);
	rc = rte_oops_signals_enabled(signals);
	TEST_ASSERT_NOT_EQUAL(rc, 0, "rc=%d\n", rc);
	free(signals);

	signals = malloc(sizeof(int) * RTE_OOPS_SIGNALS_MAX);
	rc = rte_oops_signals_enabled(signals);
	TEST_ASSERT_NOT_EQUAL(rc, 0, "rc=%d\n", rc);

	for (i = 0; i < rc; i++)
		TEST_ASSERT_NOT_EQUAL(signals[i], 0, "idx=%d val=%d\n", i,
				      signals[i]);

	rc = test_signal_handler_installed(rc, signals);
	free(signals);

	return rc;
}

static struct unit_test_suite oops_tests = {
	.suite_name = "oops autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
			    TEST_CASE(test_oops_signals_enabled),
			    TEST_CASE(test_oops_generate),
			    TEST_CASES_END()}};

static int
test_oops(void)
{
	return unit_test_suite_runner(&oops_tests);
}

REGISTER_TEST_COMMAND(oops_autotest, test_oops);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <inttypes.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_oops.h>

#include "eal_private.h"

#define oops_print(...) rte_log(RTE_LOG_ERR, RTE_LOGTYPE_EAL, __VA_ARGS__)

static int oops_signals[] = {SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGFPE, SIGSYS};

struct oops_signal {
	int sig;
	bool enabled;
	struct sigaction sa;
};

static struct oops_signal signals_db[RTE_DIM(oops_signals)];

static void
back_trace_dump(ucontext_t *context)
{
	RTE_SET_USED(context);

	rte_dump_stack();
}
static void
siginfo_dump(int sig, siginfo_t *info)
{
	oops_print("PID:           %" PRIdMAX "\n", (intmax_t)getpid());

	if (info == NULL)
		return;
	if (sig != info->si_signo)
		oops_print("Invalid signal info\n");

	oops_print("Signal number: %d\n", info->si_signo);
	oops_print("Fault address: %p\n", info->si_addr);
}

static void
mem32_dump(void *ptr)
{
	uint32_t *p = ptr;
	int i;

	for (i = 0; i < 16; i++)
		oops_print("%p: 0x%x\n", p + i, rte_be_to_cpu_32(p[i]));
}

static void
stack_dump_header(void)
{
	oops_print("Stack dump:\n");
	oops_print("----------\n");
}

static void
code_dump_header(void)
{
	oops_print("Code dump:\n");
	oops_print("----------\n");
}

static void
stack_code_dump(void *stack, void *code)
{
	if (stack == NULL || code == NULL)
		return;

	oops_print("\n");
	stack_dump_header();
	mem32_dump(stack);
	oops_print("\n");

	code_dump_header();
	mem32_dump(code);
	oops_print("\n");
}
static void
archinfo_dump(ucontext_t *uc)
{
	RTE_SET_USED(uc);

	stack_code_dump(NULL, NULL);
}

static void
default_signal_handler_invoke(int sig)
{
	unsigned int idx;

	for (idx = 0; idx < RTE_DIM(oops_signals); idx++) {
		/* Skip disabled signals */
		if (signals_db[idx].sig != sig)
			continue;
		if (!signals_db[idx].enabled)
			continue;
		/* Replace with stored handler */
		sigaction(sig, &signals_db[idx].sa, NULL);
		kill(getpid(), sig);
	}
}

void
rte_oops_decode(int sig, siginfo_t *info, ucontext_t *uc)
{
	oops_print("Signal info:\n");
	oops_print("------------\n");
	siginfo_dump(sig, info);
	oops_print("\n");

	oops_print("Backtrace:\n");
	oops_print("----------\n");
	back_trace_dump(uc);
	oops_print("\n");

	oops_print("Arch info:\n");
	oops_print("----------\n");
	if (uc)
		archinfo_dump(uc);
}

static void
eal_oops_handler(int sig, siginfo_t *info, void *ctx)
{
	ucontext_t *uc = ctx;

	rte_oops_decode(sig, info, uc);
	default_signal_handler_invoke(sig);
}

int
rte_oops_signals_enabled(int *signals)
{
	int count = 0, sig[RTE_OOPS_SIGNALS_MAX];
	unsigned int idx = 0;

	for (idx = 0; idx < RTE_DIM(oops_signals); idx++) {
		if (signals_db[idx].enabled) {
			sig[count] = signals_db[idx].sig;
			count++;
		}
	}
	if (signals)
		memcpy(signals, sig, sizeof(*signals) * count);

	return count;
}

int
eal_oops_init(void)
{
	unsigned int idx, rc = 0;
	struct sigaction sa;

	RTE_BUILD_BUG_ON(RTE_DIM(oops_signals) > RTE_OOPS_SIGNALS_MAX);

	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = &eal_oops_handler;
	sa.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;

	for (idx = 0; idx < RTE_DIM(oops_signals); idx++) {
		signals_db[idx].sig = oops_signals[idx];
		/* Get exiting sigaction */
		rc = sigaction(signals_db[idx].sig, NULL, &signals_db[idx].sa);
		if (rc)
			continue;
		/* Replace with oops handler */
		rc = sigaction(signals_db[idx].sig, &sa, NULL);
		if (rc)
			continue;
		signals_db[idx].enabled = true;
	}
	return rc;
}

void
eal_oops_fini(void)
{
	unsigned int idx;

	for (idx = 0; idx < RTE_DIM(oops_signals); idx++) {
		if (!signals_db[idx].enabled)
			continue;
		/* Replace with stored handler */
		sigaction(signals_db[idx].sig, &signals_db[idx].sa, NULL);
	}
}

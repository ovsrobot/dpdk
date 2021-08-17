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

#if defined(RTE_USE_LIBUNWIND)

#define BACKTRACE_DEPTH 256
#define UNW_LOCAL_ONLY
#include <libunwind.h>

static void
back_trace_dump(ucontext_t *context)
{
	unw_cursor_t cursor;
	unw_word_t ip, off;
	int rc, level = 0;
	char name[256];

	if (context == NULL) {
		rte_dump_stack();
		return;
	}

	rc = unw_init_local(&cursor, (unw_context_t *)context);
	if (rc < 0)
		goto fail;

	for (;;) {
		rc = unw_get_reg(&cursor, UNW_REG_IP, &ip);
		if (rc < 0)
			goto fail;
		rc = unw_get_proc_name(&cursor, name, sizeof(name), &off);
		if (rc == 0)
			oops_print("[%16p]: %s()+0x%" PRIx64 "\n", (void *)ip,
				   name, (uint64_t)off);
		else
			oops_print("[%16p]: <unknown>\n", (void *)ip);
		rc = unw_step(&cursor);
		if (rc <= 0 || ++level >= BACKTRACE_DEPTH)
			break;
	}
	return;
fail:
	oops_print("libunwind call failed %s\n", unw_strerror(rc));
}

#else

static void
back_trace_dump(ucontext_t *context)
{
	RTE_SET_USED(context);

	rte_dump_stack();
}

#endif

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

#if defined(RTE_ARCH_X86_64) && defined(RTE_EXEC_ENV_LINUX)
static void
archinfo_dump(ucontext_t *uc)
{

	mcontext_t *mc = &uc->uc_mcontext;

	oops_print("R8 : 0x%.16llx  ", mc->gregs[REG_R8]);
	oops_print("R9 : 0x%.16llx\n", mc->gregs[REG_R9]);
	oops_print("R10: 0x%.16llx  ", mc->gregs[REG_R10]);
	oops_print("R11: 0x%.16llx\n", mc->gregs[REG_R11]);
	oops_print("R12: 0x%.16llx  ", mc->gregs[REG_R12]);
	oops_print("R13: 0x%.16llx\n", mc->gregs[REG_R13]);
	oops_print("R14: 0x%.16llx  ", mc->gregs[REG_R14]);
	oops_print("R15: 0x%.16llx\n", mc->gregs[REG_R15]);
	oops_print("RAX: 0x%.16llx  ", mc->gregs[REG_RAX]);
	oops_print("RBX: 0x%.16llx\n", mc->gregs[REG_RBX]);
	oops_print("RCX: 0x%.16llx  ", mc->gregs[REG_RCX]);
	oops_print("RDX: 0x%.16llx\n", mc->gregs[REG_RDX]);
	oops_print("RBP: 0x%.16llx  ", mc->gregs[REG_RBP]);
	oops_print("RSP: 0x%.16llx\n", mc->gregs[REG_RSP]);
	oops_print("RSI: 0x%.16llx  ", mc->gregs[REG_RSI]);
	oops_print("RDI: 0x%.16llx\n", mc->gregs[REG_RDI]);
	oops_print("RIP: 0x%.16llx  ", mc->gregs[REG_RIP]);
	oops_print("EFL: 0x%.16llx\n", mc->gregs[REG_EFL]);

	stack_code_dump((void *)mc->gregs[REG_RSP], (void *)mc->gregs[REG_RIP]);
}

#else

static void
archinfo_dump(ucontext_t *uc)
{
	RTE_SET_USED(uc);

	stack_code_dump(NULL, NULL);
}

#endif

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

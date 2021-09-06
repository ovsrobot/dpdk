/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell.
 */

#ifndef _RTE_OOPS_H_
#define _RTE_OOPS_H_

#include <rte_common.h>
#include <rte_compat.h>
#include <rte_config.h>

/**
 * @file
 *
 * RTE oops API
 *
 * This file provides the oops handling APIs to RTE applications.
 *
 * On rte_eal_init() invocation and if *--no-oops* not provided in the EAL
 * command line argument, then EAL library installs the oops handler for
 * the essential signals. The rte_oops_signals_enabled() API provides the list
 * of signals the library installed by the EAL.
 *
 * The default EAL oops handler decodes the oops message using rte_oops_decode()
 * and then calls the signal handler installed by the application before
 * invoking the rte_eal_init(). This scheme will also enable the use of
 * the default coredump handler(for gdb etc.) provided by OS if the application
 * does not install any specific signal handler.
 *
 * The second case where the application installs the signal handler after
 * the rte_eal_init() invocation, rte_oops_decode() provides the means of
 * decoding the oops message in the application's fault handler.
 *
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum number of oops signals enabled in EAL.
 * @see rte_oops_signals_enabled()
 */
#define RTE_OOPS_SIGNALS_MAX 32

/**
 * Get the list of enabled oops signals installed by EAL.
 *
 * @param [out] signals
 *   A pointer to store the enabled signals.
 *   Value NULL is allowed. if not NULL, then the size of this array must be
 *   at least RTE_OOPS_SIGNALS_MAX.
 *
 * @return
 *   Number of enabled oops signals.
 */
__rte_experimental
int rte_oops_signals_enabled(int *signals);

#if defined(RTE_EXEC_ENV_LINUX) || defined(RTE_EXEC_ENV_FREEBSD)
#include <signal.h>
#include <ucontext.h>

/**
 * Decode an oops
 *
 * This prototype is same as sa_sigaction defined in signal.h.
 * Application must register signal handler using sigaction() with
 * sa_flag as SA_SIGINFO flag to get this information from unix OS.
 *
 * @param sig
 *   Signal number
 * @param info
 *   Signal info provided by sa_sigaction. Value NULL is allowed.
 * @param uc
 *   ucontext_t provided when signal installed with SA_SIGINFO flag.
 *   Value NULL is allowed.
 *
 */
__rte_experimental
void rte_oops_decode(int sig, siginfo_t *info, ucontext_t *uc);
#else

/**
 * Decode an oops
 *
 * @param sig
 *   Signal number
 */
__rte_experimental
void rte_oops_decode(int sig);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_OOPS_H_ */

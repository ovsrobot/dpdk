/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifdef RTE_BACKTRACE
#include <execinfo.h>
#include <dlfcn.h>
#endif
#include <stdarg.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <rte_log.h>
#include <rte_debug.h>
#include <rte_common.h>
#include <rte_eal.h>

#define BACKTRACE_SIZE 256

/* Dump the stack of the calling core
 *
 * Note: this requires limiting what functions are used in this code to stay safe
 * when called from a signal handler and malloc pool maybe corrupt.
 */
void rte_dump_stack(void)
{
#ifdef RTE_BACKTRACE
	void *func[BACKTRACE_SIZE];
	int i, size;

	size = backtrace(func, BACKTRACE_SIZE);

	for (i = 0; i < size; i++) {
		void *pc = func[i];
		const char *fname;
		Dl_info info;

		if (dladdr(pc, &info) == 0) {
			/* If symbol information not found print in hex */
			rte_log(RTE_LOG_ERR, RTE_LOGTYPE_EAL,
				"%d: ?? [%p]\n", i, pc);
			continue;
		}

		/* Is file name known? */
		fname = (info.dli_fname && *info.dli_fname) ? info.dli_fname : "(vdso)";

		/* Is symbol name known? */
		if (info.dli_sname != NULL)
			rte_log(RTE_LOG_ERR, RTE_LOGTYPE_EAL,
				"%d: %s (%s+%#tx) [%p]\n",
				i, fname, info.dli_sname,
				(ptrdiff_t)((uintptr_t)pc - (uintptr_t)info.dli_saddr),
				pc);
		else
			rte_log(RTE_LOG_ERR, RTE_LOGTYPE_EAL,
				"%d: %s (%p+%#tx) [%p]\n",
				i, fname, info.dli_fbase,
				(ptrdiff_t)((uintptr_t)pc - (uintptr_t)info.dli_fbase),
				pc);
	}
#endif /* RTE_BACKTRACE */
}

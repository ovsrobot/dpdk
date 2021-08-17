/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */


#include <rte_oops.h>

#include "eal_private.h"

void
rte_oops_decode(int sig, siginfo_t *info, ucontext_t *uc)
{
	RTE_SET_USED(sig);
	RTE_SET_USED(info);
	RTE_SET_USED(uc);

}

int
rte_oops_signals_enabled(int *signals)
{
	RTE_SET_USED(signals);

	return 0;
}

int
eal_oops_init(void)
{
	return 0;
}

void
eal_oops_fini(void)
{
}

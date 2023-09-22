/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Red Hat, Inc.
 */

#include <stdio.h>
#include <inttypes.h>

#include "eal_cpu.h"

#include "test.h"

static int
test_cpu(void)
{
#ifndef RTE_ARCH_X86
	RTE_TEST_ASSERT(!rte_cpu_is_x86(), "rte_cpu_is_x86() returned true on " RTE_STR(RTE_ARCH));
#else
	const char *vendor;

	RTE_TEST_ASSERT(rte_cpu_is_x86(), "rte_cpu_is_x86() returned false");

	if (rte_cpu_x86_is_amd())
		vendor = "AMD";
	else if (rte_cpu_x86_is_intel())
		vendor = "Intel";
	else
		vendor = "unknown";

	printf("The processor running this program is a x86 %s processor, brand=0x%"
		PRIx8", family=0x%"PRIx8", model=0x%"PRIx8"\n", vendor, rte_cpu_x86_brand(),
		rte_cpu_x86_family(), rte_cpu_x86_model());
#endif

	return TEST_SUCCESS;
}

REGISTER_FAST_TEST(cpu_autotest, true, true, test_cpu);

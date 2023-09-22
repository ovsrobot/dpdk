/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Red Hat, Inc.
 */

#include <rte_debug.h>

#include "eal_cpu.h"

#ifdef RTE_ARCH_X86
#ifndef RTE_TOOLCHAIN_MSVC
#include <cpuid.h>
#endif

static void
x86_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx,
	uint32_t *ecx, uint32_t *edx)
{
	uint32_t regs[4] = { 0 };

#ifdef RTE_TOOLCHAIN_MSVC
	__cpuidex(regs, leaf, subleaf);
#else
	__cpuid_count(leaf, subleaf, regs[0], regs[1], regs[2], regs[3]);
#endif

	*eax = regs[0];
	*ebx = regs[1];
	*ecx = regs[2];
	*edx = regs[3];
}
#endif /* RTE_ARCH_X86 */

bool
rte_cpu_is_x86(void)
{
#ifndef RTE_ARCH_X86
	return false;
#else
	return true;
#endif
}

bool
rte_cpu_x86_is_amd(void)
{
#ifndef RTE_ARCH_X86
	rte_panic("Calling %s does not make sense on %s architecture.\n",
		__func__, RTE_STR(RTE_ARCH));
#else
	uint32_t eax, ebx, ecx, edx;

	x86_cpuid(0x0, 0x0, &eax, &ebx, &ecx, &edx);
	/* ascii_to_little_endian("Auth enti cAMD") */
	return ebx == 0x68747541 && ecx == 0x444d4163 && edx == 0x69746e65;
#endif
}

bool
rte_cpu_x86_is_intel(void)
{
#ifndef RTE_ARCH_X86
	rte_panic("Calling %s does not make sense on %s architecture.\n",
		__func__, RTE_STR(RTE_ARCH));
#else
	uint32_t eax, ebx, ecx, edx;

	x86_cpuid(0x0, 0x0, &eax, &ebx, &ecx, &edx);
	/* ascii_to_little_endian("Genu ineI ntel") */
	return ebx == 0x756e6547 && ecx == 0x6c65746e && edx == 0x49656e69;
#endif
}

uint8_t
rte_cpu_x86_brand(void)
{
#ifndef RTE_ARCH_X86
	rte_panic("Calling %s does not make sense on %s architecture.\n",
		__func__, RTE_STR(RTE_ARCH));
#else
	uint32_t eax, ebx, ecx, edx;
	uint8_t brand = 0;

	x86_cpuid(0x0, 0x0, &eax, &ebx, &ecx, &edx);
	if (eax >= 1) {
		x86_cpuid(0x1, 0x0, &eax, &ebx, &ecx, &edx);
		brand = ebx & 0xff;
	}

	return brand;
#endif
}

uint8_t
rte_cpu_x86_family(void)
{
#ifndef RTE_ARCH_X86
	rte_panic("Calling %s does not make sense on %s architecture.\n",
		__func__, RTE_STR(RTE_ARCH));
#else
	uint32_t eax, ebx, ecx, edx;
	uint8_t family = 0;

	x86_cpuid(0x0, 0x0, &eax, &ebx, &ecx, &edx);
	if (eax >= 1) {
		uint8_t family_id;

		x86_cpuid(0x1, 0x0, &eax, &ebx, &ecx, &edx);
		family_id = (eax >> 8) & 0x0f;
		family = family_id;
		if (family_id == 0xf)
			family += (eax >> 20) & 0xff;
	}

	return family;
#endif
}

uint8_t
rte_cpu_x86_model(void)
{
#ifndef RTE_ARCH_X86
	rte_panic("Calling %s does not make sense on %s architecture.\n",
		__func__, RTE_STR(RTE_ARCH));
#else
	uint32_t eax, ebx, ecx, edx;
	uint8_t model = 0;

	x86_cpuid(0x0, 0x0, &eax, &ebx, &ecx, &edx);
	if (eax >= 1) {
		uint8_t family_id;

		x86_cpuid(0x1, 0x0, &eax, &ebx, &ecx, &edx);
		family_id = (eax >> 8) & 0x0f;
		model = (eax >> 4) & 0x0f;
		if (family_id == 0x6 || family_id == 0xf)
			model += (eax >> 12) & 0xf0;
	}

	return model;
#endif
}

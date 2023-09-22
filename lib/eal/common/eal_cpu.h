/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Red Hat, Inc.
 */

#ifndef EAL_CPU_H
#define EAL_CPU_H

#include <stdbool.h>
#include <stdint.h>

#include <rte_compat.h>

/**
 * Returns whether the processor running this program is a x86 one.
 *
 * @return
 *      true or false
 */
__rte_internal
bool rte_cpu_is_x86(void);

/**
 * Returns whether the processor running this program is a AMD x86 one.
 *
 * Note: calling this function only makes sense if rte_cpu_is_x86() == true.
 *
 * @return
 *      true or false
 */
__rte_internal
bool rte_cpu_x86_is_amd(void);

/**
 * Returns whether the processor running this program is a Intel x86 one.
 *
 * Note: calling this function only makes sense if rte_cpu_is_x86() == true.
 *
 * @return
 *      true or false
 */
__rte_internal
bool rte_cpu_x86_is_intel(void);

/**
 * Returns the processor brand (as returned by CPUID).
 *
 * Note: calling this function only makes sense if rte_cpu_is_x86() == true.
 *
 * @return
 *      x86 processor brand
 */
__rte_internal
uint8_t rte_cpu_x86_brand(void);

/**
 * Returns the processor family (as returned by CPUID).
 *
 * Note: calling this function only makes sense if rte_cpu_is_x86() == true.
 *
 * @return
 *      x86 processor family
 */
__rte_internal
uint8_t rte_cpu_x86_family(void);

/**
 * Returns the processor model (as returned by CPUID).
 *
 * Note: calling this function only makes sense if rte_cpu_is_x86() == true.
 *
 * @return
 *      x86 processor model
 */
__rte_internal
uint8_t rte_cpu_x86_model(void);

#endif /* EAL_CPU_H */

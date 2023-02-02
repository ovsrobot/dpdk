/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell
 */

#ifndef _PMU_PRIVATE_H_
#define _PMU_PRIVATE_H_

/**
 * Architecture specific PMU init callback.
 *
 * @return
 *   0 in case of success, negative value otherwise.
 */
int
pmu_arch_init(void);

/**
 * Architecture specific PMU cleanup callback.
 */
void
pmu_arch_fini(void);

/**
 * Apply architecture specific settings to config before passing it to syscall.
 */
void
pmu_arch_fixup_config(uint64_t config[3]);

#endif /* _PMU_PRIVATE_H_ */

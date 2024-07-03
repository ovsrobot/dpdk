/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */

#ifndef _SIG_CMP_FUNC_H_
#define _SIG_CMP_FUNC_H_

/** Enum used to select the implementation of the signature comparison function to use
 * eg: A system supporting SVE might want to use a NEON implementation.
 * Those may change and are for internal use only
 */
enum rte_hash_sig_compare_function {
	RTE_HASH_COMPARE_SCALAR = 0,
	RTE_HASH_COMPARE_SSE,
	RTE_HASH_COMPARE_NEON,
	RTE_HASH_COMPARE_SVE,
	RTE_HASH_COMPARE_NUM
};

#endif

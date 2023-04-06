/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

/**
 * @file
 * Branch Prediction Helpers in RTE
 */

#ifndef _RTE_BRANCH_PREDICTION_H_
#define _RTE_BRANCH_PREDICTION_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check if a branch is likely to be taken.
 *
 * This compiler builtin allows the developer to indicate if a branch is
 * likely to be taken. Example:
 *
 *   if (likely(x > 1))
 *      do_stuff();
 *
 */
#ifndef likely
#ifndef RTE_TOOLCHAIN_MSVC
#define likely(x)	__builtin_expect(!!(x), 1)
#else
#define likely(x)	(x)
#endif
#endif /* likely */

/**
 * Check if a branch is unlikely to be taken.
 *
 * This compiler builtin allows the developer to indicate if a branch is
 * unlikely to be taken. Example:
 *
 *   if (unlikely(x < 1))
 *      do_stuff();
 *
 */
#ifndef unlikely
#ifndef RTE_TOOLCHAIN_MSVC
#define unlikely(x)	__builtin_expect(!!(x), 0)
#else
#define unlikely(x)	(x)
#endif
#endif /* unlikely */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_BRANCH_PREDICTION_H_ */

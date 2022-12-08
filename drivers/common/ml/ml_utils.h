/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#ifndef _ML_UTILS_H_
#define _ML_UTILS_H_

#include <rte_compat.h>
#include <rte_mldev.h>

/**
 * Get the size an ML IO type in bytes.
 *
 * @param[in] type
 *	Enumeration of ML IO data type.
 *
 * @return
 *	- > 0, Size of the data type in bytes.
 *	- < 0, Error code on failure.
 */
__rte_internal
int ml_io_type_size_get(enum rte_ml_io_type type);

/**
 * Get the name of an ML IO type.
 *
 * @param[in] type
 *	Enumeration of ML IO data type.
 * @param[in] str
 *	Address of character array.
 * @param[in] len
 *	Length of character array.
 */
__rte_internal
void ml_io_type_to_str(enum rte_ml_io_type type, char *str, int len);

/**
 * Get the name of an ML IO format.
 *
 * @param[in] type
 *	Enumeration of ML IO format.
 * @param[in] str
 *	Address of character array.
 * @param[in] len
 *	Length of character array.
 */
__rte_internal
void ml_io_format_to_str(enum rte_ml_io_format format, char *str, int len);

#endif /*_ML_UTILS_H_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef _RTE_ARG_PARSER_H_
#define _RTE_ARG_PARSER_H_

/**
 * @file
 *
 * RTE Argument Parsing API
 *
 * The argument parsing API is a collection of functions to help parse
 * command line arguments. The API takes a string input and will return
 * it to the user in a more usable format.
 * 
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_compat.h>


/**
 * Convert a string describing a list of core ids into an array of core ids.
 *
 * On success, the passed array is filled with the core ids present in the
 * list up to the "cores_len", and the length of the array is returned.
 * For example, passing a 1-3,6 "corelist" results in an array of [1, 2, 3, 6]
 * and would return 4.
 * 
 * Like the snprintf function for strings, if the length of the input array is
 * insufficient to hold the number of cores in the "corelist", the input array is
 * filled to capacity and the return value is the number of elements which would
 * be returned if the array had been big enough.
 * Function can also be called with a NULL array and 0 "cores_len" to find out
 * the "cores_len" required.
 *
 * @param corelist
 *   Input string describing a list of core ids.
 * @param cores
 *   An array where to store the core ids.
 *   Array can be NULL if "cores_len" is 0.
 * @param cores_len
 *   The length of the "cores" array.
 *   If the size is smaller than that needed to hold all cores from "corelist",
 *   only "cores_len" elements will be written to the array.
 * @return
 *   n: the number of unique cores present in "corelist".
 *   -1 if the string was invalid.
 *   NOTE: if n > "cores_len", then only "cores_len" elements in the "cores" array are valid.
 */
__rte_experimental
int
rte_parse_corelist(const char *corelist, uint16_t *cores, uint32_t cores_len);


#ifdef __cplusplus
}
#endif

#endif /* _RTE_ARG_PARSER_H_ */

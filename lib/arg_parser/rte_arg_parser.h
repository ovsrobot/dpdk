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
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_compat.h>


/**
 * Convert a string describing a list of core ids into an array of core ids.
 *
 * On success, the passed array is filled with the core ids present in the list up
 * to the "cores_len", and the number of unique cores present in the "corelist"
 * is returned.
 * For example, passing a 1-3,6 "corelist" results in an array of [1, 2, 3, 6]
 * and would return 4.
 *
 * NOTE: if the length of the input array is insufficient to hold the number of core ids
 * in "corelist" the input array is filled to capacity but the return value is the
 * number of elements which would have been written to the array, had enough space been
 * available. [This is similar to the behaviour of the snprintf function]. Because of
 * this, the number of core values in the "corelist" may be determined by calling the
 * function with a NULL array pointer and array length given as 0.
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
rte_arg_parse_corelist(const char *corelist, uint16_t *cores, uint32_t cores_len);

/**
 * Convert a string describing a bitmask of core ids into an array of core ids.
 *
 * On success, the passed array is filled with the core ids present in the
 * bitmask up to the "cores_len", and the number of unique cores present in the
 * "coremask" is returned.
 * For example, passing a 0xA "coremask" results in an array of [1, 3]
 * and would return 2.
 *
 * NOTE: if the length of the input array is insufficient to hold the number of core ids
 * in "coremask" the input array is filled to capacity but the return value is the
 * number of elements which would have been written to the array, had enough space been
 * available. [This is similar to the behaviour of the snprintf function]. Because of
 * this, the number of core values in the "coremask" may be determined by calling the
 * function with a NULL array pointer and array length given as 0.
 *
 * @param coremask
 *   A string containing a bitmask of core ids.
 * @param cores
 *   An array where to store the core ids.
 *   Array can be NULL if "cores_len" is 0.
 * @param cores_len
 *   The length of the "cores" array.
 *   If the size is smaller than that needed to hold all cores from "coremask",
 *   only "cores_len" elements will be written to the array.
 * @return
 *   n: the number of unique cores present in "coremask".
 *   -1 if the string was invalid.
 *   NOTE: if n > "cores_len", then only "cores_len" elements in the "cores" array are valid.
 */
__rte_experimental
int
rte_arg_parse_coremask(const char *coremask, uint16_t *cores, uint32_t cores_len);

/**
 * Use heuristics to determine if a string contains a coremask or a corelist.
 *
 * This function will check a series of conditions and return an int representing which
 * core type (mask or list) the string represents or UNKNOWN if the string is ambiguous.
 *
 * @param core_string
 *   A string describing the intended cores to be parsed
 * @return
 *   int representing the core type
 *   -1: error.
 *   0: coremask.
 *   1: corelist.
 *   2: unknown (ambiguous).
 */
__rte_experimental
int
rte_arg_parse_arg_type(const char *core_string);

/**
 * Convert a string describing either a corelist or coremask into an array of core ids.
 *
 * This function will fill the "cores" array up to "cores_len" with the core ids described
 * in the "core_string". The string can either describe a corelist or a coremask, and
 * will be parsed accordingly. The number of unique core ids in the string is then returned.
 * For example:
 * "1-4" is treated as a corelist and results in an array of [1,2,3,4] with 4 being returned
 * "0xA1" is treated as a coremask and results in an array of [0,5,7] with 3 being returned
 *
 * In the case of an ambiguous string, the function will use the default_type parameter to
 * decide.
 *
 * NOTE: if the length of the input array is insufficient to hold the number of core ids
 * in "core_string" the input array is filled to capacity but the return value is the
 * number of elements which would have been written to the array, had enough space been
 * available. [This is similar to the behaviour of the snprintf function]. Because of
 * this, the number of core values in the "core_string" may be determined by calling the
 * function with a NULL array pointer and array length given as 0.
 *
 * @param core_string
 *   A string describing the intended cores to be parsed.
 * @param cores
 *   An array where to store the core ids.
 *   Array can be NULL if "cores_len" is 0.
 * @param cores_len
 *   The length of the "cores" array.
 *   If the size is smaller than that needed to hold all cores from "core_string"
 * @param default_type
 *   How to treat ambiguous cases (e.g. '4' could be mask or list).
 *   0: mask.
 *   1: list.
 * @return
 *   n: the number of unique cores present in "core_string".
 *   -1 if the string was invalid.
 *   NOTE: if n > "cores_len", then only "cores_len" elements in the "cores" array are valid.
 */
__rte_experimental
int
rte_arg_parse_core_string(const char *core_string, uint16_t *cores, uint32_t cores_len,
		int default_type);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ARG_PARSER_H_ */

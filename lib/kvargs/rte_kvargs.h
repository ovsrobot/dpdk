/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2013 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 */

#ifndef _RTE_KVARGS_H_
#define _RTE_KVARGS_H_

/**
 * @file
 * RTE Argument parsing
 *
 * This module can be used to parse arguments whose format is
 * key1=value1,key2=value2,key3=value3,...
 *
 * The same key can appear several times with the same or a different
 * value. Indeed, the arguments are stored as a list of key/values
 * associations and not as a dictionary.
 *
 * This file provides some helpers that are especially used by virtual
 * ethernet devices at initialization for arguments parsing.
 */

#include <stdint.h>

#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of key/value associations */
#define RTE_KVARGS_MAX 32

/** separator character used between each pair */
#define RTE_KVARGS_PAIRS_DELIM	","

/** separator character used between key and value */
#define RTE_KVARGS_KV_DELIM	"="

/**
 * Callback prototype used by rte_kvargs_process().
 *
 * @param key
 *   The key to consider, it will not be NULL.
 * @param value
 *   The value corresponding to the key, it may be NULL (e.g. only with key)
 * @param opaque
 *   An opaque pointer coming from the caller.
 * @return
 *   - >=0 handle key success.
 *   - <0 on error.
 */
typedef int (*arg_handler_t)(const char *key, const char *value, void *opaque);

/** A key/value association */
struct rte_kvargs_pair {
	char *key;      /**< the name (key) of the association  */
	char *value;    /**< the value associated to that key */
};

/** Store a list of key/value associations */
struct rte_kvargs {
	char *str;      /**< copy of the argument string */
	unsigned count; /**< number of entries in the list */
	struct rte_kvargs_pair pairs[RTE_KVARGS_MAX]; /**< list of key/values */
};

/**
 * Allocate a rte_kvargs and store key/value associations from a string
 *
 * The function allocates and fills a rte_kvargs structure from a given
 * string whose format is key1=value1,key2=value2,...
 *
 * The structure can be freed with rte_kvargs_free().
 *
 * @param args
 *   The input string containing the key/value associations
 * @param valid_keys
 *   A list of valid keys (table of const char *, the last must be NULL).
 *   This argument is ignored if NULL
 *
 * @return
 *   - A pointer to an allocated rte_kvargs structure on success
 *   - NULL on error
 */
struct rte_kvargs *rte_kvargs_parse(const char *args,
		const char *const valid_keys[]);

/**
 * Allocate a rte_kvargs and store key/value associations from a string.
 * This version will consider any byte from valid_ends as a possible
 * terminating character, and will not parse beyond any of their occurrence.
 *
 * The function allocates and fills an rte_kvargs structure from a given
 * string whose format is key1=value1,key2=value2,...
 *
 * The structure can be freed with rte_kvargs_free().
 *
 * @param args
 *   The input string containing the key/value associations
 *
 * @param valid_keys
 *   A list of valid keys (table of const char *, the last must be NULL).
 *   This argument is ignored if NULL
 *
 * @param valid_ends
 *   Acceptable terminating characters.
 *   If NULL, the behavior is the same as ``rte_kvargs_parse``.
 *
 * @return
 *   - A pointer to an allocated rte_kvargs structure on success
 *   - NULL on error
 */
struct rte_kvargs *rte_kvargs_parse_delim(const char *args,
		const char *const valid_keys[],
		const char *valid_ends);

/**
 * Free a rte_kvargs structure
 *
 * Free a rte_kvargs structure previously allocated with
 * rte_kvargs_parse().
 *
 * @param kvlist
 *   The rte_kvargs structure. No error if NULL.
 */
void rte_kvargs_free(struct rte_kvargs *kvlist);

/**
 * Get the value associated with a given key.
 *
 * If multiple keys match, the value of the first one is returned.
 *
 * The memory returned is allocated as part of the rte_kvargs structure,
 * it must never be modified.
 *
 * @param kvlist
 *   A list of rte_kvargs pair of 'key=value'.
 * @param key
 *   The matching key.
 *
 * @return
 *   NULL if no key matches the input,
 *   a value associated with a matching key otherwise.
 */
const char *rte_kvargs_get(const struct rte_kvargs *kvlist, const char *key);

/**
 * Get the value associated with a given key and value.
 *
 * Find the first entry in the kvlist whose key and value match the
 * ones passed as argument.
 *
 * The memory returned is allocated as part of the rte_kvargs structure,
 * it must never be modified.
 *
 * @param kvlist
 *   A list of rte_kvargs pair of 'key=value'.
 * @param key
 *   The matching key. If NULL, any key will match.
 * @param value
 *   The matching value. If NULL, any value will match.
 *
 * @return
 *   NULL if no key matches the input,
 *   a value associated with a matching key otherwise.
 */
const char *rte_kvargs_get_with_value(const struct rte_kvargs *kvlist,
				      const char *key, const char *value);

/**
 * Call a handler function for each key=value matching the key
 *
 * For each key=value association that matches the given key, calls the
 * handler function with the for a given arg_name passing the value on the
 * dictionary for that key and a given extra argument.
 *
 * @note Compared to @see rte_kvargs_process_opt, this API will return -1
 * when handle only-key case (that is the matched key's value is NULL).
 *
 * @param kvlist
 *   The rte_kvargs structure.
 * @param key_match
 *   The key on which the handler should be called, or NULL to process handler
 *   on all associations
 * @param handler
 *   The function to call for each matching key
 * @param opaque_arg
 *   A pointer passed unchanged to the handler
 *
 * @return
 *   - 0 on success
 *   - Negative on error
 */
int rte_kvargs_process(const struct rte_kvargs *kvlist,
	const char *key_match, arg_handler_t handler, void *opaque_arg);

/**
 * Call a handler function for each key=value or only-key matching the key
 *
 * For each key=value or only-key association that matches the given key, calls
 * the handler function with the for a given arg_name passing the value on the
 * dictionary for that key and a given extra argument.
 *
 * @param kvlist
 *   The rte_kvargs structure.
 * @param key_match
 *   The key on which the handler should be called, or NULL to process handler
 *   on all associations
 * @param handler
 *   The function to call for each matching key
 * @param opaque_arg
 *   A pointer passed unchanged to the handler
 *
 * @return
 *   - 0 on success
 *   - Negative on error
 */
int rte_kvargs_process_opt(const struct rte_kvargs *kvlist,
	const char *key_match, arg_handler_t handler, void *opaque_arg);

/**
 * Count the number of associations matching the given key
 *
 * @param kvlist
 *   The rte_kvargs structure
 * @param key_match
 *   The key that should match, or NULL to count all associations
 *
 * @return
 *   The number of entries
 */
unsigned rte_kvargs_count(const struct rte_kvargs *kvlist,
	const char *key_match);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Handlers to convert a key/value pair into a numeric type.
 *
 * The functions below all match the ``arg_handler_t`` prototype, so they can
 * be passed directly to rte_kvargs_process():
 *
 * @code
 *   uint16_t nb_desc = DEFAULT_NB_DESC;
 *
 *   ret = rte_kvargs_process(kvlist, "nb_desc",
 *                            rte_kvargs_handle_u16, &nb_desc);
 * @endcode
 *
 * The value string is accepted only if it represents the whole number, that
 * is:
 *
 * - it is not NULL and not empty;
 * - it is decimal, or hexadecimal with a ``0x`` or ``0X`` prefix;
 * - it has no trailing characters other than white space;
 * - it does not overflow the target type.
 *
 * A leading ``+`` or ``-`` sign is accepted. The unsigned handlers reject a
 * negative value rather than wrapping it around, which is what strtoul()
 * would otherwise do.
 *
 * Note that a leading zero does @b not select octal, so ``010`` is ten and
 * not eight.
 *
 * @param key
 *   The key, used for error reporting only. May be NULL.
 * @param value
 *   The value to convert.
 * @param opaque
 *   Pointer to the variable to store the result into. The pointed-to type
 *   must match the handler: for example rte_kvargs_handle_u16() requires a
 *   ``uint16_t *``. On error the variable is left unmodified.
 *
 * @return
 *   - 0 on success.
 *   - -EINVAL if the value is missing or malformed, or if @p opaque is NULL.
 *   - -ERANGE if the value does not fit in the target type.
 */
__rte_experimental
int rte_kvargs_handle_u8(const char *key, const char *value, void *opaque);

/** Convert a value to uint16_t. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_u16(const char *key, const char *value, void *opaque);

/** Convert a value to uint32_t. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_u32(const char *key, const char *value, void *opaque);

/** Convert a value to uint64_t. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_u64(const char *key, const char *value, void *opaque);

/** Convert a value to int8_t. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_i8(const char *key, const char *value, void *opaque);

/** Convert a value to int16_t. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_i16(const char *key, const char *value, void *opaque);

/** Convert a value to int32_t. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_i32(const char *key, const char *value, void *opaque);

/** Convert a value to int64_t. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_i64(const char *key, const char *value, void *opaque);

/** Convert a value to unsigned int. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_uint(const char *key, const char *value, void *opaque);

/** Convert a value to int. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_int(const char *key, const char *value, void *opaque);

/** Convert a value to long. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_long(const char *key, const char *value, void *opaque);

/** Convert a value to unsigned long. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_ulong(const char *key, const char *value, void *opaque);

/** Convert a value to size_t. See rte_kvargs_handle_u8(). */
__rte_experimental
int rte_kvargs_handle_size(const char *key, const char *value, void *opaque);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Convert a bit mask to uint32_t.
 *
 * As rte_kvargs_handle_u32(), except that the value is always read as
 * hexadecimal, with or without a ``0x`` prefix, so ``10`` is sixteen. This
 * is for arguments documented as a bare hexadecimal mask; use
 * rte_kvargs_handle_u32() for a count or a size.
 */
__rte_experimental
int rte_kvargs_handle_hex32(const char *key, const char *value, void *opaque);

/** Convert a hexadecimal value to uint64_t. See rte_kvargs_handle_hex32(). */
__rte_experimental
int rte_kvargs_handle_hex64(const char *key, const char *value, void *opaque);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Convert a key/value pair to a boolean.
 *
 * Accepts, case insensitively, ``1``, ``y``, ``yes``, ``on`` and ``true``
 * for true; ``0``, ``n``, ``no``, ``off`` and ``false`` for false.
 *
 * A key given without a value, as in ``key``, is treated as true. Use
 * rte_kvargs_process_opt() rather than rte_kvargs_process() to support
 * that form, since the latter rejects a missing value before the handler
 * is called. An empty value, as in ``key=``, is rejected.
 *
 * @param key
 *   The key, used for error reporting only. May be NULL.
 * @param value
 *   The value to convert. NULL means true.
 * @param opaque
 *   Pointer to a ``bool`` to store the result into. On error it is left
 *   unmodified.
 *
 * @return
 *   - 0 on success.
 *   - -EINVAL if the value is malformed or if @p opaque is NULL.
 */
__rte_experimental
int rte_kvargs_handle_bool(const char *key, const char *value, void *opaque);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Convert a key/value pair to a NUMA socket id.
 *
 * Accepts -1, which is SOCKET_ID_ANY, through RTE_MAX_NUMA_NODES - 1.
 * The bound is the compile time maximum rather than the set of sockets
 * present on the running system, matching what drivers checked before
 * this helper existed.
 *
 * @param key
 *   The key, used for error reporting only. May be NULL.
 * @param value
 *   The value to convert.
 * @param opaque
 *   Pointer to an ``int`` to store the result into. On error it is left
 *   unmodified.
 *
 * @return
 *   - 0 on success.
 *   - -EINVAL if the value is malformed, or if @p opaque is NULL.
 *   - -ERANGE if the value is not a valid socket id.
 */
__rte_experimental
int rte_kvargs_handle_socket_id(const char *key, const char *value, void *opaque);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Convert a string to an unsigned integer, checking it against a range.
 *
 * This is the underlying conversion used by the rte_kvargs_handle_*()
 * unsigned handlers. It is meant for drivers which need a range narrower
 * than the target type, or which parse a value obtained from
 * rte_kvargs_get() rather than from a handler.
 *
 * @param value
 *   The string to convert. Must be non-NULL and non-empty. See
 *   rte_kvargs_handle_u8() for the accepted syntax.
 * @param min
 *   Smallest acceptable value, inclusive.
 * @param max
 *   Largest acceptable value, inclusive.
 * @param result
 *   Where to store the converted value. Left unmodified on error.
 *
 * @return
 *   - 0 on success.
 *   - -EINVAL if the value is missing or malformed, or if @p result is NULL.
 *   - -ERANGE if the value is outside [@p min, @p max].
 */
__rte_experimental
int rte_kvargs_to_uint(const char *value, uint64_t min, uint64_t max,
	uint64_t *result);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Convert a string to a signed integer, checking it against a range.
 *
 * This is the signed counterpart of rte_kvargs_to_uint().
 *
 * @param value
 *   The string to convert. Must be non-NULL and non-empty. See
 *   rte_kvargs_handle_u8() for the accepted syntax.
 * @param min
 *   Smallest acceptable value, inclusive.
 * @param max
 *   Largest acceptable value, inclusive.
 * @param result
 *   Where to store the converted value. Left unmodified on error.
 *
 * @return
 *   - 0 on success.
 *   - -EINVAL if the value is missing or malformed, or if @p result is NULL.
 *   - -ERANGE if the value is outside [@p min, @p max].
 */
__rte_experimental
int rte_kvargs_to_int(const char *value, int64_t min, int64_t max,
	int64_t *result);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Convert a hexadecimal string to an unsigned integer, checking it against
 * a maximum.
 *
 * This is the conversion underlying rte_kvargs_handle_hex32(), and is the
 * hexadecimal counterpart of rte_kvargs_to_uint(). The minimum is always
 * zero, since a negative value is rejected rather than wrapped around.
 *
 * @param value
 *   The string to convert. Must be non-NULL and non-empty.
 * @param max
 *   Largest acceptable value, inclusive.
 * @param result
 *   Where to store the converted value. Left unmodified on error.
 *
 * @return
 *   - 0 on success.
 *   - -EINVAL if the value is missing or malformed, or if @p result is NULL.
 *   - -ERANGE if the value is greater than @p max.
 */
__rte_experimental
int rte_kvargs_to_hex(const char *value, uint64_t max, uint64_t *result);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Range and result for rte_kvargs_handle_urange().
 */
struct rte_kvargs_urange {
	uint64_t min;	/**< Smallest acceptable value, inclusive. */
	uint64_t max;	/**< Largest acceptable value, inclusive. */
	uint64_t val;	/**< The result, written only on success. */
};

/** Range and result for rte_kvargs_handle_irange(). */
struct rte_kvargs_irange {
	int64_t min;	/**< Smallest acceptable value, inclusive. */
	int64_t max;	/**< Largest acceptable value, inclusive. */
	int64_t val;	/**< The result, written only on success. */
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Convert a key/value pair to an unsigned integer in a range.
 *
 * As rte_kvargs_handle_u8(), except that the bounds are given by the
 * caller rather than by the target type. This is for an argument whose
 * valid range is narrower than the type it is stored in.
 *
 * The bounds are passed and the result returned through the same
 * structure, since a handler has only one opaque pointer. Seed ``val``
 * with the default: it is left alone when the key is absent and when
 * the value is rejected.
 *
 * @param key
 *   The key, used for error reporting only. May be NULL.
 * @param value
 *   The value to convert.
 * @param opaque
 *   Pointer to a ``struct rte_kvargs_urange`` holding the range. On
 *   success its ``val`` is set, on error it is left unmodified.
 *
 * @return
 *   - 0 on success.
 *   - -EINVAL if the value is missing or malformed, or if @p opaque is NULL.
 *   - -ERANGE if the value is outside the range.
 */
__rte_experimental
int rte_kvargs_handle_urange(const char *key, const char *value, void *opaque);

/**
 * Convert a value to a signed integer in a range, taking a
 * ``struct rte_kvargs_irange``. See rte_kvargs_handle_urange().
 */
__rte_experimental
int rte_kvargs_handle_irange(const char *key, const char *value, void *opaque);

#ifdef __cplusplus
}
#endif

#endif

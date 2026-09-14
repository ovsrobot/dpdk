/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2013 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include <eal_export.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_os_shim.h>

#include "rte_kvargs.h"

RTE_LOG_REGISTER_DEFAULT(kvargs_logtype, INFO);
#define RTE_LOGTYPE_KVARGS kvargs_logtype

#define KVARGS_LOG(level, ...) \
	RTE_LOG_LINE(level, KVARGS, __VA_ARGS__)

/*
 * Receive a string with a list of arguments following the pattern
 * key=value,key=value,... and insert them into the list.
 * Params string will be copied to be modified.
 * list "[]" and list element splitter ",", "-" is treated as value.
 * Supported examples:
 *   k1=v1,k2=v2
 *   k1
 *   k1=x[0-1]y[1,3-5,9]z
 */
static int
rte_kvargs_tokenize(struct rte_kvargs *kvlist, const char *params)
{
	char *str, *start;
	bool in_list = false, end_key = false, end_value = false;
	bool save = false, end_pair = false;

	/* Copy the const char *params to a modifiable string
	 * to pass to rte_strsplit
	 */
	kvlist->str = strdup(params);
	if (kvlist->str == NULL)
		return -1;

	/* browse each key/value pair and add it in kvlist */
	str = kvlist->str;
	start = str; /* start of current key or value */
	while (1) {
		switch (*str) {
		case '=': /* End of key. */
			end_key = true;
			save = true;
			break;
		case ',':
			/* End of value, skip comma in middle of range */
			if (!in_list) {
				if (end_key)
					end_value = true;
				else
					end_key = true;
				save = true;
				end_pair = true;
			}
			break;
		case '[': /* Start of list. */
			in_list = true;
			break;
		case ']': /* End of list.  */
			if (in_list)
				in_list = false;
			break;
		case '\0': /* End of string */
			if (end_key)
				end_value = true;
			else
				end_key = true;
			save = true;
			end_pair = true;
			break;
		default:
			break;
		}

		if (!save) {
			/* Continue if not end of key or value. */
			str++;
			continue;
		}

		if (kvlist->count >= RTE_KVARGS_MAX)
			return -1;

		if (end_value)
			/* Value parsed */
			kvlist->pairs[kvlist->count].value = start;
		else if (end_key)
			/* Key parsed. */
			kvlist->pairs[kvlist->count].key = start;

		if (end_pair) {
			if (end_value || str != start)
				/* Ignore empty pair. */
				kvlist->count++;
			end_key = false;
			end_value = false;
			end_pair = false;
		}

		if (*str == '\0') /* End of string. */
			break;
		*str = '\0';
		str++;
		start = str;
		save = false;
	}

	return 0;
}

/*
 * Determine whether a key is valid or not by looking
 * into a list of valid keys.
 */
static int
is_valid_key(const char * const valid[], const char *key_match)
{
	const char * const *valid_ptr;

	for (valid_ptr = valid; *valid_ptr != NULL; valid_ptr++) {
		if (strcmp(key_match, *valid_ptr) == 0)
			return 1;
	}
	return 0;
}

/*
 * Determine whether all keys are valid or not by looking
 * into a list of valid keys.
 */
static int
check_for_valid_keys(struct rte_kvargs *kvlist,
		const char * const valid[])
{
	unsigned i, ret;
	struct rte_kvargs_pair *pair;

	for (i = 0; i < kvlist->count; i++) {
		pair = &kvlist->pairs[i];
		ret = is_valid_key(valid, pair->key);
		if (!ret)
			return -1;
	}
	return 0;
}

/*
 * Return the number of times a given arg_name exists in the key/value list.
 * E.g. given a list = { rx = 0, rx = 1, tx = 2 } the number of args for
 * arg "rx" will be 2.
 */
RTE_EXPORT_SYMBOL(rte_kvargs_count)
unsigned
rte_kvargs_count(const struct rte_kvargs *kvlist, const char *key_match)
{
	const struct rte_kvargs_pair *pair;
	unsigned i, ret;

	ret = 0;
	for (i = 0; i < kvlist->count; i++) {
		pair = &kvlist->pairs[i];
		if (key_match == NULL || strcmp(pair->key, key_match) == 0)
			ret++;
	}

	return ret;
}

static int
kvargs_process_common(const struct rte_kvargs *kvlist, const char *key_match,
		      arg_handler_t handler, void *opaque_arg, bool support_only_key)
{
	const struct rte_kvargs_pair *pair;
	unsigned i;

	if (kvlist == NULL)
		return -1;

	for (i = 0; i < kvlist->count; i++) {
		pair = &kvlist->pairs[i];
		if (key_match == NULL || strcmp(pair->key, key_match) == 0) {
			if (!support_only_key && pair->value == NULL)
				return -1;
			if ((*handler)(pair->key, pair->value, opaque_arg) < 0)
				return -1;
		}
	}

	return 0;
}

/*
 * For each matching key in key=value, call the given handler function.
 */
RTE_EXPORT_SYMBOL(rte_kvargs_process)
int
rte_kvargs_process(const struct rte_kvargs *kvlist, const char *key_match, arg_handler_t handler,
		   void *opaque_arg)
{
	return kvargs_process_common(kvlist, key_match, handler, opaque_arg, false);
}

/*
 * For each matching key in key=value or only-key, call the given handler function.
 */
RTE_EXPORT_SYMBOL(rte_kvargs_process_opt)
int
rte_kvargs_process_opt(const struct rte_kvargs *kvlist, const char *key_match,
		       arg_handler_t handler, void *opaque_arg)
{
	return kvargs_process_common(kvlist, key_match, handler, opaque_arg, true);
}

/* free the rte_kvargs structure */
RTE_EXPORT_SYMBOL(rte_kvargs_free)
void
rte_kvargs_free(struct rte_kvargs *kvlist)
{
	if (!kvlist)
		return;

	free(kvlist->str);
	free(kvlist);
}

/* Lookup a value in an rte_kvargs list by its key and value. */
RTE_EXPORT_SYMBOL(rte_kvargs_get_with_value)
const char *
rte_kvargs_get_with_value(const struct rte_kvargs *kvlist, const char *key,
			  const char *value)
{
	unsigned int i;

	if (kvlist == NULL)
		return NULL;
	for (i = 0; i < kvlist->count; ++i) {
		if (key != NULL && strcmp(kvlist->pairs[i].key, key) != 0)
			continue;
		if (value != NULL && strcmp(kvlist->pairs[i].value, value) != 0)
			continue;
		return kvlist->pairs[i].value;
	}
	return NULL;
}

/* Lookup a value in an rte_kvargs list by its key. */
RTE_EXPORT_SYMBOL(rte_kvargs_get)
const char *
rte_kvargs_get(const struct rte_kvargs *kvlist, const char *key)
{
	if (kvlist == NULL || key == NULL)
		return NULL;
	return rte_kvargs_get_with_value(kvlist, key, NULL);
}

/*
 * Parse the arguments "key=value,key=value,..." string and return
 * an allocated structure that contains a key/value list. Also
 * check if only valid keys were used.
 */
RTE_EXPORT_SYMBOL(rte_kvargs_parse)
struct rte_kvargs *
rte_kvargs_parse(const char *args, const char * const valid_keys[])
{
	struct rte_kvargs *kvlist;

	kvlist = malloc(sizeof(*kvlist));
	if (kvlist == NULL)
		return NULL;
	memset(kvlist, 0, sizeof(*kvlist));

	if (rte_kvargs_tokenize(kvlist, args) < 0) {
		rte_kvargs_free(kvlist);
		return NULL;
	}

	if (valid_keys != NULL && check_for_valid_keys(kvlist, valid_keys) < 0) {
		rte_kvargs_free(kvlist);
		return NULL;
	}

	return kvlist;
}

RTE_EXPORT_SYMBOL(rte_kvargs_parse_delim)
struct rte_kvargs *
rte_kvargs_parse_delim(const char *args, const char * const valid_keys[],
		       const char *valid_ends)
{
	struct rte_kvargs *kvlist = NULL;
	char *copy;
	size_t len;

	if (valid_ends == NULL)
		return rte_kvargs_parse(args, valid_keys);

	copy = strdup(args);
	if (copy == NULL)
		return NULL;

	len = strcspn(copy, valid_ends);
	copy[len] = '\0';

	kvlist = rte_kvargs_parse(copy, valid_keys);

	free(copy);
	return kvlist;
}

/*
 * Determine the base of a numeric value and skip over its prefix.
 *
 * Only decimal and 0x/0X hexadecimal are recognized. Octal is deliberately
 * not supported: no driver documents it, and silently reading "010" as eight
 * has been a recurring source of surprise.
 *
 * Returns the base, and advances *str past the "0x" prefix if there is one.
 * Returns 0 if what follows the prefix is a second one: strtoull() would
 * strip that itself, making "0x0x10" sixteen rather than the garbage it is.
 */
static int
kvargs_get_base(const char **str)
{
	const char *s = *str;

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X') &&
	    isxdigit((unsigned char)s[2])) {
		s += 2;
		if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
			return 0;
		*str = s;
		return 16;
	}

	return 10;
}

/* Skip trailing white space, and tell whether anything else is left. */
static bool
kvargs_at_end(const char *str)
{
	while (isspace((unsigned char)*str))
		str++;

	return *str == '\0';
}

/*
 * Consume an optional sign, and report whether it was negative.
 *
 * strtoull() skips white space and a sign of its own, and negates on '-',
 * so the sign has to be taken away from it: it is handled here and anything
 * that follows must be a digit or an 0x prefix. That rejects "+-1" and
 * "- 1", which strtoull() would otherwise accept.
 */
static bool
kvargs_get_sign(const char **str)
{
	const char *s = *str;
	bool negative;

	while (isspace((unsigned char)*s))
		s++;

	negative = (*s == '-');
	if (*s == '-' || *s == '+')
		s++;

	*str = s;
	return negative;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_to_uint, 26.11)
int
rte_kvargs_to_uint(const char *value, uint64_t min, uint64_t max,
		   uint64_t *result)
{
	const char *str = value;
	unsigned long long val;
	char *endptr;
	int base;

	if (str == NULL || result == NULL)
		return -EINVAL;

	/* "-1" would otherwise be silently wrapped around to UINT64_MAX. */
	if (kvargs_get_sign(&str))
		return -EINVAL;

	base = kvargs_get_base(&str);
	if (base == 0)
		return -EINVAL;	/* doubled 0x prefix */

	/* Nothing may sit between the sign and the digits. */
	if (!isxdigit((unsigned char)*str))
		return -EINVAL;

	errno = 0;
	val = strtoull(str, &endptr, base);
	if (endptr == str)
		return -EINVAL;	/* no digits in this base */
	if (errno == ERANGE)
		return -ERANGE;
	if (errno != 0)
		return -EINVAL;
	if (!kvargs_at_end(endptr))
		return -EINVAL;	/* trailing garbage */

	if (val < min || val > max)
		return -ERANGE;

	*result = val;
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_to_int, 26.11)
int
rte_kvargs_to_int(const char *value, int64_t min, int64_t max, int64_t *result)
{
	const char *str = value;
	unsigned long long mag;
	char *endptr;
	bool negative;
	int64_t val;
	int base;

	if (str == NULL || result == NULL)
		return -EINVAL;

	negative = kvargs_get_sign(&str);
	base = kvargs_get_base(&str);
	if (base == 0)
		return -EINVAL;	/* doubled 0x prefix */

	/* Nothing may sit between the sign and the digits. */
	if (!isxdigit((unsigned char)*str))
		return -EINVAL;

	/*
	 * The sign is consumed above, so that the 0x prefix can be found
	 * behind it, and the magnitude is parsed unsigned. Letting strtoll()
	 * do the whole job instead would reject INT64_MIN, whose magnitude is
	 * one past INT64_MAX.
	 */
	errno = 0;
	mag = strtoull(str, &endptr, base);
	if (endptr == str)
		return -EINVAL;
	if (errno == ERANGE)
		return -ERANGE;
	if (errno != 0)
		return -EINVAL;
	if (!kvargs_at_end(endptr))
		return -EINVAL;

	if (negative) {
		if (mag > (unsigned long long)INT64_MAX + 1)
			return -ERANGE;
		/* Negate in unsigned space; -INT64_MIN would overflow. */
		val = (int64_t)(-(uint64_t)mag);
	} else {
		if (mag > INT64_MAX)
			return -ERANGE;
		val = (int64_t)mag;
	}

	if (val < min || val > max)
		return -ERANGE;

	*result = val;
	return 0;
}

/*
 * The typed handlers below share this shape: convert with a range matching
 * the target type, then store. The target is written only on success, so a
 * caller-supplied default survives a bad argument.
 */
static int
kvargs_store_uint(const char *key, const char *value, void *opaque,
		  uint64_t max, uint64_t *val)
{
	int ret;

	if (opaque == NULL)
		return -EINVAL;

	ret = rte_kvargs_to_uint(value, 0, max, val);
	if (ret < 0)
		KVARGS_LOG(ERR, "invalid value \"%s\" for key \"%s\", expected 0..%" PRIu64,
			   value != NULL ? value : "", key != NULL ? key : "", max);

	return ret;
}

static int
kvargs_store_int(const char *key, const char *value, void *opaque,
		 int64_t min, int64_t max, int64_t *val)
{
	int ret;

	if (opaque == NULL)
		return -EINVAL;

	ret = rte_kvargs_to_int(value, min, max, val);
	if (ret < 0)
		KVARGS_LOG(ERR, "invalid value \"%s\" for key \"%s\", expected %" PRId64 "..%" PRId64,
			   value != NULL ? value : "", key != NULL ? key : "",
			   min, max);

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_u8, 26.11)
int
rte_kvargs_handle_u8(const char *key, const char *value, void *opaque)
{
	uint64_t val;
	int ret;

	ret = kvargs_store_uint(key, value, opaque, UINT8_MAX, &val);
	if (ret == 0)
		*(uint8_t *)opaque = (uint8_t)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_u16, 26.11)
int
rte_kvargs_handle_u16(const char *key, const char *value, void *opaque)
{
	uint64_t val;
	int ret;

	ret = kvargs_store_uint(key, value, opaque, UINT16_MAX, &val);
	if (ret == 0)
		*(uint16_t *)opaque = (uint16_t)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_u32, 26.11)
int
rte_kvargs_handle_u32(const char *key, const char *value, void *opaque)
{
	uint64_t val;
	int ret;

	ret = kvargs_store_uint(key, value, opaque, UINT32_MAX, &val);
	if (ret == 0)
		*(uint32_t *)opaque = (uint32_t)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_u64, 26.11)
int
rte_kvargs_handle_u64(const char *key, const char *value, void *opaque)
{
	uint64_t val;
	int ret;

	ret = kvargs_store_uint(key, value, opaque, UINT64_MAX, &val);
	if (ret == 0)
		*(uint64_t *)opaque = (uint64_t)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_uint, 26.11)
int
rte_kvargs_handle_uint(const char *key, const char *value, void *opaque)
{
	uint64_t val;
	int ret;

	ret = kvargs_store_uint(key, value, opaque, UINT_MAX, &val);
	if (ret == 0)
		*(unsigned int *)opaque = (unsigned int)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_size, 26.11)
int
rte_kvargs_handle_size(const char *key, const char *value, void *opaque)
{
	uint64_t val;
	int ret;

	ret = kvargs_store_uint(key, value, opaque, SIZE_MAX, &val);
	if (ret == 0)
		*(size_t *)opaque = (size_t)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_i8, 26.11)
int
rte_kvargs_handle_i8(const char *key, const char *value, void *opaque)
{
	int64_t val;
	int ret;

	ret = kvargs_store_int(key, value, opaque, INT8_MIN, INT8_MAX, &val);
	if (ret == 0)
		*(int8_t *)opaque = (int8_t)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_i16, 26.11)
int
rte_kvargs_handle_i16(const char *key, const char *value, void *opaque)
{
	int64_t val;
	int ret;

	ret = kvargs_store_int(key, value, opaque, INT16_MIN, INT16_MAX, &val);
	if (ret == 0)
		*(int16_t *)opaque = (int16_t)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_i32, 26.11)
int
rte_kvargs_handle_i32(const char *key, const char *value, void *opaque)
{
	int64_t val;
	int ret;

	ret = kvargs_store_int(key, value, opaque, INT32_MIN, INT32_MAX, &val);
	if (ret == 0)
		*(int32_t *)opaque = (int32_t)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_i64, 26.11)
int
rte_kvargs_handle_i64(const char *key, const char *value, void *opaque)
{
	int64_t val;
	int ret;

	ret = kvargs_store_int(key, value, opaque, INT64_MIN, INT64_MAX, &val);
	if (ret == 0)
		*(int64_t *)opaque = (int64_t)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_int, 26.11)
int
rte_kvargs_handle_int(const char *key, const char *value, void *opaque)
{
	int64_t val;
	int ret;

	ret = kvargs_store_int(key, value, opaque, INT_MIN, INT_MAX, &val);
	if (ret == 0)
		*(int *)opaque = (int)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_long, 26.11)
int
rte_kvargs_handle_long(const char *key, const char *value, void *opaque)
{
	int64_t val;
	int ret;

	ret = kvargs_store_int(key, value, opaque, LONG_MIN, LONG_MAX, &val);
	if (ret == 0)
		*(long *)opaque = (long)val;

	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_ulong, 26.11)
int
rte_kvargs_handle_ulong(const char *key, const char *value, void *opaque)
{
	uint64_t val;
	int ret;

	ret = kvargs_store_uint(key, value, opaque, ULONG_MAX, &val);
	if (ret == 0)
		*(unsigned long *)opaque = (unsigned long)val;

	return ret;
}

static const char * const kvargs_true[] = { "1", "y", "yes", "on", "true" };
static const char * const kvargs_false[] = { "0", "n", "no", "off", "false" };

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_bool, 26.11)
int
rte_kvargs_handle_bool(const char *key, const char *value, void *opaque)
{
	unsigned int i;

	if (opaque == NULL)
		return -EINVAL;

	/* A bare key means true; only rte_kvargs_process_opt() allows it.
	 * An empty value is a blank value, not a missing one, so it is
	 * rejected below.
	 */
	if (value == NULL) {
		*(bool *)opaque = true;
		return 0;
	}

	for (i = 0; i < RTE_DIM(kvargs_true); i++) {
		if (strcasecmp(value, kvargs_true[i]) == 0) {
			*(bool *)opaque = true;
			return 0;
		}
	}

	for (i = 0; i < RTE_DIM(kvargs_false); i++) {
		if (strcasecmp(value, kvargs_false[i]) == 0) {
			*(bool *)opaque = false;
			return 0;
		}
	}

	KVARGS_LOG(ERR, "invalid value \"%s\" for key \"%s\", expected a boolean",
		   value, key != NULL ? key : "");

	return -EINVAL;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_kvargs_handle_socket_id, 26.11)
int
rte_kvargs_handle_socket_id(const char *key, const char *value, void *opaque)
{
	int64_t val;
	int ret;

	/* SOCKET_ID_ANY, which is -1, is a valid socket id. It is spelled
	 * out here rather than included from EAL, which kvargs sits below.
	 */
	ret = kvargs_store_int(key, value, opaque, -1,
			       RTE_MAX_NUMA_NODES - 1, &val);
	if (ret == 0)
		*(int *)opaque = (int)val;

	return ret;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <errno.h>
#include <stdlib.h>

#undef RTE_USE_LIBBSD
#include <stdbool.h>

#include <rte_function_versioning.h>
#include <rte_string_fns.h>

#include "telemetry_data.h"

int
rte_tel_data_start_array(struct rte_tel_data *d, enum rte_tel_value_type type)
{
	enum tel_container_types array_types[] = {
			[RTE_TEL_STRING_VAL] = TEL_ARRAY_STRING,
			[RTE_TEL_INT_VAL] = TEL_ARRAY_INT,
			[RTE_TEL_UINT_VAL] = TEL_ARRAY_UINT,
			[RTE_TEL_CONTAINER] = TEL_ARRAY_CONTAINER,
	};
	d->type = array_types[type];
	d->data_len = 0;
	return 0;
}

int
rte_tel_data_start_dict(struct rte_tel_data *d)
{
	d->type = TEL_DICT;
	d->data_len = 0;
	return 0;
}

int
rte_tel_data_string(struct rte_tel_data *d, const char *str)
{
	d->type = TEL_STRING;
	d->data_len = strlcpy(d->data.str, str, sizeof(d->data.str));
	if (d->data_len >= RTE_TEL_MAX_SINGLE_STRING_LEN) {
		d->data_len = RTE_TEL_MAX_SINGLE_STRING_LEN - 1;
		return E2BIG; /* not necessarily and error, just truncation */
	}
	return 0;
}

int
rte_tel_data_add_array_string(struct rte_tel_data *d, const char *str)
{
	if (d->type != TEL_ARRAY_STRING)
		return -EINVAL;
	if (d->data_len >= RTE_TEL_MAX_ARRAY_ENTRIES)
		return -ENOSPC;
	const size_t bytes = strlcpy(d->data.array[d->data_len++].sval,
			str, RTE_TEL_MAX_STRING_LEN);
	return bytes < RTE_TEL_MAX_STRING_LEN ? 0 : E2BIG;
}

int __vsym
rte_tel_data_add_array_int_v24(struct rte_tel_data *d, int64_t x)
{
	if (d->type != TEL_ARRAY_INT)
		return -EINVAL;
	if (d->data_len >= RTE_TEL_MAX_ARRAY_ENTRIES)
		return -ENOSPC;
	d->data.array[d->data_len++].ival = x;
	return 0;
}

int __vsym
rte_tel_data_add_array_int_v23(struct rte_tel_data *d, int x)
{
	return rte_tel_data_add_array_int_v24(d, x);
}

/* mark the v23 function as the older version, and v24 as the default version */
VERSION_SYMBOL(rte_tel_data_add_array_int, _v23, 23);
BIND_DEFAULT_SYMBOL(rte_tel_data_add_array_int, _v24, 24);
MAP_STATIC_SYMBOL(int rte_tel_data_add_array_int(struct rte_tel_data *d,
		int64_t x), rte_tel_data_add_array_int_v24);

int
rte_tel_data_add_array_uint(struct rte_tel_data *d, uint64_t x)
{
	if (d->type != TEL_ARRAY_UINT)
		return -EINVAL;
	if (d->data_len >= RTE_TEL_MAX_ARRAY_ENTRIES)
		return -ENOSPC;
	d->data.array[d->data_len++].uval = x;
	return 0;
}

int
rte_tel_data_add_array_u64(struct rte_tel_data *d, uint64_t x)
{
	return rte_tel_data_add_array_uint(d, x);
}

int
rte_tel_data_add_array_container(struct rte_tel_data *d,
		struct rte_tel_data *val, int keep)
{
	if (d->type != TEL_ARRAY_CONTAINER ||
			(val->type != TEL_ARRAY_UINT
			&& val->type != TEL_ARRAY_INT
			&& val->type != TEL_ARRAY_STRING))
		return -EINVAL;
	if (d->data_len >= RTE_TEL_MAX_ARRAY_ENTRIES)
		return -ENOSPC;

	d->data.array[d->data_len].container.data = val;
	d->data.array[d->data_len++].container.keep = !!keep;
	return 0;
}

static bool
valid_name(const char *name)
{
	char allowed[128] = {
			['0' ... '9'] = 1,
			['A' ... 'Z'] = 1,
			['a' ... 'z'] = 1,
			['_'] = 1,
			['/'] = 1,
	};
	while (*name != '\0') {
		if ((size_t)*name >= RTE_DIM(allowed) || allowed[(int)*name] == 0)
			return false;
		name++;
	}
	return true;
}

int
rte_tel_data_add_dict_string(struct rte_tel_data *d, const char *name,
		const char *val)
{
	struct tel_dict_entry *e = &d->data.dict[d->data_len];
	size_t nbytes, vbytes;

	if (d->type != TEL_DICT)
		return -EINVAL;
	if (d->data_len >= RTE_TEL_MAX_DICT_ENTRIES)
		return -ENOSPC;

	if (!valid_name(name))
		return -EINVAL;

	d->data_len++;
	e->type = RTE_TEL_STRING_VAL;
	vbytes = strlcpy(e->value.sval, val, RTE_TEL_MAX_STRING_LEN);
	nbytes = strlcpy(e->name, name, RTE_TEL_MAX_STRING_LEN);
	if (vbytes >= RTE_TEL_MAX_STRING_LEN ||
			nbytes >= RTE_TEL_MAX_STRING_LEN)
		return E2BIG;
	return 0;
}

int __vsym
rte_tel_data_add_dict_int_v24(struct rte_tel_data *d, const char *name, int64_t val)
{
	struct tel_dict_entry *e = &d->data.dict[d->data_len];
	if (d->type != TEL_DICT)
		return -EINVAL;
	if (d->data_len >= RTE_TEL_MAX_DICT_ENTRIES)
		return -ENOSPC;

	if (!valid_name(name))
		return -EINVAL;

	d->data_len++;
	e->type = RTE_TEL_INT_VAL;
	e->value.ival = val;
	const size_t bytes = strlcpy(e->name, name, RTE_TEL_MAX_STRING_LEN);
	return bytes < RTE_TEL_MAX_STRING_LEN ? 0 : E2BIG;
}

int __vsym
rte_tel_data_add_dict_int_v23(struct rte_tel_data *d, const char *name, int val)
{
	return rte_tel_data_add_dict_int_v24(d, name, val);
}

/* mark the v23 function as the older version, and v24 as the default version */
VERSION_SYMBOL(rte_tel_data_add_dict_int, _v23, 23);
BIND_DEFAULT_SYMBOL(rte_tel_data_add_dict_int, _v24, 24);
MAP_STATIC_SYMBOL(int rte_tel_data_add_dict_int(struct rte_tel_data *d,
		const char *name, int64_t val), rte_tel_data_add_dict_int_v24);

int
rte_tel_data_add_dict_uint(struct rte_tel_data *d,
		const char *name, uint64_t val)
{
	struct tel_dict_entry *e = &d->data.dict[d->data_len];
	if (d->type != TEL_DICT)
		return -EINVAL;
	if (d->data_len >= RTE_TEL_MAX_DICT_ENTRIES)
		return -ENOSPC;

	if (!valid_name(name))
		return -EINVAL;

	d->data_len++;
	e->type = RTE_TEL_UINT_VAL;
	e->value.uval = val;
	const size_t bytes = strlcpy(e->name, name, RTE_TEL_MAX_STRING_LEN);
	return bytes < RTE_TEL_MAX_STRING_LEN ? 0 : E2BIG;
}

int
rte_tel_data_add_dict_u64(struct rte_tel_data *d, const char *name, uint64_t val)
{
	return rte_tel_data_add_dict_uint(d, name, val);
}

int
rte_tel_data_add_dict_container(struct rte_tel_data *d, const char *name,
		struct rte_tel_data *val, int keep)
{
	struct tel_dict_entry *e = &d->data.dict[d->data_len];

	if (d->type != TEL_DICT || (val->type != TEL_ARRAY_UINT
			&& val->type != TEL_ARRAY_INT
			&& val->type != TEL_ARRAY_STRING
			&& val->type != TEL_DICT))
		return -EINVAL;
	if (d->data_len >= RTE_TEL_MAX_DICT_ENTRIES)
		return -ENOSPC;

	if (!valid_name(name))
		return -EINVAL;

	d->data_len++;
	e->type = RTE_TEL_CONTAINER;
	e->value.container.data = val;
	e->value.container.keep = !!keep;
	const size_t bytes = strlcpy(e->name, name, RTE_TEL_MAX_STRING_LEN);
	return bytes < RTE_TEL_MAX_STRING_LEN ? 0 : E2BIG;
}

struct rte_tel_data *
rte_tel_data_alloc(void)
{
	return malloc(sizeof(struct rte_tel_data));
}

void
rte_tel_data_free(struct rte_tel_data *data)
{
	free(data);
}

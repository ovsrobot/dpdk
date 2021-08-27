/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_telemetry.h>

#include <roc_api.h>

#include "cnxk_mempool.h"
#include "cnxk_telemetry.h"

static void
mempool_list_cb(struct rte_mempool *mp, void *arg)
{
	struct rte_tel_data *d = (struct rte_tel_data *)arg;

	rte_tel_data_add_array_string(d, mp->name);
}

static int
mempool_tel_handle_list(const char *cmd __rte_unused,
			const char *params __rte_unused, struct rte_tel_data *d)
{
	rte_tel_data_start_array(d, RTE_TEL_STRING_VAL);
	rte_mempool_walk(mempool_list_cb, d);
	return 0;
}

struct mempool_info_cb_arg {
	char *pool_name;
	struct rte_tel_data *d;
};

static void
mempool_info_cb(struct rte_mempool *mp, void *arg)
{
	struct mempool_info_cb_arg *info = (struct mempool_info_cb_arg *)arg;
	const struct rte_memzone *mz;
	int aura_id;

	if (strncmp(mp->name, info->pool_name, RTE_MEMZONE_NAMESIZE))
		return;

	CNXK_TEL_DICT_STR(info->d, mp, name);
	CNXK_TEL_DICT_INT(info->d, mp, pool_id);
	CNXK_TEL_DICT_INT(info->d, mp, flags);
	CNXK_TEL_DICT_INT(info->d, mp, socket_id);
	CNXK_TEL_DICT_INT(info->d, mp, size);
	CNXK_TEL_DICT_INT(info->d, mp, cache_size);
	CNXK_TEL_DICT_INT(info->d, mp, elt_size);
	CNXK_TEL_DICT_INT(info->d, mp, header_size);
	CNXK_TEL_DICT_INT(info->d, mp, trailer_size);
	CNXK_TEL_DICT_INT(info->d, mp, private_data_size);
	CNXK_TEL_DICT_INT(info->d, mp, ops_index);
	CNXK_TEL_DICT_INT(info->d, mp, populated_size);

	aura_id = roc_npa_aura_handle_to_aura(mp->pool_id);
	rte_tel_data_add_dict_int(info->d, "aura_id", aura_id);

	mz = mp->mz;
	CNXK_TEL_DICT_STR(info->d, mz, name, mz_);
	CNXK_TEL_DICT_PTR(info->d, mz, iova, mz_);
	CNXK_TEL_DICT_PTR(info->d, mz, addr, mz_);
	CNXK_TEL_DICT_INT(info->d, mz, len, mz_);
	CNXK_TEL_DICT_U64(info->d, mz, hugepage_sz, mz_);
	CNXK_TEL_DICT_INT(info->d, mz, socket_id, mz_);
	CNXK_TEL_DICT_INT(info->d, mz, flags, mz_);
}

static int
mempool_tel_handle_info(const char *cmd __rte_unused, const char *params,
			struct rte_tel_data *d)
{
	struct mempool_info_cb_arg mp_arg;
	char name[RTE_MEMZONE_NAMESIZE];

	if (params == NULL || strlen(params) == 0)
		return -1;

	rte_strlcpy(name, params, RTE_MEMZONE_NAMESIZE);

	rte_tel_data_start_dict(d);
	mp_arg.pool_name = name;
	mp_arg.d = d;
	rte_mempool_walk(mempool_info_cb, &mp_arg);

	return 0;
}

RTE_INIT(cnxk_mempool_init_telemetry)
{
	rte_telemetry_register_cmd(
		"/cnxk/mempool/list", mempool_tel_handle_list,
		"Returns list of available mempools. Takes no parameters");
	rte_telemetry_register_cmd(
		"/cnxk/mempool/info", mempool_tel_handle_info,
		"Returns mempool info. Parameters: pool_name");
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_mbuf.h>

#include "mempool_priv.h"
#include "module_api.h"

static const char
cmd_mempool_help[] = "mempool <mempool_name> size <mbuf_size> buffers <number_of_buffers> "
		     "cache <cache_size> numa <numa_id>";

struct mempools mpconfig;

int
mempool_process(struct mempool_config *config)
{
	struct rte_mempool *mp;
	uint8_t nb_pools;

	nb_pools = mpconfig.nb_pools;
	strcpy(mpconfig.config[nb_pools].name, config->name);
	mpconfig.config[nb_pools].pool_size = config->pool_size;
	mpconfig.config[nb_pools].buffer_size = config->buffer_size;
	mpconfig.config[nb_pools].cache_size = config->cache_size;
	mpconfig.config[nb_pools].numa_node = config->numa_node;

	mp = rte_pktmbuf_pool_create(config->name, config->pool_size, config->cache_size,
		64, config->buffer_size, config->numa_node);
	if (!mp)
		return -EINVAL;

	mpconfig.mp[nb_pools] = mp;
	nb_pools++;
	mpconfig.nb_pools = nb_pools;

	return 0;
}

static int
cli_mempool_help(char **tokens __rte_unused, uint32_t n_tokens __rte_unused, char *out,
		 size_t out_size, void *obj __rte_unused)
{
	size_t len;

	len = strlen(out);
	snprintf(out + len, out_size, "\n%s\n",
		 "---------------------------- mempool command help ----------------------------");

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_mempool_help);
	return 0;
}

static int
cli_mempool(char **tokens, uint32_t n_tokens, char *out, size_t out_size, void *obj __rte_unused)
{
	uint32_t pkt_buffer_size, pool_size, cache_size, numa_node;
	struct mempool_config config;
	int rc = -EINVAL;

	if (n_tokens != 10) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		goto exit;
	}

	if (strcmp(tokens[2], "size")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "size");
		goto exit;
	}

	if (parser_uint32_read(&pkt_buffer_size, tokens[3])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "mbuf_size");
		goto exit;
	}

	if (strcmp(tokens[4], "buffers")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "buffers");
		goto exit;
	}

	if (parser_uint32_read(&pool_size, tokens[5])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "number_of_buffers");
		goto exit;
	}

	if (strcmp(tokens[6], "cache")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "cache");
		goto exit;
	}

	if (parser_uint32_read(&cache_size, tokens[7])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "cache_size");
		goto exit;
	}

	if (strcmp(tokens[8], "numa")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "numa");
		goto exit;
	}

	if (parser_uint32_read(&numa_node, tokens[9])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "numa_id");
		goto exit;
	}

	strcpy(config.name, tokens[1]);
	config.name[strlen(tokens[1])] = '\0';
	config.pool_size = pool_size;
	config.buffer_size = pkt_buffer_size;
	config.cache_size = cache_size;
	config.numa_node = numa_node;

	rc = mempool_process(&config);
	if (rc < 0)
		snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

exit:
	return rc;
}

static struct cli_module mempool = {
	.cmd = "mempool",
	.process = cli_mempool,
	.usage = cli_mempool_help,
};

CLI_REGISTER(mempool);

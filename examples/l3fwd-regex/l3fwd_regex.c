/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_regexdev.h>

#include "l3fwd.h"
#include "l3fwd_regex.h"

#define REGEX_OPS_DATA_SIZE    (0x80 +\
			254*sizeof(struct rte_regexdev_match))
/* The optimum size (in terms of memory usage) for a mempool
 * is when n is a power of two minus one: n = (2^q - 1).
 */
#define REGEX_RULE_FILE_GROUP_ID_STR "subset_id"
#define REGEX_RULE_FILE_GROUP_ID_LEN 9

#define test_bitmap(i, val) (val & (1ull << i))
#define REGEX_MOD_INC(i, l)   ((i) == (l - 1) ? (i) = 0 : (i)++)

#define REGEX_DEBUG(fmt, args...) \
		do {\
			if (unlikely(conf->debug_print))\
				printf("regex %d:"fmt, rte_lcore_id(), ##args);\
		} while (0)
#define REGEX_LOG(fmt, args...) printf("regex %d:"fmt, rte_lcore_id(), ##args)

#define REGEX_ERR(fmt, args...) printf("error %d:"fmt, rte_lcore_id(), ##args)

const char *
regex_dev_capa_strings[] = {
	[0]	= "compilation",
};


const char *
rule_flags_strings[] = {
	[0]	= "ALLOW_EMPTY",
	[1]	= "ANCHORED",
	[2]	= "CASELESS",
	[3]	= "DOTALL",
	[4]	= "DUPNAMES",
	[5]	= "EXTENDED",
	[6]	= "MATCH_UNSET_BACKREF",
	[7]	= "MULTILINE",
	[8]	= "NO_AUTO_CAPTURE",
	[9]	= "UCP",
	[10]	= "UNGREEDY",
	[11]	= "UTF",
	[12]	= "BACKSLASH",
};

struct regex_rule_db_entry {
	uint8_t		type;
	uint32_t	addr;
	uint64_t	value;
};

struct regex_rule_db {
	uint32_t version;
	uint32_t revision;
	uint32_t number_of_entries;
	struct regex_rule_db_entry *entries;
};

struct regex_stats {
	uint64_t matches;
};

struct regex_conf {
	uint32_t rule_db_len;
	char *rule_db;
	uint8_t debug_print;
	uint8_t nb_lcore;
	uint8_t drop_on_match;
};

struct regex_lcore_conf {
	uint16_t dev_id;
	uint16_t qp_id;
	struct rte_regex_ops **ops;
	struct rte_regex_ops **ops_pool;
};

struct regex_lcore_params {
	uint32_t ops_head;
	uint32_t ops_tail;
	uint32_t ops_avail;
	struct regex_stats stats;
};

static struct regex_lcore_params regex_lcore_params[RTE_MAX_LCORE];
static struct regex_lcore_conf regex_lcore_conf[RTE_MAX_LCORE];

struct regex_conf conf[] = {
		{
				.rule_db_len = 0,
				.rule_db = NULL,
				.debug_print = 0,
				.nb_lcore = 0,
				.drop_on_match = 0,
		}
};

int
regex_read_rule_db_file(char *filename)
{
	uint32_t new_len;
	long buf_len;

	FILE *fp = fopen(filename, "rb");
	if (fp == NULL) {
		printf("Error opening file\n");
		return -EIO;
	}
	if (fseek(fp, 0L, SEEK_END) == 0) {
		buf_len = ftell(fp);
		if (buf_len == -1)
			goto error;
		conf->rule_db = rte_malloc(NULL, sizeof(char) * (buf_len + 1),
				0);
		if (conf->rule_db == NULL)
			goto error;

		if (fseek(fp, 0L, SEEK_SET) != 0)
			goto error;
		new_len = fread(conf->rule_db, sizeof(char), buf_len, fp);
		if (new_len != buf_len)
			goto error;
	} else
		goto error;

	fclose(fp);
	conf->rule_db_len = buf_len;

	return 0;
error:
	if (fp)
		fclose(fp);
	if (conf->rule_db)
		rte_free(conf->rule_db);
	return -EIO;
}

void
regex_debug_enable(void)
{
	conf->debug_print = 1;
}

void
regex_drop_on_match(void)
{
	conf->drop_on_match = 1;
}

static inline int
regex_opspool_get_bulk(uint32_t lcore, struct rte_regex_ops **ops, uint32_t n)
{
	struct rte_regex_ops **ops_pool;
	uint32_t i, ops_head;

	ops_pool = regex_lcore_conf[lcore].ops_pool;
	ops_head = regex_lcore_params[lcore].ops_head;

	if (regex_lcore_params[lcore].ops_avail < n) {
		REGEX_LOG("cannot allocate ops buffer\n");
		return 0;
	}

	for (i = 0; i < n; i++) {
		ops[i] = ops_pool[ops_head];
		REGEX_MOD_INC(ops_head, REGEX_NB_OPS);
	}

	regex_lcore_params[lcore].ops_avail -= n;
	regex_lcore_params[lcore].ops_head = ops_head;
	return n;
}

static inline void
regex_opspool_put_bulk(uint32_t lcore, struct rte_regex_ops **ops, uint32_t n)
{
	struct rte_regex_ops **ops_pool;
	uint32_t i, ops_tail;

	ops_pool = regex_lcore_conf[lcore].ops_pool;
	ops_tail = regex_lcore_params[lcore].ops_tail;
	for (i = 0; i < n; i++) {
		if (ops_pool[ops_tail] != ops[i]) {
			REGEX_ERR("ops pool out of sync\n"
					"ops_pool[%d] = %p\n"
					"ops[%d] = %p\n"
					"exiting...\n", ops_tail,
					ops_pool[ops_tail], i, ops[i]);
			force_quit = true;
			return;
		}
		ops_pool[ops_tail] = ops[i];
		REGEX_MOD_INC(ops_tail, REGEX_NB_OPS);
	}
	regex_lcore_params[lcore].ops_avail += n;
	regex_lcore_params[lcore].ops_tail = ops_tail;
}

static inline void
regex_opspool_put(uint32_t lcore, struct rte_regex_ops *ops)
{
	struct rte_regex_ops **ops_pool;
	uint32_t ops_tail;

	ops_pool = regex_lcore_conf[lcore].ops_pool;
	ops_tail = regex_lcore_params[lcore].ops_tail;
	if (ops_pool[ops_tail] != ops) {
		REGEX_ERR("ops pool out of sync\n"
				"ops_pool[%d] = %p\n"
				"ops = %p\n"
				"exiting...\n", ops_tail,
				ops_pool[ops_tail], ops);
		force_quit = true;
		return;
	}
	ops_pool[ops_tail] = ops;
	REGEX_MOD_INC(ops_tail, REGEX_NB_OPS);
	regex_lcore_params[lcore].ops_avail++;
	regex_lcore_params[lcore].ops_tail = ops_tail;
}

static inline uint32_t
regex_fill_ops(uint32_t lcore, struct rte_regex_ops **ops, uint16_t nb_ops,
		struct rte_mbuf **pkts_burst)
{
	struct rte_mbuf *mbuf;
	uint32_t i;
	int ret;

	ret = regex_opspool_get_bulk(lcore, ops, nb_ops);
	if (unlikely(!ret)) {
		REGEX_LOG("cannot allocate ops buffer\n");
		return 0;
	}

	for (i = 0; i < nb_ops; i++) {

		mbuf = pkts_burst[i];
		if (unlikely(mbuf == NULL)) {
			REGEX_LOG("Cannot allocate more mbuf, %d allocated\n",
					i);
			regex_opspool_put(lcore, ops[i]);
			return i;
		}

		ops[i]->mbuf = mbuf;
		ops[i]->user_ptr = mbuf;
		ops[i]->req_flags = 0;
		ops[i]->group_id0 = 1;
		ops[i]->group_id1 = 0;
		ops[i]->group_id2 = 0;
		ops[i]->group_id3 = 0;
	}

	return i;
}

static inline void
regex_check_match(struct rte_regex_ops **ops, uint32_t deq_cnt,
		struct rte_mbuf **pkts_burst, uint32_t lcore)
{
	uint32_t i;

	for (i = 0; i < deq_cnt; i++) {
		pkts_burst[i] = ops[i]->user_ptr;
		if (ops[i]->nb_matches != 0) {
			REGEX_DEBUG("op %d matches %d\n",
					i, ops[i]->nb_matches);
			regex_lcore_params[lcore].stats.matches++;
			/* mark packet to be dropped
			 * in l3fwd_lpm_simple_forward() non-IP packets are
			 * dropped.
			 */
			if (conf->drop_on_match)
				pkts_burst[i]->packet_type = RTE_PTYPE_UNKNOWN;
		}
	}
}

uint32_t
regex_enqueue_burst_ops(int dev_id, uint32_t lcore_id, uint16_t qp_id,
		struct rte_mbuf **pkts_burst, uint16_t nb_pkts)
{
	uint32_t nb_ops, ret;
	struct rte_regex_ops **ops = regex_lcore_conf[lcore_id].ops;

	nb_ops = regex_fill_ops(lcore_id, ops, nb_pkts, pkts_burst);

	if (unlikely(nb_ops < nb_pkts))
		return 0;

	REGEX_DEBUG("Enqueue single burst %d\n", nb_ops);
	ret = rte_regexdev_enqueue_burst(dev_id, qp_id, ops, nb_ops);
	if (unlikely(ret != nb_ops)) {
		REGEX_ERR("rte_regexdev_enqueue_burst(): Failed, %d/%d enqueue\n",
				ret, nb_ops);
		return 0;
	}
	return nb_ops;
}

uint32_t
regex_dequeue_burst_ops(int dev_id, uint32_t lcore_id, uint16_t qp_id,
		struct rte_mbuf **pkts_burst, uint16_t nb_pkts)
{
	struct rte_regex_ops **ops = regex_lcore_conf[lcore_id].ops;
	uint32_t deq_cnt;

	deq_cnt = rte_regexdev_dequeue_burst(dev_id, qp_id,
			ops, nb_pkts);
	REGEX_DEBUG("dequeue burst %d\n", deq_cnt);
	if (deq_cnt)
		regex_check_match(ops, deq_cnt, pkts_burst, lcore_id);


	regex_opspool_put_bulk(lcore_id, ops, deq_cnt);

	return deq_cnt;
}


void
regex_stats_print(uint32_t lcore)
{
	REGEX_LOG("Number of matches: %"PRIu64"\n",
			regex_lcore_params[lcore].stats.matches);
}

void
regex_dev_uninit(uint32_t dev_id)
{
	if (rte_regexdev_close(dev_id) < 0)
		printf("rte_regexdev_close(dev %d): Failed\n", dev_id);
}

void
regex_lcore_uninit(uint32_t lcore_id)
{
	uint32_t i;
	if (regex_lcore_conf[lcore_id].ops_pool) {
		for (i = 0; i < REGEX_NB_OPS; i++) {
			if (regex_lcore_conf[lcore_id].ops_pool[i])
				rte_free(
					regex_lcore_conf[lcore_id].ops_pool[i]);
		}
		rte_free(regex_lcore_conf[lcore_id].ops_pool);
	}
	if (regex_lcore_conf[lcore_id].ops)
		rte_free(regex_lcore_conf[lcore_id].ops);
}

void
regex_mem_free(void)
{
	if (conf->rule_db)
		rte_free(conf->rule_db);
}

int
regex_dev_init(uint32_t dev_id, uint16_t nb_queue_pairs)
{
	struct rte_regexdev_qp_conf qp_conf;
	struct rte_regexdev_info dev_info;
	struct rte_regexdev_config cfg;
	uint32_t i;
	int ret;

	printf("info: dev id is %d\n", dev_id);
	ret = rte_regexdev_info_get(dev_id, &dev_info);
	if (ret < 0) {
		printf("rte_regexdev_info_get(): Failed\n");
		return ret;
	}
	printf("get info:\n");
	printf("driver_name          %s\n", dev_info.driver_name);
	printf("max_matches          %d\n", dev_info.max_matches);
	printf("max_queue_pairs      %d\n", dev_info.max_queue_pairs);
	printf("max_payloadsize      %d\n", dev_info.max_payload_size);
	printf("max_rules_per_group %d\n",
			dev_info.max_rules_per_group);
	printf("max_groups          %d\n", dev_info.max_groups);
	printf("regex_dev_capa       0x%x\n", dev_info.regexdev_capa);
	for (i = 0; i < 32; i++)
		if (test_bitmap(i, dev_info.regexdev_capa))
			printf("%d           %s\n", i,
					regex_dev_capa_strings[i]);
	printf("rule_flags           0x%lx\n", dev_info.rule_flags);
	for (i = 0; i < 64; i++)
		if (test_bitmap(i, dev_info.rule_flags))
			printf("%d           %s\n", i,
					rule_flags_strings[i]);

	cfg.dev_cfg_flags = 0;
	cfg.nb_max_matches = dev_info.max_matches;
	cfg.nb_queue_pairs = nb_queue_pairs;
	cfg.nb_rules_per_group = dev_info.max_rules_per_group;
	cfg.nb_groups = dev_info.max_groups;
	cfg.rule_db = conf->rule_db;
	cfg.rule_db_len = conf->rule_db_len;
	ret = rte_regexdev_configure(dev_id, &cfg);
	if (ret < 0) {
		printf("rte_regexdev_configure(): Failed\n");
		return ret;
	}

	qp_conf.qp_conf_flags = 0;
	qp_conf.nb_desc = 8192;
	qp_conf.cb = NULL;
	for (i = 0; i < nb_queue_pairs; i++) {
		ret = rte_regexdev_queue_pair_setup(dev_id, i,
				&qp_conf);
		if (ret < 0) {
			printf("rte_regexdev_queue_pair_setup(): Failed for queue %d\n",
					i);
			return ret;
		}
	}
	ret = rte_regexdev_start(dev_id);
	if (ret < 0) {
		printf("rte_regexdev_start(): Failed\n");
		return ret;
	}
	return 0;
}

int
regex_lcore_init(uint32_t lcore_id, uint32_t dev_id, uint32_t qp_id)
{
	uint32_t i;

	printf("%s lcore %u dev_id %d qp %d\n", __func__,
			lcore_id, dev_id, qp_id);

	regex_lcore_conf[lcore_id].qp_id = qp_id;
	regex_lcore_conf[lcore_id].dev_id = dev_id;

	memset(&regex_lcore_params[lcore_id].stats, 0,
			sizeof(struct regex_stats));

	regex_lcore_conf[lcore_id].ops = rte_malloc("regex_ops",
			REGEX_NB_OPS*sizeof(struct rte_regex_ops *),
			0);
	if (regex_lcore_conf[lcore_id].ops == NULL) {
		REGEX_ERR("cannot allocate ops memory");
		return -1;
	}

	regex_lcore_conf[lcore_id].ops_pool = rte_malloc("regex_ops_pool",
			REGEX_NB_OPS*sizeof(struct rte_regex_ops *),
			0);
	if (regex_lcore_conf[lcore_id].ops_pool == NULL) {
		REGEX_ERR("cannot allocate ops pool memory");
		return -1;
	}
	for (i = 0; i < REGEX_NB_OPS; i++) {
		regex_lcore_conf[lcore_id].ops_pool[i] = rte_malloc("",
				REGEX_OPS_DATA_SIZE, 0);
		if (regex_lcore_conf[lcore_id].ops_pool[i] == NULL) {
			REGEX_ERR("cannot allocate ops memory");
			return -1;
		}
	}
	regex_lcore_params[lcore_id].ops_head = 0;
	regex_lcore_params[lcore_id].ops_tail = 0;
	regex_lcore_params[lcore_id].ops_avail = REGEX_NB_OPS;
	conf->nb_lcore++;

	return 0;
}

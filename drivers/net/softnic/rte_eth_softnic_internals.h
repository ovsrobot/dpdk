/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef __INCLUDE_RTE_ETH_SOFTNIC_INTERNALS_H__
#define __INCLUDE_RTE_ETH_SOFTNIC_INTERNALS_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_ethdev.h>
#include <rte_port_in_action.h>
#include <rte_table_action.h>
#include <rte_pipeline.h>

#include <rte_ethdev_core.h>
#include <ethdev_driver.h>

#include "rte_eth_softnic.h"
#include "conn.h"

#define NAME_SIZE                                            64
#define SOFTNIC_PATH_MAX                                     4096

/**
 * PMD Parameters
 */

struct pmd_params {
	char name[NAME_SIZE];
	char firmware[SOFTNIC_PATH_MAX];
	uint16_t conn_port;
	uint32_t cpu_id;
	int sc; /**< Service cores. */
};

/**
 * MEMPOOL
 */
struct softnic_mempool_params {
	uint32_t buffer_size;
	uint32_t pool_size;
	uint32_t cache_size;
};

struct softnic_mempool {
	TAILQ_ENTRY(softnic_mempool) node;
	char name[NAME_SIZE];
	struct rte_mempool *m;
	uint32_t buffer_size;
};

TAILQ_HEAD(softnic_mempool_list, softnic_mempool);

/**
 * SWQ
 */
struct softnic_swq_params {
	uint32_t size;
};

struct softnic_swq {
	TAILQ_ENTRY(softnic_swq) node;
	char name[NAME_SIZE];
	struct rte_ring *r;
};

TAILQ_HEAD(softnic_swq_list, softnic_swq);

/**
 * LINK
 */
struct softnic_link_params {
	const char *dev_name;
	uint16_t port_id; /**< Valid only when *dev_name* is NULL. */
};

struct softnic_link {
	TAILQ_ENTRY(softnic_link) node;
	char name[NAME_SIZE];
	uint16_t port_id;
	uint32_t n_rxq;
	uint32_t n_txq;
};

TAILQ_HEAD(softnic_link_list, softnic_link);

/**
 * Input port action
 */
struct softnic_port_in_action_profile_params {
	uint64_t action_mask;
	struct rte_port_in_action_fltr_config fltr;
	struct rte_port_in_action_lb_config lb;
};

struct softnic_port_in_action_profile {
	TAILQ_ENTRY(softnic_port_in_action_profile) node;
	char name[NAME_SIZE];
	struct softnic_port_in_action_profile_params params;
	struct rte_port_in_action_profile *ap;
};

TAILQ_HEAD(softnic_port_in_action_profile_list, softnic_port_in_action_profile);

/**
 * Table action
 */
struct softnic_table_action_profile_params {
	uint64_t action_mask;
	struct rte_table_action_common_config common;
	struct rte_table_action_lb_config lb;
	struct rte_table_action_mtr_config mtr;
	struct rte_table_action_tm_config tm;
	struct rte_table_action_encap_config encap;
	struct rte_table_action_nat_config nat;
	struct rte_table_action_ttl_config ttl;
	struct rte_table_action_stats_config stats;
	struct rte_table_action_sym_crypto_config sym_crypto;
};

struct softnic_table_action_profile {
	TAILQ_ENTRY(softnic_table_action_profile) node;
	char name[NAME_SIZE];
	struct softnic_table_action_profile_params params;
	struct rte_table_action_profile *ap;
};

TAILQ_HEAD(softnic_table_action_profile_list, softnic_table_action_profile);

struct softnic_table_meter_profile {
	TAILQ_ENTRY(softnic_table_meter_profile) node;
	uint32_t meter_profile_id;
	struct rte_table_action_meter_profile profile;
};

TAILQ_HEAD(softnic_table_meter_profile_list,
	softnic_table_meter_profile);

/**
 * Pipeline
 */
struct pipeline_params {
	uint32_t timer_period_ms;
	uint32_t offset_port_id;
};

enum softnic_port_in_type {
	PORT_IN_RXQ,
	PORT_IN_SWQ,
	PORT_IN_SOURCE,
};

struct softnic_port_in_params {
	/* Read */
	enum softnic_port_in_type type;
	char dev_name[NAME_SIZE];
	union {
		struct {
			uint16_t queue_id;
		} rxq;

		struct {
			const char *mempool_name;
			const char *file_name;
			uint32_t n_bytes_per_pkt;
		} source;
	};
	uint32_t burst_size;

	/* Action */
	char action_profile_name[NAME_SIZE];
};

enum softnic_port_out_type {
	PORT_OUT_TXQ,
	PORT_OUT_SWQ,
	PORT_OUT_SINK,
};

struct softnic_port_out_params {
	enum softnic_port_out_type type;
	char dev_name[NAME_SIZE];
	union {
		struct {
			uint16_t queue_id;
		} txq;

		struct {
			const char *file_name;
			uint32_t max_n_pkts;
		} sink;
	};
	uint32_t burst_size;
	int retry;
	uint32_t n_retries;
};

enum softnic_table_type {
	TABLE_ACL,
	TABLE_ARRAY,
	TABLE_HASH,
	TABLE_LPM,
	TABLE_STUB,
};

struct softnic_table_acl_params {
	uint32_t n_rules;
	uint32_t ip_header_offset;
	int ip_version;
};

struct softnic_table_array_params {
	uint32_t n_keys;
	uint32_t key_offset;
};

#ifndef TABLE_RULE_MATCH_SIZE_MAX
#define TABLE_RULE_MATCH_SIZE_MAX                          256
#endif

struct softnic_table_hash_params {
	uint32_t n_keys;
	uint32_t key_offset;
	uint32_t key_size;
	uint8_t key_mask[TABLE_RULE_MATCH_SIZE_MAX];
	uint32_t n_buckets;
	int extendable_bucket;
};

struct softnic_table_lpm_params {
	uint32_t n_rules;
	uint32_t key_offset;
	uint32_t key_size;
};

struct softnic_table_params {
	/* Match */
	enum softnic_table_type match_type;
	union {
		struct softnic_table_acl_params acl;
		struct softnic_table_array_params array;
		struct softnic_table_hash_params hash;
		struct softnic_table_lpm_params lpm;
	} match;

	/* Action */
	char action_profile_name[NAME_SIZE];
};

struct softnic_port_in {
	struct softnic_port_in_params params;
	struct softnic_port_in_action_profile *ap;
	struct rte_port_in_action *a;
};

struct softnic_port_out {
	struct softnic_port_out_params params;
};

struct softnic_table {
	struct softnic_table_params params;
	struct softnic_table_action_profile *ap;
	struct rte_table_action *a;
	struct rte_table_action_dscp_table dscp_table;
	struct softnic_table_meter_profile_list meter_profiles;
};

struct pipeline {
	TAILQ_ENTRY(pipeline) node;
	char name[NAME_SIZE];

	struct rte_pipeline *p;
	struct pipeline_params params;
	struct softnic_port_in port_in[RTE_PIPELINE_PORT_IN_MAX];
	struct softnic_port_out port_out[RTE_PIPELINE_PORT_OUT_MAX];
	struct softnic_table table[RTE_PIPELINE_TABLE_MAX];
	uint32_t n_ports_in;
	uint32_t n_ports_out;
	uint32_t n_tables;

	struct rte_ring *msgq_req;
	struct rte_ring *msgq_rsp;
	uint32_t timer_period_ms;

	int enabled;
	uint32_t thread_id;
	uint32_t cpu_id;
};

TAILQ_HEAD(pipeline_list, pipeline);

/**
 * Thread
 */
#ifndef THREAD_PIPELINES_MAX
#define THREAD_PIPELINES_MAX                               256
#endif

#ifndef THREAD_MSGQ_SIZE
#define THREAD_MSGQ_SIZE                                   64
#endif

#ifndef THREAD_TIMER_PERIOD_MS
#define THREAD_TIMER_PERIOD_MS                             100
#endif

/**
 * Main thread: data plane thread context
 */
struct softnic_thread {
	struct rte_ring *msgq_req;
	struct rte_ring *msgq_rsp;

	uint32_t service_id;
};

/**
 * Data plane threads: context
 */
#ifndef TABLE_RULE_ACTION_SIZE_MAX
#define TABLE_RULE_ACTION_SIZE_MAX                         2048
#endif

struct softnic_table_data {
	struct rte_table_action *a;
};

struct pipeline_data {
	struct rte_pipeline *p;
	struct softnic_table_data table_data[RTE_PIPELINE_TABLE_MAX];
	uint32_t n_tables;

	struct rte_ring *msgq_req;
	struct rte_ring *msgq_rsp;
	uint64_t timer_period; /* Measured in CPU cycles. */
	uint64_t time_next;

	uint8_t buffer[TABLE_RULE_ACTION_SIZE_MAX];
};

struct softnic_thread_data {
	struct rte_pipeline *p[THREAD_PIPELINES_MAX];
	uint32_t n_pipelines;

	struct pipeline_data pipeline_data[THREAD_PIPELINES_MAX];
	struct rte_ring *msgq_req;
	struct rte_ring *msgq_rsp;
	uint64_t timer_period; /* Measured in CPU cycles. */
	uint64_t time_next;
	uint64_t time_next_min;
	uint64_t iter;
} __rte_cache_aligned;

/**
 * PMD Internals
 */
struct pmd_internals {
	/** Params */
	struct pmd_params params;

	struct softnic_conn *conn;
	struct softnic_mempool_list mempool_list;
	struct softnic_swq_list swq_list;
	struct softnic_link_list link_list;
	struct softnic_port_in_action_profile_list port_in_action_profile_list;
	struct softnic_table_action_profile_list table_action_profile_list;
	struct pipeline_list pipeline_list;
	struct softnic_thread thread[RTE_MAX_LCORE];
	struct softnic_thread_data thread_data[RTE_MAX_LCORE];
};

static inline struct rte_eth_dev *
ETHDEV(struct pmd_internals *softnic)
{
	uint16_t port_id;
	int status;

	if (softnic == NULL)
		return NULL;

	status = rte_eth_dev_get_port_by_name(softnic->params.name, &port_id);
	if (status)
		return NULL;

	return &rte_eth_devices[port_id];
}

/**
 * MEMPOOL
 */
int
softnic_mempool_init(struct pmd_internals *p);

void
softnic_mempool_free(struct pmd_internals *p);

struct softnic_mempool *
softnic_mempool_find(struct pmd_internals *p,
	const char *name);

struct softnic_mempool *
softnic_mempool_create(struct pmd_internals *p,
	const char *name,
	struct softnic_mempool_params *params);

/**
 * SWQ
 */
int
softnic_swq_init(struct pmd_internals *p);

void
softnic_swq_free(struct pmd_internals *p);

void
softnic_softnic_swq_free_keep_rxq_txq(struct pmd_internals *p);

struct softnic_swq *
softnic_swq_find(struct pmd_internals *p,
	const char *name);

struct softnic_swq *
softnic_swq_create(struct pmd_internals *p,
	const char *name,
	struct softnic_swq_params *params);

/**
 * LINK
 */
int
softnic_link_init(struct pmd_internals *p);

void
softnic_link_free(struct pmd_internals *p);

struct softnic_link *
softnic_link_find(struct pmd_internals *p,
	const char *name);

struct softnic_link *
softnic_link_create(struct pmd_internals *p,
	const char *name,
	struct softnic_link_params *params);

/**
 * Input port action
 */
int
softnic_port_in_action_profile_init(struct pmd_internals *p);

void
softnic_port_in_action_profile_free(struct pmd_internals *p);

struct softnic_port_in_action_profile *
softnic_port_in_action_profile_find(struct pmd_internals *p,
	const char *name);

struct softnic_port_in_action_profile *
softnic_port_in_action_profile_create(struct pmd_internals *p,
	const char *name,
	struct softnic_port_in_action_profile_params *params);

/**
 * Table action
 */
int
softnic_table_action_profile_init(struct pmd_internals *p);

void
softnic_table_action_profile_free(struct pmd_internals *p);

struct softnic_table_action_profile *
softnic_table_action_profile_find(struct pmd_internals *p,
	const char *name);

struct softnic_table_action_profile *
softnic_table_action_profile_create(struct pmd_internals *p,
	const char *name,
	struct softnic_table_action_profile_params *params);

/**
 * Pipeline
 */
int
softnic_pipeline_init(struct pmd_internals *p);

void
softnic_pipeline_free(struct pmd_internals *p);

void
softnic_pipeline_disable_all(struct pmd_internals *p);

uint32_t
softnic_pipeline_thread_count(struct pmd_internals *p, uint32_t thread_id);

struct pipeline *
softnic_pipeline_find(struct pmd_internals *p, const char *name);

struct pipeline *
softnic_pipeline_create(struct pmd_internals *p,
	const char *name,
	struct pipeline_params *params);

int
softnic_pipeline_port_in_create(struct pmd_internals *p,
	const char *pipeline_name,
	struct softnic_port_in_params *params,
	int enabled);

int
softnic_pipeline_port_in_connect_to_table(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t port_id,
	uint32_t table_id);

int
softnic_pipeline_port_out_create(struct pmd_internals *p,
	const char *pipeline_name,
	struct softnic_port_out_params *params);

int
softnic_pipeline_port_out_find(struct pmd_internals *softnic,
		const char *pipeline_name,
		const char *name,
		uint32_t *port_id);

int
softnic_pipeline_table_create(struct pmd_internals *p,
	const char *pipeline_name,
	struct softnic_table_params *params);

struct softnic_table_meter_profile *
softnic_pipeline_table_meter_profile_find(struct softnic_table *table,
	uint32_t meter_profile_id);

struct softnic_table_rule_match_acl {
	int ip_version;

	RTE_STD_C11
	union {
		struct {
			uint32_t sa;
			uint32_t da;
		} ipv4;

		struct {
			uint8_t sa[16];
			uint8_t da[16];
		} ipv6;
	};

	uint32_t sa_depth;
	uint32_t da_depth;
	uint16_t sp0;
	uint16_t sp1;
	uint16_t dp0;
	uint16_t dp1;
	uint8_t proto;
	uint8_t proto_mask;
	uint32_t priority;
};

struct softnic_table_rule_match_array {
	uint32_t pos;
};

struct softnic_table_rule_match_hash {
	uint8_t key[TABLE_RULE_MATCH_SIZE_MAX];
};

struct softnic_table_rule_match_lpm {
	int ip_version;

	RTE_STD_C11
	union {
		uint32_t ipv4;
		uint8_t ipv6[16];
	};

	uint8_t depth;
};

struct softnic_table_rule_match {
	enum softnic_table_type match_type;

	union {
		struct softnic_table_rule_match_acl acl;
		struct softnic_table_rule_match_array array;
		struct softnic_table_rule_match_hash hash;
		struct softnic_table_rule_match_lpm lpm;
	} match;
};

#ifndef SYM_CRYPTO_MAX_KEY_SIZE
#define SYM_CRYPTO_MAX_KEY_SIZE		(256)
#endif
struct softnic_table_rule_action {
	uint64_t action_mask;
	struct rte_table_action_fwd_params fwd;
	struct rte_table_action_lb_params lb;
	struct rte_table_action_mtr_params mtr;
	struct rte_table_action_tm_params tm;
	struct rte_table_action_encap_params encap;
	struct rte_table_action_nat_params nat;
	struct rte_table_action_ttl_params ttl;
	struct rte_table_action_stats_params stats;
	struct rte_table_action_time_params time;
	struct rte_table_action_tag_params tag;
	struct rte_table_action_decap_params decap;
	struct rte_table_action_sym_crypto_params sym_crypto;
	uint8_t sym_crypto_key[SYM_CRYPTO_MAX_KEY_SIZE];
};

int
softnic_pipeline_port_in_stats_read(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t port_id,
	struct rte_pipeline_port_in_stats *stats,
	int clear);

int
softnic_pipeline_port_in_enable(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t port_id);

int
softnic_pipeline_port_in_disable(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t port_id);

int
softnic_pipeline_port_out_stats_read(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t port_id,
	struct rte_pipeline_port_out_stats *stats,
	int clear);

int
softnic_pipeline_table_stats_read(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	struct rte_pipeline_table_stats *stats,
	int clear);

int
softnic_pipeline_table_rule_add(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	struct softnic_table_rule_match *match,
	struct softnic_table_rule_action *action,
	void **data);

int
softnic_pipeline_table_rule_add_bulk(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	struct softnic_table_rule_match *match,
	struct softnic_table_rule_action *action,
	void **data,
	uint32_t *n_rules);

int
softnic_pipeline_table_rule_add_default(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	struct softnic_table_rule_action *action,
	void **data);

int
softnic_pipeline_table_rule_delete(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	struct softnic_table_rule_match *match);

int
softnic_pipeline_table_rule_delete_default(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id);

int
softnic_pipeline_table_rule_stats_read(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	void *data,
	struct rte_table_action_stats_counters *stats,
	int clear);

int
softnic_pipeline_table_mtr_profile_add(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	uint32_t meter_profile_id,
	struct rte_table_action_meter_profile *profile);

int
softnic_pipeline_table_mtr_profile_delete(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	uint32_t meter_profile_id);

int
softnic_pipeline_table_rule_mtr_read(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	void *data,
	uint32_t tc_mask,
	struct rte_table_action_mtr_counters *stats,
	int clear);

int
softnic_pipeline_table_dscp_table_update(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	uint64_t dscp_mask,
	struct rte_table_action_dscp_table *dscp_table);

int
softnic_pipeline_table_rule_ttl_read(struct pmd_internals *p,
	const char *pipeline_name,
	uint32_t table_id,
	void *data,
	struct rte_table_action_ttl_counters *stats,
	int clear);

/**
 * Thread
 */
int
softnic_thread_init(struct pmd_internals *p);

void
softnic_thread_free(struct pmd_internals *p);

int
softnic_thread_pipeline_enable(struct pmd_internals *p,
	uint32_t thread_id,
	const char *pipeline_name);

int
softnic_thread_pipeline_disable(struct pmd_internals *p,
	uint32_t thread_id,
	const char *pipeline_name);

/**
 * CLI
 */
void
softnic_cli_process(char *in,
	char *out,
	size_t out_size,
	void *arg);

int
softnic_cli_script_process(struct pmd_internals *softnic,
	const char *file_name,
	size_t msg_in_len_max,
	size_t msg_out_len_max);

#endif /* __INCLUDE_RTE_ETH_SOFTNIC_INTERNALS_H__ */

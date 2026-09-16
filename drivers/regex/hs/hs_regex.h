/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#ifndef HS_REGEX_H
#define HS_REGEX_H

#include <rte_regexdev.h>
#include <rte_hash.h>
#include <hs/hs.h>

#define HS_REGEX_DRIVER_NAME "regex_hs"
#define HS_REGEX_INITIAL_RULES_CAP 64
#define HS_REGEX_MAX_QUEUE_PAIRS 64
#define HS_REGEX_MAX_GROUPS 64
#define HS_REGEX_MAX_RULES 1000000
#define HS_REGEX_DEFAULT_NB_DESC 1024
#define HS_REGEX_MAX_NB_DESC 32768
/* Cap on per-rule lines printed by dev_dump(); large rule counts are summarized. */
#define HS_REGEX_DUMP_MAX_RULES 32
/* Sanity cap on imported serialized database size (defense in depth;
 * Hyperscan allocates memory proportional to this size).
 */
#define HS_REGEX_MAX_RULE_DB_LEN (512U * 1024 * 1024)

/* Ext params encoded in rule_flags bits 37-63 */
#define HS_REGEX_EXT_MAX_OFFSET_SHIFT 37
#define HS_REGEX_EXT_MAX_OFFSET_MASK  0x1FFFULL
#define HS_REGEX_EXT_MIN_OFFSET_SHIFT 50
#define HS_REGEX_EXT_MIN_OFFSET_MASK  0x3FFFULL

/* Device lifecycle state machine. */
enum hs_regex_dev_state {
	HS_REGEX_DEV_CREATED = 0,
	HS_REGEX_DEV_CONFIGURED,
	HS_REGEX_DEV_STARTED,
	HS_REGEX_DEV_STOPPED,
};

/* Per-rule entry stored before compilation */
struct hs_regex_rule {
	char *pattern;
	uint32_t rule_id;
	uint16_t group_id;
	uint64_t rule_flags;
	uint64_t min_offset;
	uint64_t max_offset;
	uint64_t min_length;
};

/* Queue pair */
struct hs_regex_qp {
	struct rte_regex_ops **ops;
	uint16_t nb_desc;
	uint16_t head;
	uint16_t tail;
	uint16_t count;
	hs_scratch_t *scratch;
	uint64_t qp_enqueued;
	uint64_t qp_dequeued;
	uint64_t qp_matches;
};

/* Per-device private data */
struct hs_regex_priv {
	struct hs_regex_rule *rules;
	struct rte_hash *rule_id_hash;
	uint32_t nb_rules;
	uint32_t rules_cap;

	hs_database_t *db;
	int db_compiled;

	struct hs_regex_qp *qps;
	uint16_t nb_queue_pairs;

	uint16_t max_matches;
	uint16_t nb_groups;

	enum hs_regex_dev_state dev_state;
};

int hs_regex_dev_create(const char *name, struct rte_device *device);
void hs_regex_dev_destroy(const char *name);

#endif /* HS_REGEX_H */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 *
 * Intel Hyperscan PMD for DPDK rte_regexdev
 *
 * This Poll Mode Driver wraps Intel Hyperscan behind the standard DPDK
 * regex device API (rte_regexdev). Applications use the enqueue/dequeue
 * burst interface with Hyperscan as the matching engine.
 *
 * Key design:
 *   - Synchronous scan in enqueue (hs_scan blocks until done)
 *   - Per-queue-pair scratch space for lock-free parallel scanning
 *   - HS_MODE_BLOCK: each buffer scanned independently
 *   - Runtime compilation via hs_compile_ext_multi()
 *   - Serialized database import/export via hs_deserialize_database()
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <bus_vdev_driver.h>
#include <rte_regexdev.h>
#include <rte_regexdev_core.h>
#include <rte_regexdev_driver.h>
#include <rte_mbuf.h>

#include <hs/hs.h>

#include "hs_regex.h"

RTE_LOG_REGISTER_DEFAULT(hs_regex_logtype, NOTICE);
#define RTE_LOGTYPE_HS_REGEX hs_regex_logtype

#define HS_LOG(level, ...) \
	RTE_LOG_LINE(level, HS_REGEX, __VA_ARGS__)

/* Match callback context */
struct hs_match_ctx {
	struct rte_regex_ops *op;
	uint16_t max_matches;
	uint64_t total_matches; /* 64-bit counter for accurate tracking */
};

static int
hs_regex_rule_db_import(struct rte_regexdev *dev, const char *rule_db,
			uint32_t rule_db_len);

static int
hs_match_cb(unsigned int id, unsigned long long from,
	    unsigned long long to, unsigned int flags __rte_unused,
	    void *context)
{
	struct hs_match_ctx *ctx = (struct hs_match_ctx *)context;
	struct rte_regex_ops *op;

	if (unlikely(ctx == NULL))
		return 1;

	op = ctx->op;
	if (unlikely(op == NULL))
		return 1;

	ctx->total_matches++;
	op->nb_actual_matches++;

	if (op->nb_matches < ctx->max_matches) {
		struct rte_regexdev_match *m = &op->matches[op->nb_matches];

		m->rule_id = id;
		m->start_offset = (uint16_t)from;
		m->len = (uint16_t)(to - from);
		op->nb_matches++;

	} else {
		/* Match list full; report truncation while keeping actual count. */
		op->rsp_flags |= RTE_REGEX_OPS_RSP_MAX_MATCH_F;
	}

	return 0;
}

/* Device Info */
static int
hs_regex_info_get(struct rte_regexdev *dev, struct rte_regexdev_info *info)
{
	(void)dev;

	if (info == NULL)
		return -EINVAL;

	info->driver_name = HS_REGEX_DRIVER_NAME;
	info->dev = NULL;
	info->max_matches = UINT16_MAX;
	info->max_queue_pairs = HS_REGEX_MAX_QUEUE_PAIRS;
	info->max_payload_size = UINT16_MAX;
	info->max_rules_per_group = HS_REGEX_MAX_RULES;
	info->max_groups = HS_REGEX_MAX_GROUPS;
	info->regexdev_capa = RTE_REGEXDEV_CAPA_RUNTIME_COMPILATION_F;
	info->rule_flags = RTE_REGEX_PCRE_RULE_CASELESS_F |
			   RTE_REGEX_PCRE_RULE_DOTALL_F |
			   RTE_REGEX_PCRE_RULE_MULTILINE_F |
			   RTE_REGEX_PCRE_RULE_UTF_F;

	return 0;
}

/* Configure */
static int
hs_regex_configure(struct rte_regexdev *dev,
		   const struct rte_regexdev_config *cfg)
{
	struct hs_regex_priv *priv;
	int ret;

	if (dev == NULL || cfg == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	/* Reconfigure is not allowed while running. */
	if (priv->dev_state == HS_REGEX_DEV_STARTED) {
		HS_LOG(ERR, "Cannot configure while device is started");
		return -EBUSY;
	}

	if (cfg->nb_queue_pairs > HS_REGEX_MAX_QUEUE_PAIRS) {
		HS_LOG(ERR, "Requested %u queue pairs exceeds max %u",
		       cfg->nb_queue_pairs, HS_REGEX_MAX_QUEUE_PAIRS);
		return -EINVAL;
	}

	priv->nb_queue_pairs = cfg->nb_queue_pairs;
	priv->max_matches = cfg->nb_max_matches ? cfg->nb_max_matches :
						  UINT16_MAX;
	priv->nb_groups = cfg->nb_groups ? cfg->nb_groups : 1;

	/* Reconfigure replaces rules, database, and queue resources. */
	if (priv->rules) {
		uint32_t i;
		for (i = 0; i < priv->nb_rules; i++)
			rte_free(priv->rules[i].pattern);
		rte_free(priv->rules);
		priv->rules = NULL;
		priv->nb_rules = 0;
		priv->rules_cap = 0;
	}
	if (priv->rule_id_hash) {
		rte_hash_free(priv->rule_id_hash);
		priv->rule_id_hash = NULL;
	}
	if (priv->db) {
		hs_free_database(priv->db);
		priv->db = NULL;
		priv->db_compiled = 0;
	}

	if (priv->qps) {
		rte_free(priv->qps);
		priv->qps = NULL;
	}

	priv->qps = rte_zmalloc("hs_regex_qps",
				sizeof(struct hs_regex_qp) *
				cfg->nb_queue_pairs,
				RTE_CACHE_LINE_SIZE);
	if (!priv->qps) {
		HS_LOG(ERR, "Failed to allocate queue pairs");
		/* Keep nb_queue_pairs in sync with the NULL qps array. */
		priv->nb_queue_pairs = 0;
		return -ENOMEM;
	}

	HS_LOG(INFO, "Configured: %u queue pairs, max_matches=%u",
	       priv->nb_queue_pairs, priv->max_matches);

	/* Configuration complete. */
	priv->dev_state = HS_REGEX_DEV_CONFIGURED;

	if (cfg->rule_db != NULL && cfg->rule_db_len > 0) {
		ret = hs_regex_rule_db_import(dev, cfg->rule_db,
					     cfg->rule_db_len);
		if (ret < 0) {
			HS_LOG(ERR, "Failed to import rule DB in configure");
			/* Roll back QP allocation on import failure. */
			rte_free(priv->qps);
			priv->qps = NULL;
			priv->nb_queue_pairs = 0;
			/* Revert state since configure failed */
			priv->dev_state = HS_REGEX_DEV_CREATED;
			return ret;
		}
	}

	return 0;
}

/* Queue Pair Setup */
static int
hs_regex_qp_setup(struct rte_regexdev *dev, uint16_t qp_id,
		  const struct rte_regexdev_qp_conf *qp_conf)
{
	struct hs_regex_priv *priv;
	struct hs_regex_qp *qp;
	uint16_t nb_desc;
	hs_error_t err;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	if (qp_id >= priv->nb_queue_pairs) {
		HS_LOG(ERR, "Invalid qp_id %u (max %u)", qp_id,
		       priv->nb_queue_pairs);
		return -EINVAL;
	}

	/* nb_queue_pairs must stay in sync with a live qps array. */
	if (priv->qps == NULL) {
		HS_LOG(ERR, "qp %u: queue pairs not allocated", qp_id);
		return -EINVAL;
	}

	qp = &priv->qps[qp_id];
	nb_desc = (qp_conf && qp_conf->nb_desc) ? qp_conf->nb_desc :
						   HS_REGEX_DEFAULT_NB_DESC;

	/*
	 * The ring uses modulo arithmetic on head/tail.
	 * Keep descriptor count as power-of-two for predictable wrap behavior.
	 */
	if (nb_desc == 0 || (nb_desc & (nb_desc - 1)) != 0) {
		uint16_t orig = nb_desc;
		uint32_t aligned = rte_align32pow2(nb_desc ? nb_desc : 1);

		if (aligned > HS_REGEX_MAX_NB_DESC)
			aligned = HS_REGEX_MAX_NB_DESC;
		nb_desc = aligned;
		HS_LOG(WARNING, "QP %u: nb_desc %u rounded up to %u (power of 2)",
		       qp_id, orig, nb_desc);
	}

	/* Re-setup replaces previous ring allocation. */
	if (qp->ops) {
		rte_free(qp->ops);
		qp->ops = NULL;
	}

	/* Scratch is recreated on re-setup. */
	if (qp->scratch) {
		hs_free_scratch(qp->scratch);
		qp->scratch = NULL;
	}

	qp->ops = rte_zmalloc("hs_regex_qp_ops",
			      sizeof(struct rte_regex_ops *) * nb_desc,
			      RTE_CACHE_LINE_SIZE);
	if (!qp->ops) {
		HS_LOG(ERR, "Failed to allocate ops ring for qp %u", qp_id);
		return -ENOMEM;
	}

	qp->nb_desc = nb_desc;
	qp->head = 0;
	qp->tail = 0;
	qp->count = 0;

	if (priv->db) {
		err = hs_alloc_scratch(priv->db, &qp->scratch);
		if (err != HS_SUCCESS) {
			HS_LOG(ERR, "Failed to alloc scratch for qp %u",
			       qp_id);
			rte_free(qp->ops);
			qp->ops = NULL;
			return -ENOMEM;
		}
	}

	HS_LOG(INFO, "QP %u setup: nb_desc=%u", qp_id, nb_desc);
	return 0;
}

/* Rule Database Update */
static int
hs_regex_rule_db_update(struct rte_regexdev *dev,
			const struct rte_regexdev_rule *rules,
			uint16_t nb_rules)
{
	struct hs_regex_priv *priv;
	uint64_t rf;
	uint16_t i;

	if (dev == NULL || rules == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	if (nb_rules == 0)
		return 0;

	/* Lazy-init hash table for O(1) duplicate rule_id detection. */
	if (!priv->rule_id_hash) {
		struct rte_hash_parameters hp = {
			.name = "hs_rule_ids",
			.entries = HS_REGEX_MAX_RULES,
			.key_len = sizeof(uint32_t),
			.socket_id = SOCKET_ID_ANY,
		};
		priv->rule_id_hash = rte_hash_create(&hp);
		if (!priv->rule_id_hash) {
			HS_LOG(ERR, "Failed to create rule_id hash");
			return -ENOMEM;
		}
	}

	for (i = 0; i < nb_rules; i++) {
		if (rules[i].op == RTE_REGEX_RULE_OP_ADD) {
			uint32_t idx;

			/* Reject empty or NULL patterns. */
			if (!rules[i].pcre_rule || rules[i].pcre_rule_len == 0) {
				HS_LOG(ERR, "Rule %u: NULL or empty pattern",
				       rules[i].rule_id);
				rte_errno = EINVAL;
				return i;
			}

			/* Keep rule_id unique for deterministic match reporting. */
			if (priv->rule_id_hash &&
			    rte_hash_lookup(priv->rule_id_hash,
					   &rules[i].rule_id) >= 0) {
				HS_LOG(ERR, "Rule %u: duplicate rule_id",
				       rules[i].rule_id);
				rte_errno = EINVAL;
				return i;
			}

			if (priv->nb_rules >= HS_REGEX_MAX_RULES) {
				HS_LOG(ERR, "Rule limit reached (%u)",
				       HS_REGEX_MAX_RULES);
				rte_errno = ENOSPC;
				return i;
			}

			if (priv->nb_rules >= priv->rules_cap) {
				uint32_t new_cap = priv->rules_cap ?
					priv->rules_cap * 2 :
					HS_REGEX_INITIAL_RULES_CAP;
				struct hs_regex_rule *tmp = rte_realloc(
					priv->rules,
					new_cap * sizeof(struct hs_regex_rule), 0);
				if (!tmp) {
					HS_LOG(ERR, "Failed to grow rules");
					rte_errno = ENOMEM;
					return i;
				}
				priv->rules = tmp;
				priv->rules_cap = new_cap;
			}

			idx = priv->nb_rules;

			priv->rules[idx].pattern = rte_malloc("hs_pattern",
				rules[i].pcre_rule_len + 1, 0);
			if (!priv->rules[idx].pattern) {
				rte_errno = ENOMEM;
				return i;
			}
			memcpy(priv->rules[idx].pattern,
			       rules[i].pcre_rule, rules[i].pcre_rule_len);
			priv->rules[idx].pattern[rules[i].pcre_rule_len] = '\0';

			priv->rules[idx].rule_id = rules[i].rule_id;
			priv->rules[idx].group_id = rules[i].group_id;
			priv->rules[idx].rule_flags = rules[i].rule_flags;

			rf = rules[i].rule_flags;
			priv->rules[idx].max_offset =
				(rf >> HS_REGEX_EXT_MAX_OFFSET_SHIFT) &
				HS_REGEX_EXT_MAX_OFFSET_MASK;
			priv->rules[idx].min_offset =
				(rf >> HS_REGEX_EXT_MIN_OFFSET_SHIFT) &
				HS_REGEX_EXT_MIN_OFFSET_MASK;
			priv->rules[idx].min_length = 0;

			priv->nb_rules++;

			if (priv->rule_id_hash)
				rte_hash_add_key(priv->rule_id_hash,
						 &rules[i].rule_id);

		} else if (rules[i].op == RTE_REGEX_RULE_OP_REMOVE) {
			uint32_t j;

			if (priv->rule_id_hash)
				rte_hash_del_key(priv->rule_id_hash,
						 &rules[i].rule_id);

			for (j = 0; j < priv->nb_rules; j++) {
				if (priv->rules[j].rule_id !=
				    rules[i].rule_id)
					continue;
				rte_free(priv->rules[j].pattern);
				memmove(&priv->rules[j], &priv->rules[j + 1],
					(priv->nb_rules - j - 1) *
					sizeof(struct hs_regex_rule));
				priv->nb_rules--;
				break;
			}
		}
	}

	priv->db_compiled = 0;
	HS_LOG(INFO, "Rule DB updated: %u total rules", priv->nb_rules);
	return nb_rules;
}

/* Compile and Activate */
static int
hs_regex_rule_db_compile_activate(struct rte_regexdev *dev)
{
	struct hs_regex_priv *priv;
	hs_compile_error_t *compile_err = NULL;
	hs_error_t err;
	const char **expressions;
	unsigned int *flags;
	unsigned int *ids;
	hs_expr_ext_t *ext;
	const hs_expr_ext_t **ext_ptrs;
	uint32_t i;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	if (priv->nb_rules == 0) {
		HS_LOG(ERR, "No rules to compile");
		return -EINVAL;
	}

	if (priv->qps == NULL) {
		HS_LOG(ERR, "Cannot compile: queue pairs not allocated");
		return -EINVAL;
	}

	if (priv->db) {
		hs_free_database(priv->db);
		priv->db = NULL;
	}

	expressions = rte_malloc("hs_expr",
				 sizeof(char *) * priv->nb_rules, 0);
	flags = rte_malloc("hs_flags",
			   sizeof(unsigned int) * priv->nb_rules, 0);
	ids = rte_malloc("hs_ids",
			 sizeof(unsigned int) * priv->nb_rules, 0);
	ext = rte_zmalloc("hs_ext",
			  sizeof(hs_expr_ext_t) * priv->nb_rules, 0);
	ext_ptrs = rte_malloc("hs_ext_ptrs",
			      sizeof(hs_expr_ext_t *) * priv->nb_rules, 0);

	if (!expressions || !flags || !ids || !ext || !ext_ptrs) {
		rte_free(expressions);
		rte_free(flags);
		rte_free(ids);
		rte_free(ext);
		rte_free(ext_ptrs);
		return -ENOMEM;
	}

	for (i = 0; i < priv->nb_rules; i++) {
		expressions[i] = priv->rules[i].pattern;
		ids[i] = priv->rules[i].rule_id;

		flags[i] = 0;
		if (priv->rules[i].rule_flags & RTE_REGEX_PCRE_RULE_CASELESS_F)
			flags[i] |= HS_FLAG_CASELESS;
		if (priv->rules[i].rule_flags & RTE_REGEX_PCRE_RULE_DOTALL_F)
			flags[i] |= HS_FLAG_DOTALL;
		if (priv->rules[i].rule_flags & RTE_REGEX_PCRE_RULE_MULTILINE_F)
			flags[i] |= HS_FLAG_MULTILINE;
		if (priv->rules[i].rule_flags & RTE_REGEX_PCRE_RULE_UTF_F)
			flags[i] |= HS_FLAG_UTF8;

		/* Extended parameters */
		ext[i].flags = 0;
		if (priv->rules[i].min_offset) {
			ext[i].flags |= HS_EXT_FLAG_MIN_OFFSET;
			ext[i].min_offset = priv->rules[i].min_offset;
		}
		if (priv->rules[i].max_offset) {
			ext[i].flags |= HS_EXT_FLAG_MAX_OFFSET;
			ext[i].max_offset = priv->rules[i].max_offset;
		}
		if (priv->rules[i].min_length) {
			ext[i].flags |= HS_EXT_FLAG_MIN_LENGTH;
			ext[i].min_length = priv->rules[i].min_length;
		}
		ext_ptrs[i] = &ext[i];
	}

	err = hs_compile_ext_multi(expressions, flags, ids, ext_ptrs,
				   priv->nb_rules, HS_MODE_BLOCK, NULL,
				   &priv->db, &compile_err);

	rte_free(expressions);
	rte_free(flags);
	rte_free(ids);
	rte_free(ext);
	rte_free(ext_ptrs);

	if (err != HS_SUCCESS) {
		HS_LOG(ERR, "hs_compile_ext_multi failed: %s (pattern %d)",
		       compile_err ? compile_err->message : "unknown",
		       compile_err ? compile_err->expression : -1);
		if (compile_err)
			hs_free_compile_error(compile_err);
		return -EINVAL;
	}

	/* Allocate scratch per queue pair for scanning. */
	for (i = 0; i < priv->nb_queue_pairs; i++) {
		struct hs_regex_qp *qp = &priv->qps[i];

		if (qp->scratch) {
			hs_free_scratch(qp->scratch);
			qp->scratch = NULL;
		}
		err = hs_alloc_scratch(priv->db, &qp->scratch);
		if (err != HS_SUCCESS) {
			uint32_t j;

			HS_LOG(ERR, "Scratch alloc failed for qp %u", i);
			/* Partial failure: unwind previous scratch allocations. */
			for (j = 0; j < i; j++) {
				if (priv->qps[j].scratch) {
					hs_free_scratch(priv->qps[j].scratch);
					priv->qps[j].scratch = NULL;
				}
			}
			hs_free_database(priv->db);
			priv->db = NULL;
			return -ENOMEM;
		}
	}

	priv->db_compiled = 1;
	HS_LOG(INFO, "Compiled %u rules into Hyperscan database",
	       priv->nb_rules);
	return 0;
}

/*
 * Import a prebuilt serialized Hyperscan database.
 * The buffer must be produced by hs_serialize_database().
 */
static int
hs_regex_rule_db_import(struct rte_regexdev *dev, const char *rule_db,
			uint32_t rule_db_len)
{
	struct hs_regex_priv *priv;
	hs_error_t err;
	uint32_t i;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	if (!rule_db || rule_db_len == 0) {
		HS_LOG(ERR, "Invalid rule_db pointer or length");
		return -EINVAL;
	}

	if (priv->qps == NULL) {
		HS_LOG(ERR, "Cannot import: queue pairs not allocated");
		return -EINVAL;
	}

	/* Free existing database */
	if (priv->db) {
		hs_free_database(priv->db);
		priv->db = NULL;
	}

	/* Deserialize the precompiled database */
	err = hs_deserialize_database(rule_db, (size_t)rule_db_len, &priv->db);
	if (err != HS_SUCCESS) {
		HS_LOG(ERR, "hs_deserialize_database failed (error %d)", err);
		return -EINVAL;
	}

	/* Imported DB also requires per-QP scratch. */
	for (i = 0; i < priv->nb_queue_pairs; i++) {
		struct hs_regex_qp *qp = &priv->qps[i];

		if (qp->scratch) {
			hs_free_scratch(qp->scratch);
			qp->scratch = NULL;
		}
		err = hs_alloc_scratch(priv->db, &qp->scratch);
		if (err != HS_SUCCESS) {
			uint32_t j;

			HS_LOG(ERR, "Scratch alloc failed for qp %u"
			       " after import", i);
			/* Clean up already allocated scratches */
			for (j = 0; j < i; j++) {
				if (priv->qps[j].scratch) {
					hs_free_scratch(priv->qps[j].scratch);
					priv->qps[j].scratch = NULL;
				}
			}
			hs_free_database(priv->db);
			priv->db = NULL;
			return -ENOMEM;
		}
	}

	priv->db_compiled = 1;
	HS_LOG(INFO, "Imported serialized Hyperscan database (%u bytes)",
	       rule_db_len);
	return 0;
}

/*
 * Export the compiled Hyperscan database as a serialized blob.
 * If rule_db is NULL, returns the required buffer size.
 */
static int
hs_regex_rule_db_export(struct rte_regexdev *dev, char *rule_db)
{
	struct hs_regex_priv *priv;
	hs_error_t err;
	char *buf;
	size_t len;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	if (!priv->db) {
		HS_LOG(ERR, "No database to export");
		return -EINVAL;
	}

	err = hs_serialize_database(priv->db, &buf, &len);
	if (err != HS_SUCCESS) {
		HS_LOG(ERR, "hs_serialize_database failed (error %d)", err);
		return -EIO;
	}

	if (rule_db == NULL) {
		/* buf allocated by Hyperscan's malloc, not rte_malloc. */
		free(buf);
		if (len > INT_MAX) {
			HS_LOG(ERR, "Serialized DB too large (%zu bytes)", len);
			return -EOVERFLOW;
		}
		return (int)len;
	}

	memcpy(rule_db, buf, len);
	/* Hyperscan allocates buf internally via malloc, not rte_malloc. */
	free(buf);
	return 0;
}

/*
 * Fast Path
 *
 * Thread-safety model: single-producer / single-consumer per queue
 * pair.  Each QP must be used by exactly one thread.  No locking is
 * performed on ring operations (head/tail/count).  Using the same QP
 * from multiple threads concurrently causes data races.
 */

static uint16_t
hs_regex_enqueue_burst(struct rte_regexdev *dev, uint16_t qp_id,
		       struct rte_regex_ops **ops, uint16_t nb_ops)
{
	struct hs_regex_priv *priv;
	struct hs_regex_qp *qp;
	uint16_t i;
	uint16_t free_space;

	if (unlikely(dev == NULL || ops == NULL))
		return 0;

	priv = dev->data->dev_private;
	if (unlikely(priv == NULL))
		return 0;

	/* Validate queue pair index. */
	if (unlikely(qp_id >= priv->nb_queue_pairs)) {
		HS_LOG(ERR, "enqueue: invalid qp_id %u (max %u)",
		       qp_id, priv->nb_queue_pairs);
		return 0;
	}

	if (unlikely(priv->dev_state != HS_REGEX_DEV_STARTED)) {
		HS_LOG(ERR, "enqueue: device not started");
		return 0;
	}

	if (unlikely(priv->db == NULL)) {
		HS_LOG(ERR, "enqueue: no compiled database, dropping burst");
		return 0;
	}

	qp = &priv->qps[qp_id];

	if (unlikely(qp->scratch == NULL)) {
		HS_LOG(ERR, "enqueue: qp %u has no scratch, dropping burst",
		       qp_id);
		return 0;
	}

	/* Bounded ring: accept only free entries. */
	free_space = qp->nb_desc - qp->count;
	if (nb_ops > free_space)
		nb_ops = free_space;

	for (i = 0; i < nb_ops; i++) {
		struct rte_regex_ops *op = ops[i];
		struct rte_mbuf *mbuf;
		const char *data;
		uint32_t data_len;
		struct hs_match_ctx ctx = { .total_matches = 0 };
		hs_error_t err;

		if (unlikely(op == NULL))
			break;

		mbuf = op->mbuf;
		if (unlikely(mbuf == NULL)) {
			op->nb_matches = 0;
			op->nb_actual_matches = 0;
			op->rsp_flags = RTE_REGEX_OPS_RSP_RESOURCE_LIMIT_REACHED_F;
			goto enqueue_op;
		}

		/* hs_scan requires contiguous data. */
		if (rte_pktmbuf_linearize(mbuf) != 0) {
			op->nb_matches = 0;
			op->nb_actual_matches = 0;
			op->rsp_flags = RTE_REGEX_OPS_RSP_RESOURCE_LIMIT_REACHED_F;
			goto enqueue_op;
		}
		data = rte_pktmbuf_mtod(mbuf, const char *);
		data_len = rte_pktmbuf_pkt_len(mbuf);

		if (unlikely(data_len == 0)) {
			op->nb_matches = 0;
			op->nb_actual_matches = 0;
			op->rsp_flags = 0;
			goto enqueue_op;
		}

		op->nb_matches = 0;
		op->nb_actual_matches = 0;
		op->rsp_flags = 0;

		ctx.op = op;
		ctx.max_matches = priv->max_matches;
		ctx.total_matches = 0;

		err = hs_scan(priv->db, data, data_len, 0,
			      qp->scratch, hs_match_cb, &ctx);

		if (unlikely(err != HS_SUCCESS &&
			     err != HS_SCAN_TERMINATED))
			op->rsp_flags |=
				RTE_REGEX_OPS_RSP_RESOURCE_LIMIT_REACHED_F;

enqueue_op:
		/* Keep completed op for dequeue_burst(). */
		qp->ops[qp->tail] = op;
		qp->tail = (qp->tail + 1) % qp->nb_desc;
		qp->count++;

		qp->qp_matches += ctx.total_matches;
	}

	qp->qp_enqueued += i;
	return i;
}

static uint16_t
hs_regex_dequeue_burst(struct rte_regexdev *dev, uint16_t qp_id,
		       struct rte_regex_ops **ops, uint16_t nb_ops)
{
	struct hs_regex_priv *priv;
	struct hs_regex_qp *qp;
	uint16_t i;
	uint16_t avail;

	if (unlikely(dev == NULL || ops == NULL))
		return 0;

	priv = dev->data->dev_private;
	if (unlikely(priv == NULL))
		return 0;

	/* Validate queue pair index. */
	if (unlikely(qp_id >= priv->nb_queue_pairs)) {
		HS_LOG(ERR, "dequeue: invalid qp_id %u (max %u)",
		       qp_id, priv->nb_queue_pairs);
		return 0;
	}

	if (unlikely(priv->qps == NULL))
		return 0;

	qp = &priv->qps[qp_id];

	/* Return completed ops currently available in the ring. */
	avail = qp->count;
	if (nb_ops > avail)
		nb_ops = avail;

	for (i = 0; i < nb_ops; i++) {
		ops[i] = qp->ops[qp->head];
		qp->head = (qp->head + 1) % qp->nb_desc;
		qp->count--;
	}

	/* Device-level stats. */
	qp->qp_dequeued += i;
	return i;
}

/* xstats: per-QP statistics */

/* 3 stats per QP: enqueued, dequeued, matches */
#define HS_XSTATS_PER_QP 3

static const char * const hs_xstat_suffixes[HS_XSTATS_PER_QP] = {
	"enqueued", "dequeued", "matches"
};

static int
hs_regex_xstats_names_get(struct rte_regexdev *dev,
			  struct rte_regexdev_xstats_map *xstats_map)
{
	struct hs_regex_priv *priv;
	uint16_t nqp;
	int total;
	int idx = 0;
	uint16_t q;
	int s;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	nqp = priv->nb_queue_pairs;
	total = nqp * HS_XSTATS_PER_QP;

	if (!xstats_map)
		return total;

	for (q = 0; q < nqp; q++) {
		for (s = 0; s < HS_XSTATS_PER_QP; s++) {
			snprintf(xstats_map[idx].name,
				 sizeof(xstats_map[idx].name),
				 "qp%u_%s", q, hs_xstat_suffixes[s]);
			xstats_map[idx].id = idx;
			idx++;
		}
	}
	return total;
}

static int
hs_regex_xstats_get(struct rte_regexdev *dev,
		    const uint16_t *ids, uint64_t *values,
		    uint16_t nb_values)
{
	struct hs_regex_priv *priv;
	uint16_t nqp;
	int total;
	uint16_t id, qp_idx, stat_idx;
	uint16_t i;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	nqp = priv->nb_queue_pairs;
	total = nqp * HS_XSTATS_PER_QP;

	if (!ids || !values)
		return total;

	if (priv->qps == NULL)
		total = 0;

	for (i = 0; i < nb_values; i++) {
		id = ids[i];

		if (id >= (uint16_t)total) {
			values[i] = 0;
			continue;
		}

		qp_idx = id / HS_XSTATS_PER_QP;
		stat_idx = id % HS_XSTATS_PER_QP;

		switch (stat_idx) {
		case 0:
			values[i] = priv->qps[qp_idx].qp_enqueued;
			break;
		case 1:
			values[i] = priv->qps[qp_idx].qp_dequeued;
			break;
		case 2:
			values[i] = priv->qps[qp_idx].qp_matches;
			break;
		}
	}
	return nb_values;
}

static int
hs_regex_xstats_reset(struct rte_regexdev *dev,
		      const uint16_t *ids, uint16_t nb_ids)
{
	struct hs_regex_priv *priv;
	uint16_t nqp;
	int total;
	uint16_t q, i;
	uint16_t id, qp_idx, stat_idx;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	nqp = priv->nb_queue_pairs;
	total = nqp * HS_XSTATS_PER_QP;

	if (priv->qps == NULL)
		return 0;

	if (!ids || nb_ids == 0) {
		/* Reset all stats */
		for (q = 0; q < nqp; q++) {
			priv->qps[q].qp_enqueued = 0;
			priv->qps[q].qp_dequeued = 0;
			priv->qps[q].qp_matches = 0;
		}
	} else {
		/* Reset specific stats by id */
		for (i = 0; i < nb_ids; i++) {
			id = ids[i];

			if (id >= (uint16_t)total)
				continue;

			qp_idx = id / HS_XSTATS_PER_QP;
			stat_idx = id % HS_XSTATS_PER_QP;

			switch (stat_idx) {
			case 0:
				priv->qps[qp_idx].qp_enqueued = 0;
				break;
			case 1:
				priv->qps[qp_idx].qp_dequeued = 0;
				break;
			case 2:
				priv->qps[qp_idx].qp_matches = 0;
				break;
			}
		}
	}
	return 0;
}

/* Operations table */
static const struct rte_regexdev_ops hs_regexdev_ops = {
	.dev_info_get = hs_regex_info_get,
	.dev_configure = hs_regex_configure,
	.dev_qp_setup = hs_regex_qp_setup,
	.dev_rule_db_update = hs_regex_rule_db_update,
	.dev_rule_db_compile_activate = hs_regex_rule_db_compile_activate,
	.dev_db_import = hs_regex_rule_db_import,
	.dev_db_export = hs_regex_rule_db_export,
	.dev_xstats_names_get = hs_regex_xstats_names_get,
	.dev_xstats_get = hs_regex_xstats_get,
	.dev_xstats_by_name_get = NULL,
	.dev_xstats_reset = hs_regex_xstats_reset,
};

/* Device Lifecycle */

int
hs_regex_dev_create(const char *name, struct rte_device *device)
{
	struct hs_regex_priv *priv;
	struct rte_regexdev *dev;

	if (name == NULL || device == NULL)
		return -EINVAL;

	HS_LOG(INFO, "Creating Hyperscan regex device: %s", name);

	dev = rte_regexdev_register(name);
	if (!dev) {
		HS_LOG(ERR, "Failed to register regex device %s", name);
		return -EINVAL;
	}

	priv = rte_zmalloc("hs_regex_priv", sizeof(*priv),
			   RTE_CACHE_LINE_SIZE);
	if (!priv) {
		rte_regexdev_unregister(dev);
		return -ENOMEM;
	}

	dev->dev_ops = &hs_regexdev_ops;
	dev->enqueue = hs_regex_enqueue_burst;
	dev->dequeue = hs_regex_dequeue_burst;
	dev->device = device;
	dev->data->dev_private = priv;
	dev->state = RTE_REGEXDEV_READY;

	HS_LOG(INFO, "Hyperscan regex PMD created (dev_id=%u, hs=%s)",
	       dev->data->dev_id, hs_version());
	return dev->data->dev_id;
}

void
hs_regex_dev_destroy(const char *name)
{
	struct rte_regexdev *dev;
	struct hs_regex_priv *priv;

	if (name == NULL)
		return;

	dev = rte_regexdev_get_device_by_name(name);
	if (!dev)
		return;

	priv = dev->data->dev_private;
	if (priv) {
		rte_free(priv);
		dev->data->dev_private = NULL;
	}

	rte_regexdev_unregister(dev);
	HS_LOG(INFO, "Hyperscan regex PMD destroyed: %s", name);
}

static int
hs_regex_probe(struct rte_vdev_device *vdev)
{
	const char *name;
	int ret;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		HS_LOG(ERR, "Multi-process not supported for %s", name);
		return -EINVAL;
	}

	ret = hs_regex_dev_create(name, &vdev->device);
	return ret < 0 ? ret : 0;
}

static int
hs_regex_remove(struct rte_vdev_device *vdev)
{
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	hs_regex_dev_destroy(name);
	return 0;
}

static struct rte_vdev_driver hs_regex_pmd_drv = {
	.probe = hs_regex_probe,
	.remove = hs_regex_remove,
};

RTE_PMD_REGISTER_VDEV(regex_hs, hs_regex_pmd_drv);
RTE_PMD_REGISTER_PARAM_STRING(regex_hs, "");

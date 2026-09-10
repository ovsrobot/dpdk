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
	uint8_t stop_on_match;
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
	if (op->nb_actual_matches < UINT16_MAX)
		op->nb_actual_matches++;
	else
		op->rsp_flags |= RTE_REGEX_OPS_RSP_MAX_MATCH_F;

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

	return ctx->stop_on_match ? 1 : 0;
}

/* Device Info */
static int
hs_regex_info_get(struct rte_regexdev *dev, struct rte_regexdev_info *info)
{
	if (info == NULL)
		return -EINVAL;

	info->driver_name = HS_REGEX_DRIVER_NAME;
	info->dev = dev->device;
	info->max_matches = UINT16_MAX;
	info->max_queue_pairs = HS_REGEX_MAX_QUEUE_PAIRS;
	info->max_payload_size = UINT16_MAX;
	info->max_rules_per_group = HS_REGEX_MAX_RULES;
	info->max_groups = HS_REGEX_MAX_GROUPS;
	info->regexdev_capa = RTE_REGEXDEV_CAPA_RUNTIME_COMPILATION_F;
	info->rule_flags = RTE_REGEX_PCRE_RULE_ALLOW_EMPTY_F |
			   RTE_REGEX_PCRE_RULE_CASELESS_F |
			   RTE_REGEX_PCRE_RULE_DOTALL_F |
			   RTE_REGEX_PCRE_RULE_MULTILINE_F |
			   RTE_REGEX_PCRE_RULE_UCP_F |
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
	if (cfg->dev_cfg_flags != 0) {
		HS_LOG(ERR, "Unsupported device configuration flags 0x%x",
		       cfg->dev_cfg_flags);
		return -EINVAL;
	}

	if (cfg->nb_queue_pairs > HS_REGEX_MAX_QUEUE_PAIRS) {
		HS_LOG(ERR, "Requested %u queue pairs exceeds max %u",
		       cfg->nb_queue_pairs, HS_REGEX_MAX_QUEUE_PAIRS);
		return -EINVAL;
	}

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
		uint16_t i;

		for (i = 0; i < priv->nb_queue_pairs; i++) {
			if (priv->qps[i].scratch)
				hs_free_scratch(priv->qps[i].scratch);
			rte_free(priv->qps[i].ops);
		}
		rte_free(priv->qps);
		priv->qps = NULL;
	}

	priv->nb_queue_pairs = cfg->nb_queue_pairs;
	priv->max_matches = cfg->nb_max_matches ? cfg->nb_max_matches :
						  UINT16_MAX;
	priv->nb_groups = cfg->nb_groups ? cfg->nb_groups : 1;

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
			priv->max_matches = 0;
			priv->nb_groups = 0;
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

	/* nb_queue_pairs is only meaningful once qps is allocated. */
	if (priv->qps == NULL) {
		HS_LOG(ERR, "qp %u: queue pairs not allocated", qp_id);
		return -EINVAL;
	}

	if (qp_id >= priv->nb_queue_pairs) {
		HS_LOG(ERR, "Invalid qp_id %u (max %u)", qp_id,
		       priv->nb_queue_pairs);
		return -EINVAL;
	}
	if (qp_conf && qp_conf->qp_conf_flags != 0) {
		HS_LOG(ERR, "QP %u: unsupported configuration flags 0x%x",
		       qp_id, qp_conf->qp_conf_flags);
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

		if (aligned > HS_REGEX_MAX_NB_DESC) {
			HS_LOG(WARNING,
			       "QP %u: nb_desc %u exceeds max %u, capping "
			       "(next power of 2 would be %u)",
			       qp_id, orig, HS_REGEX_MAX_NB_DESC, aligned);
			aligned = HS_REGEX_MAX_NB_DESC;
		} else {
			HS_LOG(WARNING, "QP %u: nb_desc %u rounded up to %u (power of 2)",
			       qp_id, orig, aligned);
		}
		nb_desc = aligned;
	}

	/* Re-setup replaces previous ring allocation. */
	if (qp->ops) {
		rte_free(qp->ops);
		qp->ops = NULL;
	}

	/*
	 * Scratch is recreated on re-setup here if a database already
	 * exists; otherwise compile_activate()/import() populate it
	 * for every queue pair once a database becomes available.
	 */
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

/*
 * Rule Database Update
 * On failure, returns the index of the first failed rule; rules
 * before that index are already committed (not rolled back).
 */
static int
hs_regex_rule_db_update(struct rte_regexdev *dev,
			const struct rte_regexdev_rule *rules,
			uint16_t nb_rules)
{
	struct hs_regex_priv *priv;
	const uint64_t known_flags = RTE_REGEX_PCRE_RULE_ALLOW_EMPTY_F |
		RTE_REGEX_PCRE_RULE_CASELESS_F |
		RTE_REGEX_PCRE_RULE_DOTALL_F |
		RTE_REGEX_PCRE_RULE_MULTILINE_F |
		RTE_REGEX_PCRE_RULE_UCP_F |
		RTE_REGEX_PCRE_RULE_UTF_F |
		HS_REGEX_RULE_SINGLEMATCH_F |
		HS_REGEX_RULE_PREFILTER_F |
		HS_REGEX_RULE_SOM_LEFTMOST_F |
		HS_REGEX_RULE_COMBINATION_F |
		HS_REGEX_RULE_QUIET_F;
	uint64_t flag_bits;
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
		char hash_name[RTE_HASH_NAMESIZE];
		struct rte_hash_parameters hp = {
			.entries = HS_REGEX_MAX_RULES,
			.key_len = sizeof(uint32_t),
			.socket_id = SOCKET_ID_ANY,
		};

		snprintf(hash_name, sizeof(hash_name), "hs_rule_ids_%u",
			 dev->data->dev_id);
		hp.name = hash_name;
		priv->rule_id_hash = rte_hash_create(&hp);
		if (!priv->rule_id_hash) {
			HS_LOG(ERR, "Failed to create rule_id hash");
			return -ENOMEM;
		}
	}

	for (i = 0; i < nb_rules; i++) {
		if (rules[i].op != RTE_REGEX_RULE_OP_ADD &&
		    rules[i].op != RTE_REGEX_RULE_OP_REMOVE) {
			HS_LOG(ERR, "Rule %u: unsupported operation %u",
			       rules[i].rule_id, rules[i].op);
			rte_errno = EINVAL;
			return i;
		}

		flag_bits = rules[i].rule_flags &
			((1ULL << HS_REGEX_EXT_MAX_OFFSET_SHIFT) - 1);

		if (flag_bits & ~known_flags) {
			HS_LOG(ERR, "Rule %u: unsupported flags 0x%" PRIx64,
			       rules[i].rule_id,
			       (uint64_t)(flag_bits & ~known_flags));
			rte_errno = ENOTSUP;
			return i;
		}

		if (rules[i].op == RTE_REGEX_RULE_OP_ADD) {
			int hash_ret;
			uint32_t idx;

			if (rules[i].rule_id > 0xFFFFF) {
				HS_LOG(WARNING,
				       "Rule ID %u exceeds 20-bit match result width; "
				       "reported ID will be truncated",
				       rules[i].rule_id);
			}

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

			hash_ret = rte_hash_add_key(priv->rule_id_hash,
						&rules[i].rule_id);
			if (hash_ret < 0) {
				HS_LOG(ERR, "Rule %u: failed to add rule_id to hash: %d",
				       rules[i].rule_id, hash_ret);
				rte_free(priv->rules[idx].pattern);
				memset(&priv->rules[idx], 0,
				       sizeof(priv->rules[idx]));
				rte_errno = -hash_ret;
				return i;
			}

			priv->nb_rules++;

		} else if (rules[i].op == RTE_REGEX_RULE_OP_REMOVE) {
			int hash_ret;
			uint32_t j;

			for (j = 0; j < priv->nb_rules; j++) {
				if (priv->rules[j].rule_id == rules[i].rule_id)
					break;
			}
			if (j == priv->nb_rules) {
				HS_LOG(ERR, "Rule %u: rule_id not found",
				       rules[i].rule_id);
				rte_errno = ENOENT;
				return i;
			}

			hash_ret = rte_hash_del_key(priv->rule_id_hash,
						&rules[i].rule_id);
			if (hash_ret < 0) {
				HS_LOG(ERR, "Rule %u: failed to remove rule_id from hash: %d",
				       rules[i].rule_id, hash_ret);
				rte_errno = -hash_ret;
				return i;
			}

			rte_free(priv->rules[j].pattern);
			memmove(&priv->rules[j], &priv->rules[j + 1],
				(priv->nb_rules - j - 1) *
				sizeof(struct hs_regex_rule));
			priv->nb_rules--;
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
		priv->db_compiled = 0;
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
		if (priv->rules[i].rule_flags & HS_REGEX_RULE_SINGLEMATCH_F)
			flags[i] |= HS_FLAG_SINGLEMATCH;
		if (priv->rules[i].rule_flags & RTE_REGEX_PCRE_RULE_UTF_F)
			flags[i] |= HS_FLAG_UTF8;
		if (priv->rules[i].rule_flags & RTE_REGEX_PCRE_RULE_UCP_F)
			flags[i] |= HS_FLAG_UCP;
		if (priv->rules[i].rule_flags & HS_REGEX_RULE_PREFILTER_F)
			flags[i] |= HS_FLAG_PREFILTER;
		if (priv->rules[i].rule_flags & HS_REGEX_RULE_SOM_LEFTMOST_F)
			flags[i] |= HS_FLAG_SOM_LEFTMOST;
		if (priv->rules[i].rule_flags & HS_REGEX_RULE_COMBINATION_F)
			flags[i] |= HS_FLAG_COMBINATION;
		if (priv->rules[i].rule_flags & HS_REGEX_RULE_QUIET_F)
			flags[i] |= HS_FLAG_QUIET;
		if (priv->rules[i].rule_flags & RTE_REGEX_PCRE_RULE_ALLOW_EMPTY_F)
			flags[i] |= HS_FLAG_ALLOWEMPTY;

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

	if (rule_db_len > HS_REGEX_MAX_RULE_DB_LEN) {
		HS_LOG(ERR, "rule_db_len %u exceeds max %u",
		       rule_db_len, HS_REGEX_MAX_RULE_DB_LEN);
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
	priv->db_compiled = 0;

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

/* Start */
static int
hs_regex_start(struct rte_regexdev *dev)
{
	struct hs_regex_priv *priv;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	/* Start requires configure and a compiled/imported database. */
	if (priv->dev_state == HS_REGEX_DEV_CREATED) {
		HS_LOG(ERR, "Cannot start: device not configured");
		return -EINVAL;
	}
	if (priv->dev_state == HS_REGEX_DEV_STARTED) {
		HS_LOG(ERR, "Device already started");
		return -EBUSY;
	}

	if (!priv->db_compiled) {
		HS_LOG(ERR, "Cannot start: database not compiled/imported");
		return -EINVAL;
	}

	priv->dev_state = HS_REGEX_DEV_STARTED;
	HS_LOG(INFO, "Device started (%u rules, %u queue pairs)",
	       priv->nb_rules, priv->nb_queue_pairs);
	return 0;
}

/* Stop */
static int
hs_regex_stop(struct rte_regexdev *dev)
{
	struct hs_regex_priv *priv;
	uint16_t i;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	/* Stop is valid only from STARTED state. */
	if (priv->dev_state != HS_REGEX_DEV_STARTED) {
		HS_LOG(ERR, "Device not started, cannot stop");
		return -EINVAL;
	}

	if (priv->qps == NULL)
		goto stopped;

	for (i = 0; i < priv->nb_queue_pairs; i++) {
		struct hs_regex_qp *qp = &priv->qps[i];

		if (qp->count > 0)
			HS_LOG(WARNING,
			       "qp %u: stopping with %u ops still pending "
			       "(not returned to application)",
			       i, qp->count);
		qp->head = 0;
		qp->tail = 0;
		qp->count = 0;
	}

stopped:
	priv->dev_state = HS_REGEX_DEV_STOPPED;
	HS_LOG(INFO, "Device stopped");
	return 0;
}

/* Close */
static int
hs_regex_close(struct rte_regexdev *dev)
{
	struct hs_regex_priv *priv;
	uint32_t i;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	/* Close may be called without an explicit stop. */
	if (priv->dev_state == HS_REGEX_DEV_STARTED) {
		HS_LOG(WARNING, "Device still started, stopping before close");
		hs_regex_stop(dev);
	}

	if (priv->qps) {
		for (i = 0; i < priv->nb_queue_pairs; i++) {
			if (priv->qps[i].scratch)
				hs_free_scratch(priv->qps[i].scratch);
			rte_free(priv->qps[i].ops);
		}
		rte_free(priv->qps);
		priv->qps = NULL;
	}

	if (priv->db) {
		hs_free_database(priv->db);
		priv->db = NULL;
	}

	for (i = 0; i < priv->nb_rules; i++)
		rte_free(priv->rules[i].pattern);
	rte_free(priv->rules);
	priv->rules = NULL;
	priv->nb_rules = 0;
	priv->rules_cap = 0;
	priv->db_compiled = 0;

	if (priv->rule_id_hash) {
		rte_hash_free(priv->rule_id_hash);
		priv->rule_id_hash = NULL;
	}

	/* Return to initial state. */
	priv->dev_state = HS_REGEX_DEV_CREATED;

	HS_LOG(INFO, "Device closed");
	return 0;
}

/* Dump */
static int
hs_regex_dump(struct rte_regexdev *dev, FILE *f)
{
	struct hs_regex_priv *priv;
	uint64_t total_enq = 0, total_deq = 0, total_match = 0;
	uint32_t i;

	if (dev == NULL || f == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	if (priv->qps != NULL) {
		for (i = 0; i < priv->nb_queue_pairs; i++) {
			total_enq += priv->qps[i].qp_enqueued;
			total_deq += priv->qps[i].qp_dequeued;
			total_match += priv->qps[i].qp_matches;
		}
	}

	fprintf(f, "=== Hyperscan RegEx PMD ===\n");
	fprintf(f, "  Driver:      %s\n", HS_REGEX_DRIVER_NAME);
	fprintf(f, "  HS Version:  %s\n", hs_version());
	fprintf(f, "  Rules:       %u\n", priv->nb_rules);
	fprintf(f, "  Compiled:    %s\n", priv->db_compiled ? "yes" : "no");
	fprintf(f, "  Queue Pairs: %u\n", priv->nb_queue_pairs);
	fprintf(f, "  Max Matches: %u\n", priv->max_matches);
	fprintf(f, "  Enqueued:    %" PRIu64 "\n", total_enq);
	fprintf(f, "  Dequeued:    %" PRIu64 "\n", total_deq);
	fprintf(f, "  Matches:     %" PRIu64 "\n", total_match);

	if (priv->qps != NULL) {
		for (i = 0; i < priv->nb_queue_pairs; i++)
			fprintf(f, "  QP[%u]: enqueued=%" PRIu64
				" dequeued=%" PRIu64 " matches=%" PRIu64 "\n",
				i, priv->qps[i].qp_enqueued,
				priv->qps[i].qp_dequeued,
				priv->qps[i].qp_matches);
	}

	for (i = 0; i < priv->nb_rules && i < HS_REGEX_DUMP_MAX_RULES; i++)
		fprintf(f, "  Rule[%u]: id=%u group=%u pattern=%s\n", i,
			priv->rules[i].rule_id, priv->rules[i].group_id,
			priv->rules[i].pattern);
	if (priv->nb_rules > HS_REGEX_DUMP_MAX_RULES)
		fprintf(f, "  ... and %u more rules omitted\n",
			priv->nb_rules - HS_REGEX_DUMP_MAX_RULES);

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
		/*
		 * Auto-start if DB is ready (supports apps that skip
		 * start, e.g. dpdk-test-regex; see hs.rst).
		 */
		if (priv->db_compiled) {
			priv->dev_state = HS_REGEX_DEV_STARTED;
			HS_LOG(NOTICE, "enqueue: auto-started device");
		} else {
			HS_LOG(ERR, "enqueue: device not started and no DB");
			return 0;
		}
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
		ctx.stop_on_match = !!(op->req_flags &
			RTE_REGEX_OPS_REQ_STOP_ON_MATCH_F);
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
		qp->tail = (qp->tail + 1) & (qp->nb_desc - 1);
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
		qp->head = (qp->head + 1) & (qp->nb_desc - 1);
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
	.dev_start = hs_regex_start,
	.dev_stop = hs_regex_stop,
	.dev_close = hs_regex_close,
	.dev_attr_get = NULL,
	.dev_attr_set = NULL,
	.dev_rule_db_update = hs_regex_rule_db_update,
	.dev_rule_db_compile_activate = hs_regex_rule_db_compile_activate,
	.dev_db_import = hs_regex_rule_db_import,
	.dev_db_export = hs_regex_rule_db_export,
	.dev_xstats_names_get = hs_regex_xstats_names_get,
	.dev_xstats_get = hs_regex_xstats_get,
	.dev_xstats_by_name_get = NULL,
	.dev_xstats_reset = hs_regex_xstats_reset,
	.dev_selftest = NULL,
	.dev_dump = hs_regex_dump,
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
		hs_regex_close(dev);
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

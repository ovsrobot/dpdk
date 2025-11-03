/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2025 Alex Kiselev, alex at BisonRouter.com
 */
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/queue.h>

#include <rte_log.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_per_lcore.h>
#include <rte_string_fns.h>
#include <rte_errno.h>
#include <rte_rwlock.h>
#include <rte_spinlock.h>
#include <rte_hash.h>
#include <assert.h>
#include <rte_jhash.h>
#include <rte_tailq.h>
#include <rte_ip6.h>
#include "lpm_log.h"
#include "rte_lpm6c.h"

#define RULE_HASH_TABLE_EXTRA_SPACE              64
#define TBL24_IND                        UINT32_MAX

TAILQ_HEAD(rte_lpm6c_list, rte_tailq_entry);

static struct rte_tailq_elem rte_lpm6c_tailq = {
	.name = "RTR_LPM6C",
};
EAL_REGISTER_TAILQ(rte_lpm6c_tailq)

/*
 * Convert a depth to a one byte long mask
 *   Example: 4 will be converted to 0xF0
 */
static uint8_t __rte_pure
depth_to_mask_1b(uint8_t depth)
{
	/* To calculate a mask start with a 1 on the left hand side and right
	 * shift while populating the left hand side with 1's
	 */
	return (signed char)0x80 >> (depth - 1);
}

/*
 * LPM6 rule hash function
 *
 * It's used as a hash function for the rte_hash
 *	containing rules
 */
static inline uint32_t
rule_hash(const void *data, __rte_unused uint32_t data_len,
		  uint32_t init_val)
{
	return rte_jhash(data, sizeof(struct rte_lpm6c_rule_key), init_val);
}

/*
 * Init pool of free tbl8 indexes
 */
static void
tbl8_pool_init(struct rte_lpm6c *lpm)
{
	uint32_t i;

	/* put entire range of indexes to the tbl8 pool */
	for (i = 0; i < lpm->number_tbl8s; i++)
		lpm->tbl8_pool[i] = i;

	lpm->tbl8_pool_pos = 0;
}

/*
 * Get an index of a free tbl8 from the pool
 */
static inline uint32_t
tbl8_get(struct rte_lpm6c *lpm, uint32_t *tbl8_ind)
{
	if (lpm->tbl8_pool_pos == lpm->number_tbl8s)
		/* no more free tbl8 */
		return -ENOSPC;

	/* next index */
	*tbl8_ind = lpm->tbl8_pool[lpm->tbl8_pool_pos++];
	return 0;
}

/*
 * Put an index of a free tbl8 back to the pool
 */
static inline uint32_t
tbl8_put(struct rte_lpm6c *lpm, uint32_t tbl8_ind)
{
	if (lpm->tbl8_pool_pos == 0)
		/* pool is full */
		return -ENOSPC;

	lpm->tbl8_pool[--lpm->tbl8_pool_pos] = tbl8_ind;
	return 0;
}

/*
 * Init a rule key.
 *	  note that ip must be already masked
 */
static inline void
rule_key_init(struct rte_lpm6c_rule_key *key, const struct rte_ipv6_addr *ip,
		  uint8_t depth)
{
	key->ip = *ip;
	key->depth = depth;
}

/*
 * Allocates memory for LPM object
 */
struct rte_lpm6c *
rte_lpm6c_create(const char *name, int socket_id,
		const struct rte_lpm6c_config *config)
{
	char mem_name[RTE_LPM6C_NAMESIZE];
	struct rte_lpm6c *lpm = NULL;
	struct rte_tailq_entry *te;
	uint64_t mem_size;
	struct rte_lpm6c_list *lpm_list;
	struct rte_hash *rules_tbl = NULL;
	uint32_t *tbl8_pool = NULL;
	struct rte_lpm6c_tbl8_hdr *tbl8_hdrs = NULL;

	lpm_list = RTE_TAILQ_CAST(rte_lpm6c_tailq.head, rte_lpm6c_list);

	RTE_BUILD_BUG_ON(sizeof(struct rte_lpm6c_tbl_entry) != sizeof(uint32_t));

	/* Check user arguments. */
	if ((name == NULL) || (socket_id < -1) || (config == NULL) ||
			(config->max_rules == 0) ||
			config->number_tbl8s > RTE_LPM6C_TBL8_MAX_NUM_GROUPS) {
		rte_errno = EINVAL;
		return NULL;
	}

	/* create rules hash table */
	snprintf(mem_name, sizeof(mem_name), "LRH_%s", name);
	struct rte_hash_parameters rule_hash_tbl_params = {
		.entries = config->max_rules * 1.2 +
			RULE_HASH_TABLE_EXTRA_SPACE,
		.key_len = sizeof(struct rte_lpm6c_rule_key),
		.hash_func = rule_hash,
		.hash_func_init_val = 0,
		.name = mem_name,
		.reserved = 0,
		.socket_id = socket_id,
		.extra_flag = 0
	};

	rules_tbl = rte_hash_create(&rule_hash_tbl_params);
	if (rules_tbl == NULL) {
		LPM_LOG(ERR, "LPM rules hash table allocation failed: %s (%d)",
				  rte_strerror(rte_errno), rte_errno);
		goto fail_wo_unlock;
	}

	/* allocate tbl8 indexes pool */
	tbl8_pool = rte_malloc(NULL,
			sizeof(uint32_t) * config->number_tbl8s,
			RTE_CACHE_LINE_SIZE);
	if (tbl8_pool == NULL) {
		LPM_LOG(ERR, "LPM tbl8 pool allocation failed: %s (%d)",
				  rte_strerror(rte_errno), rte_errno);
		rte_errno = ENOMEM;
		goto fail_wo_unlock;
	}

	/* allocate tbl8 headers */
	tbl8_hdrs = rte_malloc(NULL,
			sizeof(struct rte_lpm6c_tbl8_hdr) * config->number_tbl8s,
			RTE_CACHE_LINE_SIZE);
	if (tbl8_hdrs == NULL) {
		LPM_LOG(ERR, "LPM tbl8 headers allocation failed: %s (%d)",
				  rte_strerror(rte_errno), rte_errno);
		rte_errno = ENOMEM;
		goto fail_wo_unlock;
	}

	snprintf(mem_name, sizeof(mem_name), "LPM_%s", name);

	/* Determine the amount of memory to allocate. */
	mem_size = sizeof(*lpm) + (sizeof(lpm->tbl8[0]) * config->number_tbl8s);

	rte_mcfg_tailq_write_lock();

	/* Guarantee there's no existing */
	TAILQ_FOREACH(te, lpm_list, next) {
		lpm = (struct rte_lpm6c *) te->data;
		if (strncmp(name, lpm->name, RTE_LPM6C_NAMESIZE) == 0)
			break;
	}
	lpm = NULL;
	if (te != NULL) {
		rte_errno = EEXIST;
		goto fail;
	}

	/* allocate tailq entry */
	te = rte_zmalloc("LPM6_TAILQ_ENTRY", sizeof(*te), 0);
	if (te == NULL) {
		LPM_LOG(ERR, "Failed to allocate tailq entry!");
		rte_errno = ENOMEM;
		goto fail;
	}

	/* Allocate memory to store the LPM data structures. */
	lpm = rte_zmalloc_socket(mem_name, (size_t)mem_size,
			RTE_CACHE_LINE_SIZE, socket_id);

	if (lpm == NULL) {
		LPM_LOG(ERR, "LPM memory allocation failed");
		rte_free(te);
		rte_errno = ENOMEM;
		goto fail;
	}

	/* Save user arguments. */
	lpm->max_rules = config->max_rules;
	lpm->number_tbl8s = config->number_tbl8s;
	snprintf(lpm->name, sizeof(lpm->name), "%s", name);
	lpm->rules_tbl = rules_tbl;
	lpm->tbl8_pool = tbl8_pool;
	lpm->tbl8_hdrs = tbl8_hdrs;

	/* init the stack */
	tbl8_pool_init(lpm);

	te->data = (void *) lpm;

	TAILQ_INSERT_TAIL(lpm_list, te, next);
	rte_mcfg_tailq_write_unlock();
	return lpm;

fail:
	rte_mcfg_tailq_write_unlock();

fail_wo_unlock:
	rte_free(tbl8_hdrs);
	rte_free(tbl8_pool);
	rte_hash_free(rules_tbl);

	return NULL;
}

/*
 * Find an existing lpm table and return a pointer to it.
 */
struct rte_lpm6c *
rte_lpm6c_find_existing(const char *name)
{
	struct rte_lpm6c *l = NULL;
	struct rte_tailq_entry *te;
	struct rte_lpm6c_list *lpm_list;

	lpm_list = RTE_TAILQ_CAST(rte_lpm6c_tailq.head, rte_lpm6c_list);

	rte_mcfg_tailq_read_lock();
	TAILQ_FOREACH(te, lpm_list, next) {
		l = (struct rte_lpm6c *) te->data;
		if (strncmp(name, l->name, RTE_LPM6C_NAMESIZE) == 0)
			break;
	}
	rte_mcfg_tailq_read_unlock();

	if (te == NULL) {
		rte_errno = ENOENT;
		return NULL;
	}

	return l;
}

/*
 * De-allocates memory for given LPM table.
 */
void
rte_lpm6c_free(struct rte_lpm6c *lpm)
{
	struct rte_lpm6c_list *lpm_list;
	struct rte_tailq_entry *te;

	/* Check user arguments. */
	if (lpm == NULL)
		return;

	lpm_list = RTE_TAILQ_CAST(rte_lpm6c_tailq.head, rte_lpm6c_list);

	rte_mcfg_tailq_write_lock();

	/* find our tailq entry */
	TAILQ_FOREACH(te, lpm_list, next) {
		if (te->data == (void *) lpm)
			break;
	}

	if (te != NULL)
		TAILQ_REMOVE(lpm_list, te, next);

	rte_mcfg_tailq_write_unlock();

	rte_free(lpm->tbl8_hdrs);
	rte_free(lpm->tbl8_pool);
	rte_hash_free(lpm->rules_tbl);
	rte_free(lpm);
	rte_free(te);
}

/* Find a rule */
static inline int
rule_find_with_key(struct rte_lpm6c *lpm,
		  const struct rte_lpm6c_rule_key *rule_key,
		  uint32_t *next_hop)
{
	uint64_t hash_val;
	int ret;

	/* lookup for a rule */
	ret = rte_hash_lookup_data(lpm->rules_tbl, (const void *)rule_key,
		(void **)&hash_val);
	if (ret >= 0) {
		*next_hop = (uint32_t) hash_val;
		return 1;
	}

	return 0;
}

/* Find a rule */
static int
rule_find(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip, uint8_t depth,
		  uint32_t *next_hop)
{
	struct rte_lpm6c_rule_key rule_key;

	/* init a rule key */
	rule_key_init(&rule_key, ip, depth);

	return rule_find_with_key(lpm, &rule_key, next_hop);
}

/*
 * Checks if a rule already exists in the rules table and updates
 * the nexthop if so. Otherwise it adds a new rule if enough space is available.
 *
 * Returns:
 *    0 - next hop of existed rule is updated
 *    1 - new rule successfully added
 *   <0 - error
 */
static inline int
rule_add(struct rte_lpm6c *lpm, struct rte_ipv6_addr *ip, uint8_t depth,
		  uint32_t next_hop)
{
	int ret, rule_exist;
	struct rte_lpm6c_rule_key rule_key;
	uint32_t unused;

	/* init a rule key */
	rule_key_init(&rule_key, ip, depth);

	/* Scan through rule list to see if rule already exists. */
	rule_exist = rule_find_with_key(lpm, &rule_key, &unused);

	/*
	 * If rule does not exist check if there is space to add a new rule to
	 * this rule group. If there is no space return error.
	 */
	if (!rule_exist && lpm->used_rules == lpm->max_rules)
		return -ENOSPC;

	/* add the rule or update rules next hop */
	ret = rte_hash_add_key_data(lpm->rules_tbl, &rule_key,
		(void *)(uintptr_t) next_hop);
	if (ret < 0)
		return ret;

	/* Increment the used rules counter for this rule group. */
	if (!rule_exist) {
		lpm->used_rules++;
		return 1;
	}

	return 0;
}

/*
 * Find a less specific rule
 */
static int
rule_find_less_specific(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth, struct rte_lpm6c_rule *rule)
{
	int ret;
	uint32_t next_hop;
	uint8_t mask;
	struct rte_lpm6c_rule_key rule_key;

	if (depth == 1)
		return 0;

	rule_key_init(&rule_key, ip, depth);

	while (depth > 1) {
		depth--;

		/* each iteration zero one more bit of the key */
		mask = depth & 7; /* depth % RTE_LPM6C_BYTE_SIZE */
		if (mask > 0)
			mask = depth_to_mask_1b(mask);

		rule_key.depth = depth;
		rule_key.ip.a[depth >> 3] &= mask;

		ret = rule_find_with_key(lpm, &rule_key, &next_hop);
		if (ret) {
			rule->depth = depth;
			rule->ip = rule_key.ip;
			rule->next_hop = next_hop;
			return 1;
		}
	}

	return 0;
}

/*
 * Function that expands a rule across the data structure when a less-generic
 * one has been added before. It assures that every possible combination of bits
 * in the IP address returns a match.
 */
static void
expand_rule(struct rte_lpm6c *lpm, uint32_t tbl8_ind, uint8_t old_depth,
		uint8_t new_depth, uint32_t next_hop, uint8_t valid)
{
	uint32_t j;
	struct rte_lpm6c_tbl8_hdr *tbl_hdr;
	struct rte_lpm6c_tbl8 *tbl;
	struct rte_lpm6c_tbl_entry *entries;

	tbl_hdr = &lpm->tbl8_hdrs[tbl8_ind];
	tbl = &lpm->tbl8[tbl8_ind];

	if (tbl_hdr->lsp_depth <= old_depth ||
			  tbl->lsp_next_hop == RTE_LPM6C_UNDEF_NEXT_HOP) {
		if (valid) {
			tbl->lsp_next_hop = next_hop;
			tbl_hdr->lsp_depth = new_depth;
		} else
			tbl->lsp_next_hop = RTE_LPM6C_UNDEF_NEXT_HOP;
	}

	entries = lpm->tbl8[tbl8_ind].entries;

	struct rte_lpm6c_tbl_entry new_tbl8_entry = {
		.valid = valid,
		.valid_group = valid,
		.depth = new_depth,
		.next_hop = next_hop,
		.ext_entry = 0,
	};

	for (j = 0; j < RTE_LPM6C_TBL8_GROUP_NUM_ENTRIES; j++)
		if (!entries[j].valid || (entries[j].ext_entry == 0
				&& entries[j].depth <= old_depth)) {

			entries[j] = new_tbl8_entry;

		} else if (entries[j].ext_entry == 1) {

			expand_rule(lpm, entries[j].lpm6_tbl8_ind,
					  old_depth, new_depth, next_hop, valid);
		}
}

/*
 * Init a tbl8 header
 */
static inline void
init_tbl8_header(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth, uint32_t tbl_ind, uint32_t owner_tbl_ind,
		  uint32_t owner_entry_ind, uint32_t lsp_next_hop, uint8_t lsp_depth)
{
	struct rte_lpm6c_tbl8_hdr *tbl_hdr = &lpm->tbl8_hdrs[tbl_ind];
	struct rte_lpm6c_tbl8 *tbl = &lpm->tbl8[tbl_ind];

	tbl_hdr->owner_tbl_ind = owner_tbl_ind;
	tbl_hdr->owner_entry_ind = owner_entry_ind;

	tbl_hdr->nb_ext  = 0;
	tbl_hdr->nb_rule  = 0;

	tbl->ip = *ip;
	rte_ipv6_addr_mask(&tbl->ip, depth);
	tbl_hdr->depth = depth;

	tbl_hdr->lsp_depth = lsp_depth;
	tbl->lsp_next_hop = lsp_next_hop;
}

/*
 * Calculate index to the table based on the number and position
 * of the bytes being inspected in this step.
 */
static uint32_t
get_bitshift(const struct rte_ipv6_addr *ip, uint8_t first_byte, uint8_t bytes)
{
	uint32_t entry_ind, i;
	int8_t bitshift;

	entry_ind = 0;
	for (i = first_byte; i < (uint32_t)(first_byte + bytes); i++) {
		bitshift = (int8_t)((bytes - i) * RTE_LPM6C_BYTE_SIZE);

		if (bitshift < 0)
			bitshift = 0;
		entry_ind = entry_ind | ip->a[i - 1] << bitshift;
	}

	return entry_ind;
}

/*
 * Returns number of free tbl8s
 */
uint32_t
rte_lpm6c_tbl8_available(struct rte_lpm6c *lpm)
{
	return lpm->number_tbl8s - lpm->tbl8_pool_pos;
}

/*
 * Returns number of tbl8s in use
 */
uint32_t
rte_lpm6c_tbl8_in_use(struct rte_lpm6c *lpm)
{
	return lpm->tbl8_pool_pos;
}

int
rte_lpm6c_is_rule_present(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth, uint32_t *next_hop)
{
	struct rte_ipv6_addr masked_ip;

	/* Check user arguments. */
	if ((lpm == NULL) || next_hop == NULL || ip == NULL ||
			(depth < 1) || (depth > RTE_IPV6_MAX_DEPTH))
		return -EINVAL;

	/* Copy the IP and mask it to avoid modifying user's input data. */
	masked_ip = *ip;
	rte_ipv6_addr_mask(&masked_ip, depth);

	return rule_find(lpm, &masked_ip, depth, next_hop);
}

static uint8_t
depth_to_level(uint8_t depth)
{
	if (depth <= RTE_LPM6C_ROOT_LEV_BYTES * RTE_LPM6C_BYTE_SIZE)
		return 0;
	return 1 + (depth - 1 - RTE_LPM6C_ROOT_LEV_BYTES * RTE_LPM6C_BYTE_SIZE) /
			  RTE_LPM6C_BYTE_SIZE;
}

static uint8_t
level_to_depth(uint8_t level)
{
	if (level == 0)
		return 0;
	return (RTE_LPM6C_ROOT_LEV_BYTES + level - 1) * RTE_LPM6C_BYTE_SIZE;
}

#define LPM6_TBL_NOT_FOUND 0
#define LPM6_DEST_TBL_FOUND 1
#define LPM6_INTRM_TBL_FOUND 2

static int
find_table(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip, uint8_t depth,
		  uint8_t *p_level, struct rte_lpm6c_tbl_entry **p_tbl,
		  uint32_t *p_tbl_ind, uint32_t *p_entry_ind)
{
	uint8_t bits, first_byte, bytes, level;
	struct rte_ipv6_addr masked_ip;
	uint32_t entry_ind, tbl_ind, ext_tbl_ind;
	int ret;
	struct rte_lpm6c_tbl_entry *entries;
	struct rte_lpm6c_tbl8_hdr *tbl_hdr;
	struct rte_lpm6c_tbl8 *tbl8;

	entries = *p_tbl;
	tbl_ind = *p_tbl_ind;
	level = *p_level;

	while (1) {
		if (level == 0) {
			first_byte = 1;
			bytes = RTE_LPM6C_ROOT_LEV_BYTES;
		} else {
			first_byte = RTE_LPM6C_ROOT_LEV_BYTES + level;
			bytes = 1;
		}

		/*
		 * Calculate index to the table based on the number and position
		 * of the bytes being inspected in this step.
		 */
		entry_ind = get_bitshift(ip, first_byte, bytes);
		/* Number of bits covered in this step */
		bits = (uint8_t)((bytes + first_byte - 1) * RTE_LPM6C_BYTE_SIZE);

		/*
		 * If depth if smaller than this number,
		 * then the destination (last level) table is found.
		 */
		if (depth <= bits) {
			ret = LPM6_DEST_TBL_FOUND;
			break;
		}
		if (!entries[entry_ind].valid || entries[entry_ind].ext_entry == 0) {
			ret = LPM6_INTRM_TBL_FOUND;
			break;
		}

		/* follow the reference to the next level */
		assert(entries[entry_ind].ext_entry == 1);
		level = entries[entry_ind].depth;

		/* check that the next level is still on the prefix path */
		if (depth < level_to_depth(level) + 1) {
			ret = LPM6_TBL_NOT_FOUND;
			break;
		}

		/* Check that the next level table is still on the prefix path */
		ext_tbl_ind = entries[entry_ind].lpm6_tbl8_ind;
		tbl_hdr = &lpm->tbl8_hdrs[ext_tbl_ind];
		tbl8 = &lpm->tbl8[ext_tbl_ind];
		masked_ip = *ip;
		rte_ipv6_addr_mask(&masked_ip, tbl_hdr->depth);
		if (!rte_ipv6_addr_eq(&tbl8->ip, &masked_ip)) {
			ret = LPM6_TBL_NOT_FOUND;
			break;
		}

		tbl_ind = ext_tbl_ind;
		entries = lpm->tbl8[tbl_ind].entries;
		*p_level = level;
	}

	*p_tbl = entries;
	*p_tbl_ind = tbl_ind;
	*p_entry_ind = entry_ind;
	return ret;
}

static void
fill_dst_tbl(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth, struct rte_lpm6c_tbl_entry *tbl, uint8_t level,
		  uint32_t tbl_ind, int is_new_rule, uint32_t next_hop)
{
	uint32_t entry_ind, tbl_range, i;
	uint8_t bits_covered, first_byte, bytes;

	if (level == 0) {
		first_byte = 1;
		bytes = RTE_LPM6C_ROOT_LEV_BYTES;
	} else {
		first_byte = RTE_LPM6C_ROOT_LEV_BYTES + level;
		bytes = 1;
	}

	/*
	 * Calculate index to the table based on the number and position
	 * of the bytes being inspected in this step.
	 */
	entry_ind = get_bitshift(ip, first_byte, bytes);
	/* Number of bits covered in this step */
	bits_covered = (uint8_t)((bytes + first_byte - 1) * RTE_LPM6C_BYTE_SIZE);

	/*
	 * If depth if smaller than this number (i.e. this is the last step)
	 * expand the rule across the relevant positions in the table.
	 */
	assert(depth <= bits_covered);
	tbl_range = 1 << (bits_covered - depth);

	for (i = entry_ind; i < (entry_ind + tbl_range); i++) {
		if (!tbl[i].valid || (tbl[i].ext_entry == 0 &&
				tbl[i].depth <= depth)) {

			struct rte_lpm6c_tbl_entry new_tbl_entry = {
				.next_hop = next_hop,
				.depth = depth,
				.valid = VALID,
				.valid_group = VALID,
				.ext_entry = 0,
			};

			tbl[i] = new_tbl_entry;

		} else if (tbl[i].ext_entry == 1) {
			/*
			 * If tbl entry is valid and extended calculate the index
			 * into next tbl8 and expand the rule across the data structure.
			 */
			expand_rule(lpm, tbl[i].lpm6_tbl8_ind, depth, depth,
					  next_hop, VALID);
		}
	}

	/* increase the number of rules saved in the table */
	if (tbl_ind != TBL24_IND && is_new_rule)
		lpm->tbl8_hdrs[tbl_ind].nb_rule++;
}

static int
add_new_tbl(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth, struct rte_lpm6c_tbl_entry *parent_tbl,
		  uint32_t entry_ind, uint32_t parent_tbl_ind, uint8_t level,
		  struct rte_lpm6c_tbl_entry **p_new_tbl,
		  uint32_t *p_new_tbl_ind)
{
	bool lsp;
	uint8_t lsp_depth;
	int ret;
	uint32_t tbl8_gindex;
	uint32_t lsp_next_hop;
	struct rte_lpm6c_tbl_entry *new_tbl;

	/* get a new tbl8 index */
	ret = tbl8_get(lpm, &tbl8_gindex);
	if (ret != 0)
		return -ENOSPC;
	new_tbl = lpm->tbl8[tbl8_gindex].entries;

	lsp = false;
	lsp_next_hop = RTE_LPM6C_UNDEF_NEXT_HOP;
	lsp_depth = 0;

	if (parent_tbl[entry_ind].valid) {
		if (parent_tbl[entry_ind].ext_entry) {
			struct rte_lpm6c_rule lsp_rule;

			ret = rule_find_less_specific(lpm, ip, depth, &lsp_rule);
			if (ret) {
				lsp = true;
				lsp_next_hop = lsp_rule.next_hop;
				lsp_depth = lsp_rule.depth;
			}
		} else {
			lsp = true;
			lsp_next_hop = parent_tbl[entry_ind].next_hop;
			lsp_depth = parent_tbl[entry_ind].depth;
		}
	}

	/* If it's invalid a new tbl8 is needed */
	if (lsp) {
		/*
		 * If it's valid but not extended the rule that was stored
		 * here needs to be moved to the next table.
		 */
		int i;

		struct rte_lpm6c_tbl_entry tbl_entry = {
			.next_hop = lsp_next_hop,
			.depth = lsp_depth,
			.valid = VALID,
			.valid_group = VALID,
			.ext_entry = 0
		};

		/* Populate new tbl8 with tbl value. */
		for (i = 0; i < RTE_LPM6C_TBL8_GROUP_NUM_ENTRIES; i++)
			new_tbl[i] = tbl_entry;
	} else
		/* invalidate all new tbl8 entries */
		memset(new_tbl, 0,
				  RTE_LPM6C_TBL8_GROUP_NUM_ENTRIES *
				  sizeof(struct rte_lpm6c_tbl_entry));

	/*
	 * Init the new table's header:
	 *   save the reference to the owner table
	 */
	init_tbl8_header(lpm, ip, level_to_depth(level),
			  tbl8_gindex, parent_tbl_ind, entry_ind,
			  lsp_next_hop, lsp_depth);

	/* reference to a new tbl8 */
	struct rte_lpm6c_tbl_entry new_tbl_entry = {
		.lpm6_tbl8_ind = tbl8_gindex,
		.depth = level,
		.valid = VALID,
		.valid_group = VALID,
		.ext_entry = 1,
	};

	parent_tbl[entry_ind] = new_tbl_entry;

	/* increase the number of external entries saved in the parent table */
	if (parent_tbl_ind != TBL24_IND)
		lpm->tbl8_hdrs[parent_tbl_ind].nb_ext++;

	*p_new_tbl = new_tbl;
	*p_new_tbl_ind = tbl8_gindex;
	return 0;
}

static int
add_intermediate_tbl(struct rte_lpm6c *lpm, struct rte_ipv6_addr *ip,
		  uint8_t depth, struct rte_lpm6c_tbl_entry *tbl, uint32_t tbl_ind,
		  uint32_t entry_ind)
{
	int ret, i, cnt;
	uint8_t level;
	uint32_t ext_tbl_ind, interm_tbl_ind;
	struct rte_lpm6c_tbl_entry ext_entry;
	struct rte_lpm6c_tbl8_hdr *ext_tbl_hdr;
	struct rte_lpm6c_tbl8 *tbl8;
	struct rte_lpm6c_tbl_entry *interm_tbl;

	/*
	 * determine the level at which a new intermediate table
	 * should be added
	 */
	ext_entry = tbl[entry_ind];
	assert(ext_entry.ext_entry == 1);
	ext_tbl_ind = ext_entry.lpm6_tbl8_ind;
	ext_tbl_hdr = &lpm->tbl8_hdrs[ext_tbl_ind];
	tbl8 = &lpm->tbl8[ext_tbl_ind];

	/*
	 * ext table's prefix and the given prefix should be
	 * equal at the root level
	 */
	assert(memcmp(ip->a, tbl8->ip.a, RTE_LPM6C_ROOT_LEV_BYTES) == 0);

	cnt = RTE_MIN(depth_to_level(depth), depth_to_level(ext_tbl_hdr->depth));
	for (i = 1; i <= cnt; i++)
		if (ip->a[RTE_LPM6C_ROOT_LEV_BYTES + i - 1] !=
				  tbl8->ip.a[RTE_LPM6C_ROOT_LEV_BYTES + i - 1])
			break;
	level = i > cnt ? cnt : i;

	/* add a new intermediate table */
	ret = add_new_tbl(lpm, ip, depth, tbl, entry_ind, tbl_ind, level,
			  &interm_tbl, &interm_tbl_ind);
	if (ret != 0)
		return ret;

	/* move the initial reference to the intermediate table */
	entry_ind = tbl8->ip.a[RTE_LPM6C_ROOT_LEV_BYTES + level - 1];
	interm_tbl[entry_ind] = ext_entry;
	/* update the header of ext table */
	ext_tbl_hdr->owner_tbl_ind = interm_tbl_ind;
	ext_tbl_hdr->owner_entry_ind = entry_ind;

	if (tbl_ind != TBL24_IND) {
		assert(lpm->tbl8_hdrs[tbl_ind].nb_ext > 0);
		lpm->tbl8_hdrs[tbl_ind].nb_ext--;
	}
	lpm->tbl8_hdrs[interm_tbl_ind].nb_ext++;

	return 0;
}

int
rte_lpm6c_add(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth, uint32_t next_hop)
{
	struct rte_lpm6c_tbl_entry *tbl, *new_tbl;
	int ret, is_new_rule;
	uint32_t tbl_ind, entry_ind;
	uint8_t level;
	struct rte_ipv6_addr masked_ip;

	/* Check user arguments. */
	if ((lpm == NULL) || (depth < 1) || (depth > RTE_IPV6_MAX_DEPTH))
		return -EINVAL;

	/* Copy the IP and mask it to avoid modifying user's input data. */
	masked_ip = *ip;
	rte_ipv6_addr_mask(&masked_ip, depth);

	/*
	 * Check that tbl8 pool contains enough entries to create the longest
	 * path in the tree
	 */
	if (rte_lpm6c_tbl8_available(lpm) < MIN_TBL8_REQ_FOR_ADD)
		return -ENOSPC;

	/* Add the rule to the rule table. */
	is_new_rule = rule_add(lpm, &masked_ip, depth, next_hop);
	/* If there is no space available for new rule return error. */
	if (is_new_rule < 0)
		return is_new_rule;

	level = 0;
	tbl = lpm->tbl24;
	tbl_ind = TBL24_IND;

start:
	ret = find_table(lpm, &masked_ip, depth,
			  &level, &tbl, &tbl_ind, &entry_ind);

	switch (ret) {
	case LPM6_TBL_NOT_FOUND:
		ret = add_intermediate_tbl(lpm, &masked_ip, depth, tbl, tbl_ind,
				  entry_ind);
		if (ret < 0)
			return ret;
		goto start;

	case LPM6_DEST_TBL_FOUND:
		/* fill existing table and expand some cells if necessary */
		fill_dst_tbl(lpm, &masked_ip, depth, tbl, level, tbl_ind,
				  is_new_rule, next_hop);
		ret = 0;
		break;

	case LPM6_INTRM_TBL_FOUND:
		/* link a new table and fill it */
		level = depth_to_level(depth);
		ret = add_new_tbl(lpm, &masked_ip, depth, tbl, entry_ind, tbl_ind, level,
				  &new_tbl, &tbl_ind);
		if (ret < 0)
			break;
		fill_dst_tbl(lpm, &masked_ip, depth, new_tbl, level, tbl_ind,
				  is_new_rule, next_hop);
		ret = 0;
		break;
	}

	return ret;
}

/*
 * Delete a rule from the rule table.
 * NOTE: Valid range for depth parameter is 1 .. 128 inclusive.
 * return
 *	  0 on success
 *   <0 on failure
 */
static inline int
rule_delete(struct rte_lpm6c *lpm, struct rte_ipv6_addr *ip, uint8_t depth)
{
	int ret;
	struct rte_lpm6c_rule_key rule_key;

	/* init rule key */
	rule_key_init(&rule_key, ip, depth);

	/* delete the rule */
	ret = rte_hash_del_key(lpm->rules_tbl, (void *)&rule_key);
	if (ret >= 0)
		lpm->used_rules--;

	return ret;
}

/*
 * Deletes a group of rules
 */
int
rte_lpm6c_delete_bulk_func(struct rte_lpm6c *lpm,
		const struct rte_ipv6_addr *ips, uint8_t *depths, unsigned int n)
{
	unsigned int i;

	/* Check input arguments. */
	if ((lpm == NULL) || (ips == NULL) || (depths == NULL))
		return -EINVAL;

	for (i = 0; i < n; i++)
		rte_lpm6c_delete(lpm, &ips[i], depths[i]);

	return 0;
}

/*
 * Delete all rules from the LPM table.
 */
void
rte_lpm6c_delete_all(struct rte_lpm6c *lpm)
{
	/* Zero used rules counter. */
	lpm->used_rules = 0;

	/* Zero tbl24. */
	memset(lpm->tbl24, 0, sizeof(lpm->tbl24));

	/* Zero tbl8. */
	memset(lpm->tbl8, 0, sizeof(lpm->tbl8[0]) * lpm->number_tbl8s);

	/* init pool of free tbl8 indexes */
	tbl8_pool_init(lpm);

	/* Delete all rules form the rules table. */
	rte_hash_reset(lpm->rules_tbl);
}

/*
 *	Iterate rules
 */
void
rte_lpm6c_rules_iterate_cb(const struct rte_lpm6c *lpm, lpm6_iter_cb cb,
		  void *cb_param)
{
	struct rte_lpm6c_rule_key *rule_key;
	uint64_t next_hop;
	uint32_t iter = 0;

	while (rte_hash_iterate(lpm->rules_tbl, (void *)&rule_key,
			(void **)&next_hop, &iter) >= 0)
		cb(cb_param, &rule_key->ip, rule_key->depth, (uint32_t) next_hop);
}

int32_t
rte_lpm6c_rules_iterate(const struct rte_lpm6c *lpm, uint32_t *iter,
		  const struct rte_ipv6_addr **ip, uint8_t *depth, uint32_t *next_hop)
{
	uint64_t hash_val;
	const struct rte_lpm6c_rule_key *rule_key;

	int32_t ret = rte_hash_iterate(lpm->rules_tbl, (void *)&rule_key,
			(void **)&hash_val, iter);
	if (ret >= 0) {
		*ip = &rule_key->ip;
		*depth = rule_key->depth;
		*next_hop = (uint32_t)hash_val;
	}

	return ret;
}

/*
 * Remove an intermediate table
 */
static void
del_intermediate_tbl(struct rte_lpm6c *lpm, uint32_t tbl_ind,
		  struct rte_lpm6c_tbl8_hdr *tbl_hdr)
{
	unsigned int i;
	struct rte_lpm6c_tbl_entry *entry, *owner_entry;
	struct rte_lpm6c_tbl8_hdr *ext_tbl_hdr;

	assert(tbl_hdr->nb_ext == 1);
	entry = lpm->tbl8[tbl_ind].entries;
	for (i = 0; i < RTE_LPM6C_TBL8_GROUP_NUM_ENTRIES; i++, entry++)
		if (entry->ext_entry == 1)
			break;
	assert(i < RTE_LPM6C_TBL8_GROUP_NUM_ENTRIES);

	/*
	 * move found external entry from the intermediate
	 * table to the intermediate's parent table
	 */
	if (tbl_hdr->owner_tbl_ind == TBL24_IND)
		owner_entry = &lpm->tbl24[tbl_hdr->owner_entry_ind];
	else
		owner_entry = &lpm->tbl8[tbl_hdr->owner_tbl_ind].entries[
			tbl_hdr->owner_entry_ind];
	*owner_entry = *entry;

	/* update the header of ext table */
	ext_tbl_hdr = &lpm->tbl8_hdrs[entry->next_hop];
	ext_tbl_hdr->owner_tbl_ind = tbl_hdr->owner_tbl_ind;
	ext_tbl_hdr->owner_entry_ind = tbl_hdr->owner_entry_ind;

	tbl8_put(lpm, tbl_ind);
}

/*
 * Remove a table from the LPM tree
 */
static void
remove_tbl(struct rte_lpm6c *lpm, struct rte_lpm6c_tbl8_hdr *tbl_hdr,
		  uint32_t tbl_ind, struct rte_lpm6c_rule *lsp_rule)
{
	struct rte_lpm6c_tbl_entry *owner_entry;

	if (tbl_hdr->owner_tbl_ind == TBL24_IND) {
		owner_entry = &lpm->tbl24[tbl_hdr->owner_entry_ind];
		assert(owner_entry->ext_entry == 1);
	} else {
		uint32_t owner_tbl_ind;
		struct rte_lpm6c_tbl8_hdr *owner_tbl_hdr;

		owner_tbl_ind = tbl_hdr->owner_tbl_ind;
		owner_entry = &lpm->tbl8[owner_tbl_ind].entries[
			tbl_hdr->owner_entry_ind];
		assert(owner_entry->ext_entry == 1);

		owner_tbl_hdr = &lpm->tbl8_hdrs[owner_tbl_ind];
		owner_tbl_hdr->nb_ext--;
		if (owner_tbl_hdr->nb_ext == 1 && owner_tbl_hdr->nb_rule == 0) {
			/*
			 * down external flag in order to del_intermediate_tbl()
			 * find the right (last one) external entry
			 */
			owner_entry->ext_entry = 0;
			del_intermediate_tbl(lpm, owner_tbl_ind, owner_tbl_hdr);
			tbl8_put(lpm, tbl_ind);
			return;
		}
	}

	/* unlink the table */
	if (lsp_rule != NULL) {
		struct rte_lpm6c_tbl_entry new_tbl_entry = {
			.next_hop = lsp_rule->next_hop,
			.depth = lsp_rule->depth,
			.valid = VALID,
			.valid_group = VALID,
			.ext_entry = 0
		};

		*owner_entry = new_tbl_entry;
	} else {
		struct rte_lpm6c_tbl_entry new_tbl_entry = {
			.next_hop = 0,
			.depth = 0,
			.valid = INVALID,
			.valid_group = INVALID,
			.ext_entry = 0
		};

		*owner_entry = new_tbl_entry;
	}

	/* return the table to the pool */
	tbl8_put(lpm, tbl_ind);
}

/*
 * Find range of tbl8 cells occupied by a rule
 */
static void
rule_find_range(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth, struct rte_lpm6c_tbl_entry **from,
		  struct rte_lpm6c_tbl_entry **to,
		  uint32_t *out_tbl_ind)
{
	uint32_t ind = 0;
	uint32_t first_3bytes = RTE_LPM6C_ROOT_TBL_IND(ip);

	if (depth <= RTE_LPM6C_ROOT_LEVEL_BITS) {
		/* rule is within the top level */
		ind = first_3bytes;
		*from = &lpm->tbl24[ind];
		ind += (1 << (24 - depth)) - 1;
		*to = &lpm->tbl24[ind];
		*out_tbl_ind = TBL24_IND;
	} else {
		int i;
		uint32_t level = 0;
		uint32_t tbl_ind = 0;
		struct rte_lpm6c_tbl_entry *entry;
		struct rte_lpm6c_tbl_entry *entries = NULL;

		/* top level entry */
		entry = &lpm->tbl24[first_3bytes];
		assert(entry->ext_entry == 1);
		/* iterate through levels until we reach the last one */
		do {
			if (level_to_depth(entry->depth) >= depth)
				break;
			level = entry->depth;
			tbl_ind = entry->lpm6_tbl8_ind;
			entries = lpm->tbl8[tbl_ind].entries;
			ind = ip->a[RTE_LPM6C_ROOT_LEV_BYTES + level - 1];
			entry = &entries[ind];
		} while (entry->ext_entry == 1);

		/* last level */
		*from = entry;
		assert(depth > level_to_depth(level));
		i = depth - level_to_depth(level);
		assert(i <= RTE_LPM6C_BYTE_SIZE);
		ind += (1 << (RTE_LPM6C_BYTE_SIZE - i)) - 1;
		assert(entries != NULL);
		*to = &entries[ind];
		*out_tbl_ind = tbl_ind;
	}
}

/*
 * Deletes a rule
 */
int
rte_lpm6c_delete(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth)
{
	struct rte_ipv6_addr masked_ip;
	struct rte_lpm6c_rule lsp_rule_obj;
	struct rte_lpm6c_rule *lsp_rule;
	int ret;
	uint32_t tbl_ind;
	struct rte_lpm6c_tbl_entry *from, *to;
	struct rte_lpm6c_tbl8_hdr *tbl_hdr;

	/* Check input arguments. */
	if ((lpm == NULL) || (depth < 1) || (depth > RTE_IPV6_MAX_DEPTH))
		return -EINVAL;

	/* Copy the IP and mask it to avoid modifying user's input data. */
	masked_ip = *ip;
	rte_ipv6_addr_mask(&masked_ip, depth);

	/* Delete the rule from the rule table. */
	ret = rule_delete(lpm, &masked_ip, depth);
	if (ret < 0)
		return -ENOENT;

	/* find rule cells */
	rule_find_range(lpm, &masked_ip, depth, &from, &to, &tbl_ind);

	/* find a less specific rule (a rule with smaller depth)
	 * note: masked_ip will be modified, don't use it anymore
	 */
	ret = rule_find_less_specific(lpm, &masked_ip, depth,
			&lsp_rule_obj);
	lsp_rule = ret ? &lsp_rule_obj : NULL;

	/* decrement the number of rules in the table
	 * note that tbl24 doesn't have a header
	 */
	if (tbl_ind != TBL24_IND) {
		tbl_hdr = &lpm->tbl8_hdrs[tbl_ind];
		tbl_hdr->nb_rule--;
		if (tbl_hdr->nb_rule == 0 && tbl_hdr->nb_ext == 0) {
			/* remove the table */
			remove_tbl(lpm, tbl_hdr, tbl_ind, lsp_rule);
			return 0;
		}
	}

	/* iterate rule cells */
	for (; from <= to; from++)
		if (from->ext_entry == 1) {
			/* reference to a more specific space
			 * of the prefix/rule. Entries in a more
			 * specific space that are not used by
			 * a more specific prefix must be occupied
			 * by the prefix
			 */
			if (lsp_rule != NULL)
				expand_rule(lpm,
					from->lpm6_tbl8_ind,
					depth, lsp_rule->depth,
					lsp_rule->next_hop, VALID);
			else
				/* since the prefix has no less specific prefix,
				 * its more specific space must be invalidated
				 */
				expand_rule(lpm,
					from->lpm6_tbl8_ind,
					depth, 0, 0, INVALID);
		} else if (from->depth == depth) {
			/* entry is not a reference and belongs to the prefix */
			if (lsp_rule != NULL) {
				struct rte_lpm6c_tbl_entry new_tbl_entry = {
					.next_hop = lsp_rule->next_hop,
					.depth = lsp_rule->depth,
					.valid = VALID,
					.valid_group = VALID,
					.ext_entry = 0
				};

				*from = new_tbl_entry;
			} else {
				struct rte_lpm6c_tbl_entry new_tbl_entry = {
					.next_hop = 0,
					.depth = 0,
					.valid = INVALID,
					.valid_group = INVALID,
					.ext_entry = 0
				};

				*from = new_tbl_entry;
			}
		}

	if (tbl_ind != TBL24_IND && tbl_hdr->nb_rule == 0 && tbl_hdr->nb_ext == 1)
		del_intermediate_tbl(lpm, tbl_ind, tbl_hdr);

	return 0;
}

uint32_t
rte_lpm6c_pool_pos(struct rte_lpm6c *lpm)
{
	return lpm->tbl8_pool_pos;
}

uint32_t
rte_lpm6c_used_rules(struct rte_lpm6c *lpm)
{
	return lpm->used_rules;
}

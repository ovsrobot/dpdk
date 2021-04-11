/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <rte_thash.h>
#include <rte_tailq.h>
#include <rte_random.h>
#include <rte_memcpy.h>
#include <rte_errno.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc.h>

#define THASH_NAME_LEN		64

struct thash_lfsr {
	uint32_t	ref_cnt;
	uint32_t	poly;
	/**< polynomial associated with the lfsr */
	uint32_t	rev_poly;
	/**< polynomial to generate the sequence in reverse direction */
	uint32_t	state;
	/**< current state of the lfsr */
	uint32_t	rev_state;
	/**< current state of the lfsr for reverse direction */
	uint32_t	deg;	/**< polynomial degree*/
	uint32_t	bits_cnt;  /**< number of bits generated by lfsr*/
};

struct rte_thash_subtuple_helper {
	char	name[THASH_NAME_LEN];	/** < Name of subtuple configuration */
	LIST_ENTRY(rte_thash_subtuple_helper)	next;
	struct thash_lfsr	*lfsr;
	uint32_t	offset;		/** < Offset of the m-sequence */
	uint32_t	len;		/** < Length of the m-sequence */
	uint32_t	tuple_offset;	/** < Offset in bits of the subtuple */
	uint32_t	tuple_len;	/** < Length in bits of the subtuple */
	uint32_t	lsb_msk;	/** < (1 << reta_sz_log) - 1 */
	__extension__ uint32_t	compl_table[0] __rte_cache_aligned;
	/** < Complementary table */
};

struct rte_thash_ctx {
	char		name[THASH_NAME_LEN];
	LIST_HEAD(, rte_thash_subtuple_helper) head;
	uint32_t	key_len;	/** < Length of the NIC RSS hash key */
	uint32_t	reta_sz_log;	/** < size of the RSS ReTa in bits */
	uint32_t	subtuples_nb;	/** < number of subtuples */
	uint32_t	flags;
	uint8_t		hash_key[0];
};

struct rte_thash_ctx *
rte_thash_init_ctx(const char *name __rte_unused,
	uint32_t key_len __rte_unused, uint32_t reta_sz __rte_unused,
	uint8_t *key __rte_unused, uint32_t flags __rte_unused)
{
	return NULL;
}

struct rte_thash_ctx *
rte_thash_find_existing(const char *name __rte_unused)
{
	return NULL;
}

void
rte_thash_free_ctx(struct rte_thash_ctx *ctx __rte_unused)
{
}

int
rte_thash_add_helper(struct rte_thash_ctx *ctx __rte_unused,
	const char *name __rte_unused, uint32_t len __rte_unused,
	uint32_t offset __rte_unused)
{
	return 0;
}

struct rte_thash_subtuple_helper *
rte_thash_get_helper(struct rte_thash_ctx *ctx __rte_unused,
	const char *name __rte_unused)
{
	return NULL;
}

uint32_t
rte_thash_get_complement(struct rte_thash_subtuple_helper *h __rte_unused,
	uint32_t hash __rte_unused, uint32_t desired_hash __rte_unused)
{
	return 0;
}

const uint8_t *
rte_thash_get_key(struct rte_thash_ctx *ctx __rte_unused)
{
	return NULL;
}

int
rte_thash_adjust_tuple(struct rte_thash_ctx *ctx __rte_unused,
	struct rte_thash_subtuple_helper *h __rte_unused,
	uint8_t *tuple __rte_unused, unsigned int tuple_len __rte_unused,
	uint32_t desired_value __rte_unused,
	unsigned int attempts __rte_unused,
	rte_thash_check_tuple_t fn __rte_unused, void *userdata __rte_unused)
{
	return 0;
}

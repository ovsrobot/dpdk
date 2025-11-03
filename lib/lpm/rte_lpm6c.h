/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2025 Alex Kiselev, alex at BisonRouter.com
 */
#ifndef _RTE_LPM6C_H_
#define _RTE_LPM6C_H_

/**
 * @file
 * Longest Prefix Match for IPv6 (LPM6)
 * Path Compressed DIR24-8(n) trie.
 */

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <stdint.h>
#include <rte_compat.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_ip6.h>

/** Max number of characters in LPM name. */
#define RTE_LPM6C_NAMESIZE                 32

#define RTE_LPM6C_ROOT_LEVEL_BITS                24
#define RTE_LPM6C_TBL24_NUM_ENTRIES        (1 << RTE_LPM6C_ROOT_LEVEL_BITS)
#define RTE_LPM6C_TBL8_GROUP_NUM_ENTRIES         256
#define RTE_LPM6C_TBL8_MAX_NUM_GROUPS      (1 << 21)

#define RTE_LPM6C_VALID_EXT_ENTRY_BITMASK 0xA0000000
#define RTE_LPM6C_LOOKUP_SUCCESS          0x20000000
#define RTE_LPM6C_TBL8_BITMASK            0x001FFFFF

#define RTE_LPM6C_DEPTH(x)      (((x) >> 21) & 0xFF)

#define RTE_LPM6C_ROOT_LEV_BYTES                  3
#define RTE_LPM6C_BYTE_SIZE                       8
#define RTE_LPM6C_BYTES2_SIZE                    16

#define RTE_LPM6C_ROOT_TBL_IND(ip) (\
			  (uint32_t)ip->a[0] << RTE_LPM6C_BYTES2_SIZE | \
			  (uint32_t)ip->a[1] << RTE_LPM6C_BYTE_SIZE | ip->a[2])

#define lpm6_tbl8_ind next_hop

#define MIN_TBL8_REQ_FOR_ADD 14

#define RTE_LPM6C_UNDEF_NEXT_HOP         UINT32_MAX

/** Flags for setting an entry as valid/invalid. */
enum valid_flag {
	INVALID = 0,
	VALID
};

/** Tbl entry structure. It is the same for both tbl24 and tbl8 */
struct rte_lpm6c_tbl_entry {
	uint32_t next_hop:	21;  /**< Next hop / next table to be checked. */
	uint32_t depth	:8; /**< Either a rule depth or a tree next level if
	                     * it's an external entry
	                     */
	/* Flags. */
	uint32_t valid     :1;   /**< Validation flag. */
	uint32_t valid_group :1; /**< Group validation flag. */
	uint32_t ext_entry :1;   /**< External entry. */
};

/**
 * tbl8
 */
#define SIZEOF_TBL8_UNPADDED \
	(RTE_IPV6_ADDR_SIZE + \
	sizeof(uint32_t) + \
	sizeof(struct rte_lpm6c_tbl_entry[RTE_LPM6C_TBL8_GROUP_NUM_ENTRIES]))

#define PADDING_TBL8 ((RTE_CACHE_LINE_SIZE - \
	(SIZEOF_TBL8_UNPADDED % RTE_CACHE_LINE_SIZE)) % RTE_CACHE_LINE_SIZE)

struct rte_lpm6c_tbl8 {
	struct rte_ipv6_addr ip;
	uint32_t lsp_next_hop;
	struct rte_lpm6c_tbl_entry entries[RTE_LPM6C_TBL8_GROUP_NUM_ENTRIES];
	uint8_t padding[PADDING_TBL8];
}
__rte_cache_aligned;

/** Rules tbl entry structure. */
struct rte_lpm6c_rule {
	struct rte_ipv6_addr ip; /**< Rule IP address. */
	uint32_t next_hop; /**< Rule next hop. */
	uint8_t depth; /**< Rule depth. */
};

/** Rules tbl entry key. */
struct rte_lpm6c_rule_key {
	struct rte_ipv6_addr ip; /**< Rule IP address. */
	uint32_t depth; /**< Rule depth. */
};

/* Header of tbl8 */
struct rte_lpm6c_tbl8_hdr {
	uint32_t owner_tbl_ind; /**< owner table: TBL24_IND if owner is tbl24,
	                          * otherwise index of tbl8
	                          */
	uint32_t owner_entry_ind; /**< index of the owner table entry where
	                            * pointer to the tbl8 is stored
	                            */

	uint32_t nb_rule; /**< number of rules  */
	uint32_t nb_ext; /**< number of external entries */

	uint8_t depth;
	uint8_t lsp_depth;
}
__rte_cache_aligned;

/** LPM6 structure. */
struct rte_lpm6c {
	uint32_t max_rules;              /**< Max number of rules. */
	uint32_t used_rules;             /**< Used rules so far. */
	uint32_t number_tbl8s;           /**< Number of tbl8s to allocate. */

	uint32_t tbl8_pool_pos; /**< current position in the tbl8 pool */

	/* next hop index */
	uint32_t default_next_hop_ind;

	/* LPM Tables. */
	struct rte_hash *rules_tbl; /**< LPM rules. */
	struct rte_lpm6c_tbl8_hdr *tbl8_hdrs; /* array of tbl8 headers */
	uint32_t *tbl8_pool; /**< pool of indexes of free tbl8s */

	/* LPM metadata. */
	char name[RTE_LPM6C_NAMESIZE];    /**< Name of the lpm. */

	alignas(RTE_CACHE_LINE_SIZE) struct rte_lpm6c_tbl_entry
			  tbl24[RTE_LPM6C_TBL24_NUM_ENTRIES]; /**< LPM tbl24 table. */

	alignas(RTE_CACHE_LINE_SIZE) struct rte_lpm6c_tbl8 tbl8[0];
			  /**< LPM tbl8 table. */
};

/** LPM configuration structure. */
struct rte_lpm6c_config {
	uint32_t max_rules;      /**< Max number of rules. */
	uint32_t number_tbl8s;   /**< Number of tbl8s to allocate. */
	int flags;               /**< This field is currently unused. */
};

/**
 * Create an LPM object.
 *
 * @param name
 *   LPM object name
 * @param socket_id
 *   NUMA socket ID for LPM table memory allocation
 * @param config
 *   Structure containing the configuration
 * @return
 *   Handle to LPM object on success, NULL otherwise with rte_errno set
 *   to an appropriate values. Possible rte_errno values include:
 *    - EINVAL - invalid parameter passed to function
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
struct rte_lpm6c *
rte_lpm6c_create(const char *name, int socket_id,
		const struct rte_lpm6c_config *config);

/**
 * Find an existing LPM object and return a pointer to it.
 *
 * @param name
 *   Name of the lpm object as passed to rte_lpm6c_create()
 * @return
 *   Pointer to lpm object or NULL if object not found with rte_errno
 *   set appropriately. Possible rte_errno values include:
 *    - ENOENT - required entry not available to return.
 */
struct rte_lpm6c *
rte_lpm6c_find_existing(const char *name);

/**
 * Free an LPM object.
 *
 * @param lpm
 *   LPM object handle
 * @return
 *   None
 */
void
rte_lpm6c_free(struct rte_lpm6c *lpm);

/**
 * Add a rule to the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP of the rule to be added to the LPM table
 * @param depth
 *   Depth of the rule to be added to the LPM table
 * @param next_hop
 *   Next hop of the rule to be added to the LPM table
 * @return
 *   0 on success, negative value otherwise
 */
int
rte_lpm6c_add(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth, uint32_t next_hop);

/**
 * Check if a rule is present in the LPM table,
 * and provide its next hop if it is.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP of the rule to be searched
 * @param depth
 *   Depth of the rule to searched
 * @param next_hop
 *   Next hop of the rule (valid only if it is found)
 * @return
 *   1 if the rule exists, 0 if it does not, a negative value on failure
 */
int
rte_lpm6c_is_rule_present(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth, uint32_t *next_hop);

/**
 * Delete a rule from the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP of the rule to be deleted from the LPM table
 * @param depth
 *   Depth of the rule to be deleted from the LPM table
 * @return
 *   0 on success, negative value otherwise
 */
int
rte_lpm6c_delete(struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		  uint8_t depth);

/**
 * Delete a rule from the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param ips
 *   Array of IPs to be deleted from the LPM table
 * @param depths
 *   Array of depths of the rules to be deleted from the LPM table
 * @param n
 *   Number of rules to be deleted from the LPM table
 * @return
 *   0 on success, negative value otherwise.
 */
int
rte_lpm6c_delete_bulk_func(struct rte_lpm6c *lpm,
		const struct rte_ipv6_addr *ips, uint8_t *depths, unsigned int n);

/**
 * Delete all rules from the LPM table.
 *
 * @param lpm
 *   LPM object handle
 */
void
rte_lpm6c_delete_all(struct rte_lpm6c *lpm);

/**
 * Returns number of free tbl8s
 *
 * @param lpm
 *   LPM object
 *  @return
 *   number of free tbl8
 */
uint32_t
rte_lpm6c_tbl8_available(struct rte_lpm6c *lpm);

/**
 * Returns number of tbl8s in use
 *
 * @param lpm
 *   LPM object
 *  @return
 *   number of tbl8 in use
 */
uint32_t
rte_lpm6c_tbl8_in_use(struct rte_lpm6c *lpm);

typedef void (*lpm6_iter_cb) (void *cb_param, struct rte_ipv6_addr *ip,
		  uint8_t depth, uint32_t next_hop);

int32_t
rte_lpm6c_rules_iterate(const struct rte_lpm6c *lpm, uint32_t *iter,
		  const struct rte_ipv6_addr **ip, uint8_t *depth, uint32_t *next_hop);

void
rte_lpm6c_rules_iterate_cb(const struct rte_lpm6c *lpm, lpm6_iter_cb cb,
		  void *cb_param);

/**
 * Lookup an IP into the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP to be looked up in the LPM table
 * @param next_hop
 *   Next hop of the most specific rule found for IP (valid on lookup hit only)
 * @return
 *   -EINVAL for incorrect arguments, -ENOENT on lookup miss, 0 on lookup hit
 */
static inline int
rte_lpm6c_lookup(const struct rte_lpm6c *lpm, const struct rte_ipv6_addr *ip,
		uint32_t *next_hop)
{
	uint32_t entry_val, tbl_ind, i, byte_ind, level;
	const struct rte_lpm6c_tbl8 *tbl;
	const struct rte_lpm6c_tbl_entry *entry;

	/* DEBUG: Check user input arguments. */
	if (unlikely(lpm == NULL) || (ip == NULL) || (next_hop == NULL))
		return -EINVAL;

	byte_ind = RTE_LPM6C_ROOT_LEV_BYTES;
	tbl_ind = RTE_LPM6C_ROOT_TBL_IND(ip);
	/* Calculate pointer to the first entry to be inspected */
	entry = &lpm->tbl24[tbl_ind];

	do {
		/* Take the integer value from the pointer. */
		entry_val = *(const uint32_t *)entry;
		tbl_ind = entry_val & RTE_LPM6C_TBL8_BITMASK;

		if ((entry_val & RTE_LPM6C_VALID_EXT_ENTRY_BITMASK) !=
				RTE_LPM6C_VALID_EXT_ENTRY_BITMASK) {
			*next_hop = tbl_ind;
			return (entry_val & RTE_LPM6C_LOOKUP_SUCCESS) ? 0 : -ENOENT;
		}

		/* If it is valid and extended we calculate the new pointer to return. */
		level = RTE_LPM6C_DEPTH(entry_val) + RTE_LPM6C_ROOT_LEV_BYTES - 1;
		tbl = &lpm->tbl8[tbl_ind];

		/*
		 * if some levels were skipped then make sure that
		 * the ip matches the ip address of a table we've jumped to,
		 * i.e. check the ip's bytes corresponding the skipped levels.
		 */
		for (i = byte_ind; i < level; i++)
			if (tbl->ip.a[i] != ip->a[i]) {
				if (tbl->lsp_next_hop == RTE_LPM6C_UNDEF_NEXT_HOP)
					return -ENOENT;
				*next_hop = tbl->lsp_next_hop;
				return 0;
			}

		/* move ip byte index one byte further */
		byte_ind = level + 1;
		/* go to next level */
		entry = &tbl->entries[ip->a[level]];
	} while (true);
}

/**
 * Lookup multiple IP addresses in an LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param ips
 *   Array of IPs to be looked up in the LPM table
 * @param next_hops
 *   Next hop of the most specific rule found for IP (valid on lookup hit only).
 *   This is an array of two byte values. The next hop will be stored on
 *   each position on success; otherwise the position will be set to -1.
 * @param n
 *   Number of elements in ips (and next_hops) array to lookup.
 *  @return
 *   -EINVAL for incorrect arguments, otherwise 0
 */
static inline int
rte_lpm6c_lookup_bulk(const struct rte_lpm6c *lpm,
		  const struct rte_ipv6_addr *ips,
		  int32_t *next_hops, const unsigned int n)
{
	uint32_t entry_val, tbl_ind, i, byte_ind, level;
	unsigned int j;
	const unsigned int n_unrolled = n & ~1U; /* Process pairs of IPs */
	const struct rte_lpm6c_tbl8 *tbl;

	/* DEBUG: Check user input arguments. */
	if (unlikely(lpm == NULL) || (ips == NULL) || (next_hops == NULL))
		return -EINVAL;

	/* Unrolled loop processing two lookups at a time */
	for (j = 0; j < n_unrolled; j += 2) {
		const struct rte_lpm6c_tbl_entry *entry0, *entry1;
		const struct rte_ipv6_addr *ip0, *ip1;

		/* Start processing two independent lookups */
		ip0 = &ips[j];
		ip1 = &ips[j + 1];

		entry0 = &lpm->tbl24[RTE_LPM6C_ROOT_TBL_IND(ip0)];
		entry1 = &lpm->tbl24[RTE_LPM6C_ROOT_TBL_IND(ip1)];

		/* Lookup for IP #0 */
		byte_ind = RTE_LPM6C_ROOT_LEV_BYTES;
		do {
			/* Take the integer value from the pointer. */
			entry_val = *(const uint32_t *)entry0;
			tbl_ind = entry_val & RTE_LPM6C_TBL8_BITMASK;

			if ((entry_val & RTE_LPM6C_VALID_EXT_ENTRY_BITMASK) !=
					RTE_LPM6C_VALID_EXT_ENTRY_BITMASK) {
				next_hops[j] = (entry_val & RTE_LPM6C_LOOKUP_SUCCESS) ?
						  (int32_t)tbl_ind : -1;
				break;
			}

			/*
			 * If it is valid and extended we calculate the new pointer
			 * to return.
			 */
			level = RTE_LPM6C_DEPTH(entry_val) + RTE_LPM6C_ROOT_LEV_BYTES - 1;
			tbl = &lpm->tbl8[tbl_ind];

			/*
			 * if some levels were skipped then make sure that
			 * the ip matches the ip address of a table we've jumped to,
			 * i.e. check the ip's bytes corresponding the skipped levels.
			 */
			for (i = byte_ind; i < level; i++)
				if (tbl->ip.a[i] != ip0->a[i]) {
					next_hops[j] = tbl->lsp_next_hop ==
							  RTE_LPM6C_UNDEF_NEXT_HOP ?
						-1 : (int32_t)tbl->lsp_next_hop;
					goto next_ip0;
				}

			/* move ip byte index one byte further */
			byte_ind = level + 1;
			/* go to next level */
			entry0 = &tbl->entries[ip0->a[level]];
		} while (true);

next_ip0:
		/* Lookup for IP #1 */
		byte_ind = RTE_LPM6C_ROOT_LEV_BYTES;
		do {
			/* Take the integer value from the pointer. */
			entry_val = *(const uint32_t *)entry1;
			tbl_ind = entry_val & RTE_LPM6C_TBL8_BITMASK;

			if ((entry_val & RTE_LPM6C_VALID_EXT_ENTRY_BITMASK) !=
					RTE_LPM6C_VALID_EXT_ENTRY_BITMASK) {
				next_hops[j + 1] = (entry_val & RTE_LPM6C_LOOKUP_SUCCESS) ?
						  (int32_t)tbl_ind : -1;
				break;
			}

			/*
			 * If it is valid and extended we calculate the new pointer
			 * to return.
			 */
			level = RTE_LPM6C_DEPTH(entry_val) + RTE_LPM6C_ROOT_LEV_BYTES - 1;
			tbl = &lpm->tbl8[tbl_ind];

			/*
			 * if some levels were skipped then make sure that
			 * the ip matches the ip address of a table we've jumped to,
			 * i.e. check the ip's bytes corresponding the skipped levels.
			 */
			for (i = byte_ind; i < level; i++)
				if (tbl->ip.a[i] != ip1->a[i]) {
					next_hops[j + 1] =
						tbl->lsp_next_hop == RTE_LPM6C_UNDEF_NEXT_HOP ?
							-1 : (int32_t)tbl->lsp_next_hop;
					goto next_ip1;
				}

			/* move ip byte index one byte further */
			byte_ind = level + 1;
			/* go to next level */
			entry1 = &tbl->entries[ip1->a[level]];
		} while (true);

next_ip1:;
	}

	for (; j < n; j++) {
		const struct rte_lpm6c_tbl_entry *entry;
		const struct rte_ipv6_addr *ip0 = &ips[j];

		byte_ind = RTE_LPM6C_ROOT_LEV_BYTES;
		tbl_ind = RTE_LPM6C_ROOT_TBL_IND(ip0);
		/* Calculate pointer to the first entry to be inspected */
		entry = &lpm->tbl24[tbl_ind];

		do {
			/* Take the integer value from the pointer. */
			entry_val = *(const uint32_t *)entry;
			tbl_ind = entry_val & RTE_LPM6C_TBL8_BITMASK;

			if ((entry_val & RTE_LPM6C_VALID_EXT_ENTRY_BITMASK) !=
					RTE_LPM6C_VALID_EXT_ENTRY_BITMASK) {
				next_hops[j] = (entry_val & RTE_LPM6C_LOOKUP_SUCCESS) ?
						  (int32_t)tbl_ind : -1;
				break;
			}

			/*
			 * If it is valid and extended we calculate the new pointer
			 * to return.
			 */
			level = RTE_LPM6C_DEPTH(entry_val) + RTE_LPM6C_ROOT_LEV_BYTES - 1;
			tbl = &lpm->tbl8[tbl_ind];

			/*
			 * if some levels were skipped then make sure that
			 * the ip matches the ip address of a table we've jumped to,
			 * i.e. check the ip's bytes corresponding the skipped levels.
			 */
			for (i = byte_ind; i < level; i++)
				if (tbl->ip.a[i] != ip0->a[i]) {
					next_hops[j] = tbl->lsp_next_hop ==
							  RTE_LPM6C_UNDEF_NEXT_HOP ?
						-1 : (int32_t)tbl->lsp_next_hop;
					goto next_ip;
				}

			/* move ip byte index one byte further */
			byte_ind = level + 1;
			/* go to next level */
			entry = &tbl->entries[ip0->a[level]];
		} while (true);

next_ip:;
	}

	return 0;
}

uint32_t
rte_lpm6c_pool_pos(struct rte_lpm6c *lpm);

uint32_t
rte_lpm6c_used_rules(struct rte_lpm6c *lpm);

__END_DECLS

#endif

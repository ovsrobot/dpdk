/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _RTE_FIB_H_
#define _RTE_FIB_H_

/**
 * @file
 *
 * RTE FIB library.
 *
 * FIB (Forwarding information base) implementation
 * for IPv4 Longest Prefix Match
 */

#include <stdint.h>

#include <rte_common.h>
#include <rte_rcu_qsbr.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rte_fib;
struct rte_rib;

/* Maximum length of a FIB name. */
#define RTE_FIB_NAMESIZE	64

/** Maximum depth value possible for IPv4 FIB. */
#define RTE_FIB_MAXDEPTH	32

/** @internal Default RCU defer queue entries to reclaim in one go. */
#define RTE_FIB_RCU_DQ_RECLAIM_MAX	16
/** @internal Default RCU defer queue size. */
#define RTE_FIB_RCU_DQ_RECLAIM_SZ	128

/** RCU reclamation modes */
enum rte_fib_qsbr_mode {
	/** Create defer queue for reclaim. */
	RTE_FIB_QSBR_MODE_DQ = 0,
	/** Use blocking mode reclaim. No defer queue created. */
	RTE_FIB_QSBR_MODE_SYNC
};

/** Type of FIB struct */
enum rte_fib_type {
	RTE_FIB_DUMMY,		/**< RIB tree based FIB */
	RTE_FIB_DIR24_8		/**< DIR24_8 based FIB */
};

/** Modify FIB function */
typedef int (*rte_fib_modify_fn_t)(struct rte_fib *fib, uint32_t ip,
	uint8_t depth, uint64_t next_hop, int op);
/** FIB bulk lookup function */
typedef void (*rte_fib_lookup_fn_t)(void *fib, const uint32_t *ips,
	uint64_t *next_hops, const unsigned int n);

enum rte_fib_op {
	RTE_FIB_ADD,
	RTE_FIB_DEL,
};

/** Size of nexthop (1 << nh_sz) bits for DIR24_8 based FIB */
enum rte_fib_dir24_8_nh_sz {
	RTE_FIB_DIR24_8_1B,
	RTE_FIB_DIR24_8_2B,
	RTE_FIB_DIR24_8_4B,
	RTE_FIB_DIR24_8_8B
};

/** Type of lookup function implementation */
enum rte_fib_lookup_type {
	RTE_FIB_LOOKUP_DEFAULT,
	/**< Selects the best implementation based on the max simd bitwidth */
	RTE_FIB_LOOKUP_DIR24_8_SCALAR_MACRO,
	/**< Macro based lookup function */
	RTE_FIB_LOOKUP_DIR24_8_SCALAR_INLINE,
	/**<
	 * Lookup implementation using inlined functions
	 * for different next hop sizes
	 */
	RTE_FIB_LOOKUP_DIR24_8_SCALAR_UNI,
	/**<
	 * Unified lookup function for all next hop sizes
	 */
	RTE_FIB_LOOKUP_DIR24_8_VECTOR_AVX512
	/**< Vector implementation using AVX512 */
};

/** If set, fib lookup is expecting IPv4 address in network byte order */
#define RTE_FIB_F_LOOKUP_NETWORK_ORDER 1
#define RTE_FIB_ALLOWED_FLAGS (RTE_FIB_F_LOOKUP_NETWORK_ORDER)

/** FIB configuration structure */
struct rte_fib_conf {
	enum rte_fib_type type; /**< Type of FIB struct */
	/** Default value returned on lookup if there is no route */
	uint64_t default_nh;
	int	max_routes;
	/** Size of the node extension in the internal RIB struct */
	unsigned int rib_ext_sz;
	union {
		struct {
			enum rte_fib_dir24_8_nh_sz nh_sz;
			uint32_t	num_tbl8;
		} dir24_8;
	};
	unsigned int flags; /**< Optional feature flags from RTE_FIB_F_* **/
};

/** FIB RCU QSBR configuration structure. */
struct rte_fib_rcu_config {
	/** RCU QSBR variable. */
	struct rte_rcu_qsbr *v;
	/** Mode of RCU QSBR. See RTE_FIB_QSBR_MODE_xxx.
	 * Default: RTE_FIB_QSBR_MODE_DQ, create defer queue for reclaim.
	 */
	enum rte_fib_qsbr_mode mode;
	/** RCU defer queue size.
	 * Default: RTE_FIB_RCU_DQ_RECLAIM_SZ.
	 */
	uint32_t dq_size;
	/** Threshold to trigger auto reclaim. */
	uint32_t reclaim_thd;
	/** Max entries to reclaim in one go.
	 * Default: RTE_FIB_RCU_DQ_RECLAIM_MAX.
	 */
	uint32_t reclaim_max;
};

/**
 * Free an FIB object.
 *
 * @param fib
 *   FIB object handle created by rte_fib_create().
 *   If fib is NULL, no operation is performed.
 */
void
rte_fib_free(struct rte_fib *fib);

/**
 * Create FIB
 *
 * @param name
 *  FIB name
 * @param socket_id
 *  NUMA socket ID for FIB table memory allocation
 * @param conf
 *  Structure containing the configuration
 * @return
 *  Handle to the FIB object on success
 *  NULL otherwise with rte_errno set to an appropriate values.
 */
struct rte_fib *
rte_fib_create(const char *name, int socket_id, struct rte_fib_conf *conf)
	__rte_malloc __rte_dealloc(rte_fib_free, 1);

/**
 * Find an existing FIB object and return a pointer to it.
 *
 * @param name
 *  Name of the fib object as passed to rte_fib_create()
 * @return
 *  Pointer to fib object or NULL if object not found with rte_errno
 *  set appropriately. Possible rte_errno values include:
 *   - ENOENT - required entry not available to return.
 */
struct rte_fib *
rte_fib_find_existing(const char *name);

/**
 * Add a route to the FIB.
 *
 * @param fib
 *   FIB object handle
 * @param ip
 *   IPv4 prefix address to be added to the FIB
 * @param depth
 *   Prefix length
 * @param next_hop
 *   Next hop to be added to the FIB
 * @return
 *   0 on success, negative value otherwise
 */
int
rte_fib_add(struct rte_fib *fib, uint32_t ip, uint8_t depth, uint64_t next_hop);

/**
 * Delete a rule from the FIB.
 *
 * @param fib
 *   FIB object handle
 * @param ip
 *   IPv4 prefix address to be deleted from the FIB
 * @param depth
 *   Prefix length
 * @return
 *   0 on success, negative value otherwise
 */
int
rte_fib_delete(struct rte_fib *fib, uint32_t ip, uint8_t depth);

/**
 * Lookup multiple IP addresses in the FIB.
 *
 * @param fib
 *   FIB object handle
 * @param ips
 *   Array of IPs to be looked up in the FIB
 * @param next_hops
 *   Next hop of the most specific rule found for IP.
 *   This is an array of eight byte values.
 *   If the lookup for the given IP failed, then corresponding element would
 *   contain default nexthop value configured for a FIB.
 * @param n
 *   Number of elements in ips (and next_hops) array to lookup.
 *  @return
 *   -EINVAL for incorrect arguments, otherwise 0
 */
int
rte_fib_lookup_bulk(struct rte_fib *fib, uint32_t *ips,
		uint64_t *next_hops, int n);
/**
 * Get pointer to the dataplane specific struct
 *
 * @param fib
 *   FIB object handle
 * @return
 *   Pointer on the dataplane struct on success
 *   NULL otherwise
 */
void *
rte_fib_get_dp(struct rte_fib *fib);

/**
 * Get pointer to the RIB
 *
 * @param fib
 *   FIB object handle
 * @return
 *   Pointer on the RIB on success
 *   NULL otherwise
 */
struct rte_rib *
rte_fib_get_rib(struct rte_fib *fib);

/**
 * Set lookup function based on type
 *
 * @param fib
 *   FIB object handle
 * @param type
 *   type of lookup function
 *
 * @return
 *   0 on success
 *   -EINVAL on failure
 */
int
rte_fib_select_lookup(struct rte_fib *fib, enum rte_fib_lookup_type type);

/**
 * Associate RCU QSBR variable with a FIB object.
 *
 * @param fib
 *   FIB object handle
 * @param cfg
 *   RCU QSBR configuration
 * @return
 *   0 on success
 *   Negative otherwise
 *   Possible error codes are:
 *   - -EINVAL - invalid parameters
 *   - -EEXIST - already added QSBR
 *   - -ENOMEM - memory allocation failure
 *   - -ENOTSUP - not supported by configured dataplane algorithm
 */
__rte_experimental
int
rte_fib_rcu_qsbr_add(struct rte_fib *fib, struct rte_fib_rcu_config *cfg);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_FIB_H_ */

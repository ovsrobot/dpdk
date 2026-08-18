/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

/**
 * @file
 * Holds the structures for the eal internal configuration
 */

#ifndef EAL_INTERNAL_CFG_H
#define EAL_INTERNAL_CFG_H

#include <rte_eal.h>
#include <rte_os_shim.h>
#include <rte_pci_dev_feature_defs.h>
#include <stdint.h>
#include <stdbool.h>

#include "eal_thread.h"

#if defined(RTE_ARCH_ARM)
#define MAX_HUGEPAGE_SIZES 4  /**< support up to 4 page sizes */
#else
#define MAX_HUGEPAGE_SIZES 3  /**< support up to 3 page sizes */
#endif

/*
 * internal configuration structure for the number, size and
 * mount points of hugepages
 */
struct hugepage_info {
	uint64_t hugepage_sz;   /**< size of a huge page */
	char hugedir[PATH_MAX];    /**< dir where hugetlbfs is mounted */
	uint32_t num_pages[RTE_MAX_NUMA_NODES];
	/**< number of hugepages of that size on each socket */
	int lock_descriptor;    /**< file descriptor for hugepage dir */
};

struct simd_bitwidth {
	bool forced;
	/**< flag indicating if bitwidth is forced and can't be modified */
	uint16_t bitwidth; /**< bitwidth value */
};

/** Hugepage backing files discipline. */
struct hugepage_file_discipline {
	/** Unlink files before mapping them to leave no trace in hugetlbfs. */
	bool unlink_before_mapping;
	/** Unlink existing files at startup, re-create them before mapping. */
	bool unlink_existing;
};

/**
 * User-provided EAL initialization configuration.
 * Immutable after initialization, so no need for atomic types or locks.
 */
struct eal_user_cfg {
	size_t memory;           /**< amount of asked memory */
	size_t huge_worker_stack_size; /**< worker thread stack size */
	enum rte_proc_type_t process_type; /**< requested process type */
	enum rte_intr_mode vfio_intr_mode; /**< default interrupt mode for VFIO */
	enum rte_iova_mode iova_mode; /**< requested IOVA mode */
	struct simd_bitwidth max_simd_bitwidth; /**< max simd bitwidth path to use */
	rte_uuid_t vfio_vf_token; /**< shared VF token for VFIO-PCI bound PF and VFs */
	uint8_t force_nchannel;  /**< force number of channels */
	uint8_t force_nrank;     /**< force number of ranks */
	bool force_numa;         /**< true to request memory on specific NUMA nodes */
	bool force_numa_limits;  /**< true to apply per-NUMA memory limits */
	bool no_hugetlbfs;       /**< true to disable hugetlbfs */
	bool no_pci;             /**< true to disable PCI */
	bool no_hpet;            /**< true to disable HPET */
	bool vmware_tsc_map;     /**< true to use VMware TSC mapping */
	bool no_shconf;          /**< true if there is no shared config */
	bool in_memory;          /**< true to run with no shared runtime files */
	bool create_uio_dev;     /**< true to create /dev/uioX devices */
	bool no_telemetry;       /**< true to disable telemetry */
	bool legacy_mem;         /**< true to enable legacy memory behavior */
	bool match_allocations;  /**< true to free hugepages exactly as allocated */
	bool no_auto_probing;    /**< true to switch from block-listing to allow-listing */
	bool single_file_segments; /**< true if storing all pages within single files */
	struct hugepage_file_discipline hugepage_file;
	char *hugefile_prefix;   /**< the base filename of hugetlbfs files */
	char *hugepage_dir;      /**< specific hugetlbfs directory to use */
	char *user_mbuf_pool_ops_name; /**< user defined mbuf pool ops name */
	uintptr_t base_virtaddr; /**< base address to try and reserve memory from */
	uint64_t numa_mem[RTE_MAX_NUMA_NODES];    /**< amount of memory per NUMA node */
	uint64_t numa_limit[RTE_MAX_NUMA_NODES];  /**< limit amount of memory per NUMA node */
	/** storage for user-specified pagesz-mem overrides */
	struct pagesz_mem_override {
		uint64_t pagesz;   /**< page size in bytes */
		uint64_t limit;    /**< memory limit in bytes */
	} pagesz_mem_overrides[MAX_HUGEPAGE_SIZES];
	unsigned int num_pagesz_mem_overrides;  /**< number of stored overrides */
};

/**
 * Discovered information about cores, memory, etc. on the system.
 * Immutable after initialization, so no need for atomic types or locks.
 */
struct eal_platform_info {
	uint8_t num_hugepage_sizes;      /**< how many sizes on this system */
	struct hugepage_info hugepage_info[MAX_HUGEPAGE_SIZES];
};

/**
 * Internal EAL runtime state
 * May be modified at runtime, so access must be protected by locks or atomic types
 * as appropriate.
 */
struct eal_runtime_state {
	uint64_t hugepage_mem_sz_limits[MAX_HUGEPAGE_SIZES];
	/**< default max memory per hugepage size */
	rte_cpuset_t ctrl_cpuset;         /**< cpuset for ctrl threads */
	volatile unsigned int init_complete;
	/**< indicates whether EAL has completed initialization */
};

struct eal_user_cfg *eal_get_user_configuration(void);
struct eal_platform_info *eal_get_platform_info(void);
struct eal_runtime_state *eal_get_runtime_state(void);
void eal_reset_internal_config(void);

#endif /* EAL_INTERNAL_CFG_H */

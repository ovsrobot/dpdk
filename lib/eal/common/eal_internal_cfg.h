/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

/**
 * @file
 * Holds the structures for the eal internal configuration
 */

#ifndef EAL_INTERNAL_CFG_H
#define EAL_INTERNAL_CFG_H

#include <stdlib.h>
#include <sys/queue.h>

#include <rte_devargs.h>
#include <rte_eal.h>
#include <rte_os_shim.h>
#include <rte_pci_dev_feature_defs.h>
#include <rte_trace.h>
#include <rte_vect.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_bitset.h>
#include <rte_stdatomic.h>
#include "eal_thread.h"

/* Forward declaration — full definition is in eal_memcfg.h */
struct rte_mem_config;

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
 * A saved trace pattern string from --trace, staged during arg parsing.
 * Lives in user_cfg->trace_patterns; applied during eal_trace_init().
 */
struct eal_trace_arg {
	STAILQ_ENTRY(eal_trace_arg) next;
	char *val;
};
STAILQ_HEAD(eal_trace_arg_list, eal_trace_arg);

/**
 * A plugin path provided by the user via -d, staged during arg parsing.
 * Lives in user_cfg->plugin_list; consumed by eal_plugins_init().
 */
struct eal_plugin_path {
	TAILQ_ENTRY(eal_plugin_path) next;
	char name[PATH_MAX];
};
TAILQ_HEAD(eal_plugin_path_list, eal_plugin_path);

/**
 * A single device option (-a/-b/--vdev) staged during arg parsing.
 * Lives in user_cfg->devopt_list; drained by eal_option_device_parse().
 */
struct device_option {
	TAILQ_ENTRY(device_option) next;
	enum rte_devtype type;
	char arg[];
};
TAILQ_HEAD(eal_devopt_list, device_option);

/**
 * User-provided EAL initialization configuration.
 * Immutable after initialization, so no need for atomic types or locks.
 *
 * NOTE: On modify, always update the initializer, copy, and cleanup functions below.
 */
struct eal_user_cfg {
	struct eal_devopt_list devopt_list; /**< staged device options (-a/-b/--vdev) */
	struct eal_plugin_path_list plugin_list; /**< user-provided plugin paths (-d) */
	struct eal_trace_arg_list trace_patterns; /**< saved --trace patterns */
	char *trace_dir;        /**< trace output directory (NULL = use default) */
	uint64_t trace_bufsz;   /**< trace buffer size in bytes (0 = use default 1 MB) */
	enum rte_trace_mode trace_mode; /**< trace mode (default RTE_TRACE_MODE_OVERWRITE) */
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
	rte_cpuset_t service_cpuset; /**<  each bit set is one lcore ID to use as service core */

	/** Per-lcore cpuset array, always populated at arg-parse time for all input forms
	 * (-c coremask, -l corelist, --lcores with or without '@'/'()').
	 * Each non-NULL slot is an individually heap-allocated rte_cpuset_t.
	 * NULL means the corresponding lcore ID is not configured.
	 */
	rte_cpuset_t *lcore_cpusets[RTE_MAX_LCORE];
	int            main_lcore;    /**< ID of the main lcore */
};

#ifdef RTE_LIBEAL_USE_HPET
#define EAL_NO_HPET_DEFAULT false
#else
#define EAL_NO_HPET_DEFAULT true
#endif

#define EAL_USER_CFG_INITIALIZER(self) (struct eal_user_cfg){ \
	.devopt_list = TAILQ_HEAD_INITIALIZER((self).devopt_list), \
	.plugin_list = TAILQ_HEAD_INITIALIZER((self).plugin_list), \
	.trace_patterns = STAILQ_HEAD_INITIALIZER((self).trace_patterns), \
	.hugepage_file.unlink_existing = true, \
	.main_lcore = -1, \
	.no_hpet = EAL_NO_HPET_DEFAULT, \
	.max_simd_bitwidth.bitwidth = RTE_VECT_DEFAULT_SIMD_BITWIDTH, \
}

static inline void
eal_user_cfg_cleanup(struct eal_user_cfg *cfg)
{
	while (!TAILQ_EMPTY(&cfg->devopt_list)) {
		struct device_option *devopt = TAILQ_FIRST(&cfg->devopt_list);
		TAILQ_REMOVE(&cfg->devopt_list, devopt, next);
		free(devopt);
	}

	while (!TAILQ_EMPTY(&cfg->plugin_list)) {
		struct eal_plugin_path *p = TAILQ_FIRST(&cfg->plugin_list);
		TAILQ_REMOVE(&cfg->plugin_list, p, next);
		free(p);
	}

	while (!STAILQ_EMPTY(&cfg->trace_patterns)) {
		struct eal_trace_arg *ta = STAILQ_FIRST(&cfg->trace_patterns);
		STAILQ_REMOVE_HEAD(&cfg->trace_patterns, next);
		free(ta->val);
		free(ta);
	}

	free(cfg->trace_dir);
	cfg->trace_dir = NULL;
	free(cfg->hugefile_prefix);
	cfg->hugefile_prefix = NULL;
	free(cfg->hugepage_dir);
	cfg->hugepage_dir = NULL;
	free(cfg->user_mbuf_pool_ops_name);
	cfg->user_mbuf_pool_ops_name = NULL;

	for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
		free(cfg->lcore_cpusets[i]);
		cfg->lcore_cpusets[i] = NULL;
	}
}

static inline int
eal_user_cfg_copy(struct eal_user_cfg *dst, const struct eal_user_cfg *src)
{

	/* copy all scalar/fixed-size fields */
	*dst = *src;

	/* re-initialise list heads — the shallow copy above has stale pointers */
	TAILQ_INIT(&dst->devopt_list);
	TAILQ_INIT(&dst->plugin_list);
	STAILQ_INIT(&dst->trace_patterns);

	/* zero heap string pointers so cleanup is safe on partial failure */
	dst->trace_dir = NULL;
	dst->hugefile_prefix = NULL;
	dst->hugepage_dir = NULL;
	dst->user_mbuf_pool_ops_name = NULL;
	for (unsigned int i = 0; i < RTE_MAX_LCORE; i++)
		dst->lcore_cpusets[i] = NULL;

	/* deep-copy device option list (device_option has a flexible array member) */
	struct device_option *devopt, *devopt_copy;
	TAILQ_FOREACH(devopt, &src->devopt_list, next) {
		size_t arglen = strlen(devopt->arg) + 1;
		devopt_copy = calloc(1, sizeof(*devopt_copy) + arglen);
		if (devopt_copy == NULL)
			goto err;
		devopt_copy->type = devopt->type;
		memcpy(devopt_copy->arg, devopt->arg, arglen);
		TAILQ_INSERT_TAIL(&dst->devopt_list, devopt_copy, next);
	}

	/* deep-copy plugin path list */
	struct eal_plugin_path *p, *p_copy;
	TAILQ_FOREACH(p, &src->plugin_list, next) {
		p_copy = malloc(sizeof(*p_copy));
		if (p_copy == NULL)
			goto err;
		memcpy(p_copy->name, p->name, sizeof(p_copy->name));
		TAILQ_INSERT_TAIL(&dst->plugin_list, p_copy, next);
	}

	/* deep-copy trace pattern list */
	struct eal_trace_arg *ta, *ta_copy;
	STAILQ_FOREACH(ta, &src->trace_patterns, next) {
		ta_copy = malloc(sizeof(*ta_copy));
		if (ta_copy == NULL)
			goto err;
		ta_copy->val = strdup(ta->val);
		if (ta_copy->val == NULL) {
			free(ta_copy);
			goto err;
		}
		STAILQ_INSERT_TAIL(&dst->trace_patterns, ta_copy, next);
	}

	/* deep-copy heap strings */
	if (src->trace_dir != NULL) {
		dst->trace_dir = strdup(src->trace_dir);
		if (dst->trace_dir == NULL)
			goto err;
	}
	if (src->hugefile_prefix != NULL) {
		dst->hugefile_prefix = strdup(src->hugefile_prefix);
		if (dst->hugefile_prefix == NULL)
			goto err;
	}
	if (src->hugepage_dir != NULL) {
		dst->hugepage_dir = strdup(src->hugepage_dir);
		if (dst->hugepage_dir == NULL)
			goto err;
	}
	if (src->user_mbuf_pool_ops_name != NULL) {
		dst->user_mbuf_pool_ops_name = strdup(src->user_mbuf_pool_ops_name);
		if (dst->user_mbuf_pool_ops_name == NULL)
			goto err;
	}

	/* deep-copy per-lcore cpusets */
	for (unsigned int i = 0; i < RTE_MAX_LCORE; i++) {
		if (src->lcore_cpusets[i] == NULL)
			continue;
		dst->lcore_cpusets[i] = malloc(sizeof(rte_cpuset_t));
		if (dst->lcore_cpusets[i] == NULL)
			goto err;
		*dst->lcore_cpusets[i] = *src->lcore_cpusets[i];
	}

	return 0;

err:
	eal_user_cfg_cleanup(dst);
	return -1;
}

/**
 * Hardware facts about a single physical CPU, populated during CPU discovery.
 * Indexed by physical CPU ID (not DPDK lcore ID).
 */
struct eal_cpu_info {
	bool detected;         /**< true if this CPU ID is valid and visible to the OS */
	unsigned int numa_id;  /**< NUMA node this CPU belongs to */
	unsigned int core_id;  /**< physical core number on its NUMA node */
};

struct hp_sizes {
	uint64_t size;         /**< hugepage size in bytes */
	char dir[PATH_MAX];    /**< dir where hugetlbfs is mounted for this size */
	char subdir[32];       /**< sysfs subdir name for this size, e.g. "hugepages-2048kB" */
	uint32_t total_pages;  /**< total hugepages of this size across all NUMA nodes */
	uint32_t max_pages[RTE_MAX_NUMA_NODES];
	/**< maximum hugepages of this size available on each NUMA node */
};

/**
 * Discovered information about the system hardware.
 * Immutable after discovery.
 */
struct eal_platform_info {
	size_t cpu_count;                /**< number of entries in cpu_info[] */
	struct eal_cpu_info *cpu_info;   /**< per-physical-CPU hardware facts */
	uint32_t numa_node_count;        /**< number of detected NUMA nodes */
	uint32_t *numa_nodes;            /**< sorted list of detected NUMA node IDs */
	uint8_t num_hugepage_sizes;      /**< how many sizes on this system */
	struct hp_sizes hugepage_sizes[MAX_HUGEPAGE_SIZES];
};

/**
 * Per-lcore runtime state, owned by EAL.
 */
struct lcore_cfg {
	int core_index;                   /**< relative index, starting from 0 */
	enum rte_lcore_role_t role;       /**< role assigned to this lcore */
	rte_cpuset_t cpuset;              /**< cpu set which the lcore affinity to */
	uint16_t first_cpu;               /**< lowest CPU set in cpuset, UINT16_MAX if none */
	/* Fields for executing code on a remote lcore */
	rte_thread_t thread_id;          /**< thread identifier */
	int pipe_main2worker[2];         /**< communication pipe with main */
	int pipe_worker2main[2];         /**< communication pipe with main */
	RTE_ATOMIC(lcore_function_t *) volatile f; /**< function to call */
	void * volatile arg;             /**< argument of function */
	volatile int ret;                /**< return value of function */
	volatile RTE_ATOMIC(enum rte_lcore_state_t) state; /**< lcore state */
};

/**
 * A plugin loaded by EAL, including directory-expanded entries.
 */
struct shared_driver {
	TAILQ_ENTRY(shared_driver) next;
	char name[PATH_MAX];
	void *lib_handle;
};
TAILQ_HEAD(eal_solib_list, shared_driver);

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
	enum rte_proc_type_t process_type; /**< primary or secondary process */
	enum rte_iova_mode iova_mode; /**< PA or VA IOVA mapping mode */
	uint32_t main_lcore;          /**< ID of the main lcore */
	uint32_t lcore_count;         /**< Number of active lcore IDs (role != ROLE_OFF). */
	struct lcore_cfg lcore_cfg[RTE_MAX_LCORE];
	RTE_BITSET_DECLARE(core_indices, RTE_MAX_LCORE); /**< currently allocated core_indices */

	uint32_t num_hugepage_sizes;       /**< how many sizes stored in hugepage_info[] */
	struct hugepage_info hugepage_info[MAX_HUGEPAGE_SIZES];
	struct rte_mem_config *mem_config; /**< pointer to memory config (in shared memory) */
	struct eal_solib_list loaded_plugins; /**< all plugins loaded by eal_plugins_init() */
};

const struct eal_platform_info *eal_get_platform_info(void);
struct eal_user_cfg *eal_get_user_configuration(void);
struct eal_runtime_state *eal_get_runtime_state(void);

#endif /* EAL_INTERNAL_CFG_H */

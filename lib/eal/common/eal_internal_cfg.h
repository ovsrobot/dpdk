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
	uint8_t	unlink_before_mapping; /* Unlink files before mapping, leave no trace */
	uint8_t unlink_existing;       /* Unlink existing files at startup */
};

/**
 * internal configuration
 */
struct internal_config {
	volatile size_t memory;           /* amount of asked memory */
	volatile enum rte_proc_type_t process_type; /* multi-process proc type */
	volatile uint32_t
		force_nchannel:1, /* force number of channels */
		force_nrank:1,    /* force number of ranks */
		no_hugetlbfs:1,   /* disable hugetlbfs */
		no_pci:1,         /* disable PCI */
		no_hpet:1,        /* disable HPET */
		vmware_tsc_map:1, /* use VMware TSC mapping */
		no_shconf:1,      /* no shared config */
		in_memory:1,	  /* operate entirely in-memory no shared files */
		create_uio_dev:1, /* create /dev/uioX devices */
		force_sockets:1,  /* allocate memory on specific sockets */
		force_socket_limits:1,
		legacy_mem:1,	  /* no dynamic allocation */
		match_allocations:1, /* free hugepages exactly as allocated */
		unlink_before_mapping:1, /* unlink before mapping leave no trace in hugetlbfs */
		unlink_existing:1, /* unlink existing files at startup */
		single_file_segments:1, /* all page within single file */
		no_telemetry:1,   /* disable telemetry */
		init_complete:1;  /* EAL has completed initialization */

	uintptr_t base_virtaddr;          /* base address to try and reserve memory from */
	volatile enum rte_intr_mode vfio_intr_mode; /* default interrupt mode for VFIO */
	rte_uuid_t vfio_vf_token;	  /* VF token for VFIO-PCI bound PF and VFs devices */
	volatile int syslog_facility;	  /* facility passed to openlog() */
	char *user_mbuf_pool_ops_name;    /* user defined mbuf pool ops name */
	rte_cpuset_t ctrl_cpuset;         /* cpuset for ctrl threads */
	struct simd_bitwidth max_simd_bitwidth; /* max simd bitwidth path to use */
	struct hugepage_file_discipline hugepage_file;
	enum rte_iova_mode iova_mode ;    /* IOVA mode on this system  */
	unsigned int num_hugepage_sizes;  /* how many sizes on this system */
	size_t huge_worker_stack_size;    /* worker thread stack size */
	char *hugefile_prefix;            /* base filename of hugetlbfs files */
	char *hugepage_dir;               /* hugetlbfs directory */
	struct hugepage_info hugepage_info[MAX_HUGEPAGE_SIZES];
	volatile uint64_t socket_mem[RTE_MAX_NUMA_NODES]; /* amount of memory per socket */
	volatile uint64_t socket_limit[RTE_MAX_NUMA_NODES]; /* limit amount of memory per socket */
};

void eal_reset_internal_config(struct internal_config *internal_cfg);

#endif /* EAL_INTERNAL_CFG_H */

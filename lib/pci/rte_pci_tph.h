/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Ltd.
 */

#ifndef _RTE_PCI_TPH_H_
#define _RTE_PCI_TPH_H_

/**
 * @file
 *
 * RTE PCI TLP Processing Hints helpers
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

/**
 * @warning
 * @b EXPERIMENTAL: this structure may change, or be removed, without prior notice
 *
 * ACPI TPH _DSM input args structure.
 * Refer to PCI-SIG ECN "Revised _DSM for Cache Locality TPH Features" for details.
 */
struct rte_tph_acpi__dsm_args {
	uint32_t feature_id; /**< Always 0. */
	struct {
		/** APIC/PPTT Processor/Processor container ID. */
		uint32_t uid;
	} __rte_packed featureArg1; /**< 1st Arg. */
	struct {
		/** Intended ph bits just for validating. */
		uint64_t ph : 2;
		/** If type=1 uid is Processor container ID. */
		uint64_t type :  1;
		/** cache_reference is valid if cache_ref_valid=1. */
		uint64_t cache_ref_valid : 1;
		uint64_t reserved : 28;
		/** PPTT cache ID of the desired target. */
		uint64_t cache_refernce : 32;
	} __rte_packed featureArg2; /**< 2ns Arg. */
} __rte_packed;

/**
 * @warning
 * @b EXPERIMENTAL: this structure may change, or be removed, without prior notice
 *
 * ACPI TPH _DSM return structure.
 * Refer to PCI-SIG ECN "Revised _DSM for Cache Locality TPH Features" for details.
 */
struct rte_tph_acpi__dsm_return {
	uint64_t vmem_st_valid : 1; /**< if set to 1, vmem_st (8-bit ST) is valid. */
	/** if set to 1, vmem_ext_st (16-bit vmem ST) is valid. */
	uint64_t vmem_ext_st_valid : 1;
	/** if set to 1, ph bits in input args is valid. */
	uint64_t vmem_ph_ignore : 1;
	uint64_t reserved_1 : 5;
	/** 8-bit volatile memory ST) */
	uint64_t vmem_st : 8;
	/** 16-bit volatile ST) */
	uint64_t vmem_ext_st : 16;
	uint64_t pmem_st_valid : 1;  /**< if set to 1, pmem_st (8-bit ST) is valid. */
	/** if set to 1, pmem_ext_st (16-bit ST) is valid. */
	uint64_t pmem_ext_st_valid : 1;
	/** if set to 1, ph bits in input args are valid for persistent memory. */
	uint64_t pmem_ph_ignore : 1;
	uint64_t reserved_2 : 5;
	/** 8-bit persistent memory ST) */
	uint64_t pmem_st : 8;
	/** 16-bit persistent memory ST) */
	uint64_t pmem_ext_st : 16;
} __rte_packed;


/**
 *
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Initializes stashing hints configuration with a platform specific stashing hint
 * that matches the lcore_id and cache_level.
 *
 * @param lcore_id
 *  The lcore_id of the processor of the cache stashing target. If is_container is set
 *  the target is the processor container of the CPU specified by the lcore_id.
 * @param type
 *  If set to 1, the procssor container of the processor specified by lcore_id will be
 *  used at the stashing target. If set to 0, processor specified by the lcore_id will be
 *  used as the stashing target.
 * @param cache_level
 *  The cache level of the processor/container specified by the lcore_id.
 * @param ph
 *  TPH Processing Hints bits.
 * @param args
 *  ACPI TPH _DSM object arguments structure.
 * @return
 *  - (0) on Success.
 *  - 0 < or 0 > on Failure.
 */

int rte_init_tph_acpi__dsm_args(uint16_t lcore_id, uint8_t type,
				uint8_t cache_level, uint8_t ph,
				struct rte_tph_acpi__dsm_args *args);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PCI_TPH_H_ */

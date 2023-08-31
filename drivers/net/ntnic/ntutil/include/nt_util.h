/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTOSS_SYSTEM_NT_UTIL_H
#define NTOSS_SYSTEM_NT_UTIL_H

#include <rte_bitops.h>
#include <rte_cycles.h>
#include <rte_string_fns.h>

#define _unused __rte_unused

#define PCIIDENT_TO_DOMAIN(pci_ident) \
	((uint16_t)(((unsigned int)(pci_ident) >> 16) & 0xFFFFU))
#define PCIIDENT_TO_BUSNR(pci_ident) \
	((uint8_t)(((unsigned int)(pci_ident) >> 8) & 0xFFU))
#define PCIIDENT_TO_DEVNR(pci_ident) \
	((uint8_t)(((unsigned int)(pci_ident) >> 3) & 0x1FU))
#define PCIIDENT_TO_FUNCNR(pci_ident) \
	((uint8_t)(((unsigned int)(pci_ident) >> 0) & 0x7U))

#define PCIIDENT_PRINT_STR "%04x:%02x:%02x.%x"
#define BDF_TO_PCIIDENT(dom, bus, dev, fnc) \
	(((dom) << 16) | ((bus) << 8) | ((dev) << 3) | (fnc))

/* ALIGN: Align x to a boundary */
#define ALIGN(x, a)                           \
	({                                    \
		__typeof__(x) _a = (a);       \
		((x) + (_a - 1)) & ~(_a - 1); \
	})

/* PALIGN: Align pointer p to a boundary */
#define PALIGN(p, a) ((__typeof__(p))ALIGN((unsigned long)(p), (a)))

/* Allocation size matching minimum alignment of specified size */
#define ALIGN_SIZE(_size_) (1 << rte_log2_u64(_size_))

#define NT_OS_WAIT_USEC(x)    \
	rte_delay_us_sleep( \
		x) /* uses usleep which schedules out the calling thread */
/* spins in a waiting loop calling pause asm instruction uses RDTSC - precise wait */
#define NT_OS_WAIT_USEC_POLL(x) \
	rte_delay_us(        \
		x)

#define NT_OS_GET_TIME_US() \
	(rte_get_timer_cycles() / (rte_get_timer_hz() / 1000 / 1000))
#define NT_OS_GET_TIME_NS() \
	(rte_get_timer_cycles() * 10 / (rte_get_timer_hz() / 1000 / 1000 / 100))
#define NT_OS_GET_TIME_MONOTONIC_COUNTER() (rte_get_timer_cycles())

struct nt_dma_s {
	uint64_t iova;
	uint64_t addr;
	uint64_t size;
};

struct nt_dma_s *nt_dma_alloc(uint64_t size, uint64_t align, int numa);
void nt_dma_free(struct nt_dma_s *vfio_addr);

struct nt_util_vfio_impl {
	int (*vfio_dma_map)(int vf_num, void *virt_addr, uint64_t *iova_addr,
			    uint64_t size);
	int (*vfio_dma_unmap)(int vf_num, void *virt_addr, uint64_t iova_addr,
			      uint64_t size);
};

void nt_util_vfio_init(struct nt_util_vfio_impl *impl);

#endif /* NTOSS_SYSTEM_NT_UTIL_H */

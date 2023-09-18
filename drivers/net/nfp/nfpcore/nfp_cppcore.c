/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Netronome Systems, Inc.
 * All rights reserved.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <rte_byteorder.h>
#include <ethdev_pci.h>

#include "nfp_cpp.h"
#include "nfp_logs.h"
#include "nfp6000/nfp6000.h"
#include "nfp6000/nfp_xpb.h"
#include "nfp_nffw.h"

#define NFP_PL_DEVICE_ID                        0x00000004
#define NFP_PL_DEVICE_ID_MASK                   0xff
#define NFP_PL_DEVICE_PART_MASK                 0xffff0000
#define NFP_PL_DEVICE_MODEL_MASK               (NFP_PL_DEVICE_PART_MASK | \
						NFP_PL_DEVICE_ID_MASK)

void
nfp_cpp_priv_set(struct nfp_cpp *cpp,
		void *priv)
{
	cpp->priv = priv;
}

void *
nfp_cpp_priv(struct nfp_cpp *cpp)
{
	return cpp->priv;
}

void
nfp_cpp_model_set(struct nfp_cpp *cpp,
		uint32_t model)
{
	cpp->model = model;
}

uint32_t
nfp_cpp_model(struct nfp_cpp *cpp)
{
	int err;
	uint32_t model;

	if (cpp == NULL)
		return NFP_CPP_MODEL_INVALID;

	err = __nfp_cpp_model_autodetect(cpp, &model);

	if (err < 0)
		return err;

	return model;
}

void
nfp_cpp_interface_set(struct nfp_cpp *cpp,
		uint32_t interface)
{
	cpp->interface = interface;
}

int
nfp_cpp_serial(struct nfp_cpp *cpp,
		const uint8_t **serial)
{
	*serial = cpp->serial;
	return cpp->serial_len;
}

int
nfp_cpp_serial_set(struct nfp_cpp *cpp,
		const uint8_t *serial,
		size_t serial_len)
{
	if (cpp->serial_len)
		free(cpp->serial);

	cpp->serial = malloc(serial_len);
	if (cpp->serial == NULL)
		return -1;

	memcpy(cpp->serial, serial, serial_len);
	cpp->serial_len = serial_len;

	return 0;
}

uint16_t
nfp_cpp_interface(struct nfp_cpp *cpp)
{
	if (cpp == NULL)
		return NFP_CPP_INTERFACE(NFP_CPP_INTERFACE_TYPE_INVALID, 0, 0);

	return cpp->interface;
}

void *
nfp_cpp_area_priv(struct nfp_cpp_area *cpp_area)
{
	return &cpp_area[1];
}

struct nfp_cpp *
nfp_cpp_area_cpp(struct nfp_cpp_area *cpp_area)
{
	return cpp_area->cpp;
}

const char *
nfp_cpp_area_name(struct nfp_cpp_area *cpp_area)
{
	return cpp_area->name;
}

#define NFP_IMB_TGTADDRESSMODECFG_MODE_of(_x)       (((_x) >> 13) & 0x7)
#define NFP_IMB_TGTADDRESSMODECFG_ADDRMODE          RTE_BIT32(12)

static int
nfp_cpp_set_mu_locality_lsb(struct nfp_cpp *cpp)
{
	int ret;
	int mode;
	int addr40;
	uint32_t imbcppat;

	imbcppat = cpp->imb_cat_table[NFP_CPP_TARGET_MU];
	mode = NFP_IMB_TGTADDRESSMODECFG_MODE_of(imbcppat);
	addr40 = imbcppat & NFP_IMB_TGTADDRESSMODECFG_ADDRMODE;

	ret = nfp_cppat_mu_locality_lsb(mode, addr40);
	if (ret < 0)
		return ret;

	cpp->mu_locality_lsb = ret;

	return 0;
}

uint32_t
nfp_cpp_mu_locality_lsb(struct nfp_cpp *cpp)
{
	return cpp->mu_locality_lsb;
}

/*
 * nfp_cpp_area_alloc - allocate a new CPP area
 * @cpp:    CPP handle
 * @dest:   CPP id
 * @address:    start address on CPP target
 * @size:   size of area in bytes
 *
 * Allocate and initialize a CPP area structure.  The area must later
 * be locked down with an 'acquire' before it can be safely accessed.
 *
 * NOTE: @address and @size must be 32-bit aligned values.
 */
struct nfp_cpp_area *
nfp_cpp_area_alloc_with_name(struct nfp_cpp *cpp,
		uint32_t dest,
		const char *name,
		uint64_t address,
		uint32_t size)
{
	int err;
	struct nfp_cpp_area *area;
	uint64_t tmp64 = (uint64_t)address;

	if (cpp == NULL)
		return NULL;

	/* Remap from cpp_island to cpp_target */
	err = nfp_target_cpp(dest, tmp64, &dest, &tmp64, cpp->imb_cat_table);
	if (err < 0)
		return NULL;

	address = tmp64;

	if (name == NULL)
		name = "";

	area = calloc(1, sizeof(*area) + cpp->op->area_priv_size +
			strlen(name) + 1);
	if (area == NULL)
		return NULL;

	area->cpp = cpp;
	area->name = ((char *)area) + sizeof(*area) + cpp->op->area_priv_size;
	memcpy(area->name, name, strlen(name) + 1);

	err = cpp->op->area_init(area, dest, address, size);
	if (err < 0) {
		PMD_DRV_LOG(ERR, "Area init op failed");
		free(area);
		return NULL;
	}

	area->offset = address;
	area->size = size;

	return area;
}

struct nfp_cpp_area *
nfp_cpp_area_alloc(struct nfp_cpp *cpp,
		uint32_t dest,
		uint64_t address,
		size_t size)
{
	return nfp_cpp_area_alloc_with_name(cpp, dest, NULL, address, size);
}

/*
 * nfp_cpp_area_alloc_acquire - allocate a new CPP area and lock it down
 *
 * @cpp:    CPP handle
 * @dest:   CPP id
 * @address:    start address on CPP target
 * @size:   size of area
 *
 * Allocate and initialize a CPP area structure, and lock it down so
 * that it can be accessed directly.
 *
 * NOTE: @address and @size must be 32-bit aligned values.
 *
 * NOTE: The area must also be 'released' when the structure is freed.
 */
struct nfp_cpp_area *
nfp_cpp_area_alloc_acquire(struct nfp_cpp *cpp,
		uint32_t destination,
		uint64_t address,
		size_t size)
{
	struct nfp_cpp_area *area;

	area = nfp_cpp_area_alloc(cpp, destination, address, size);
	if (area == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate CPP area");
		return NULL;
	}

	if (nfp_cpp_area_acquire(area) != 0) {
		PMD_DRV_LOG(ERR, "Failed to acquire CPP area");
		nfp_cpp_area_free(area);
		return NULL;
	}

	return area;
}

/*
 * nfp_cpp_area_free - free up the CPP area
 * area:    CPP area handle
 *
 * Frees up memory resources held by the CPP area.
 */
void
nfp_cpp_area_free(struct nfp_cpp_area *area)
{
	if (area->cpp->op->area_cleanup != NULL)
		area->cpp->op->area_cleanup(area);
	free(area);
}

/*
 * nfp_cpp_area_release_free - release CPP area and free it
 * area:    CPP area handle
 *
 * Releases CPP area and frees up memory resources held by the it.
 */
void
nfp_cpp_area_release_free(struct nfp_cpp_area *area)
{
	nfp_cpp_area_release(area);
	nfp_cpp_area_free(area);
}

/*
 * nfp_cpp_area_acquire - lock down a CPP area for access
 * @area:   CPP area handle
 *
 * Locks down the CPP area for a potential long term activity.  Area
 * must always be locked down before being accessed.
 */
int
nfp_cpp_area_acquire(struct nfp_cpp_area *area)
{
	if (area->cpp->op->area_acquire != NULL) {
		int err = area->cpp->op->area_acquire(area);

		if (err < 0) {
			PMD_DRV_LOG(ERR, "Area acquire op failed");
			return -1;
		}
	}

	return 0;
}

/*
 * nfp_cpp_area_release - release a locked down CPP area
 * @area:   CPP area handle
 *
 * Releases a previously locked down CPP area.
 */
void
nfp_cpp_area_release(struct nfp_cpp_area *area)
{
	if (area->cpp->op->area_release != NULL)
		area->cpp->op->area_release(area);
}

/*
 * nfp_cpp_area_iomem() - get IOMEM region for CPP area
 *
 * @area:       CPP area handle
 *
 * Returns an iomem pointer for use with readl()/writel() style operations.
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 *
 * Return: pointer to the area, or NULL
 */
void *
nfp_cpp_area_iomem(struct nfp_cpp_area *area)
{
	void *iomem = NULL;

	if (area->cpp->op->area_iomem != NULL)
		iomem = area->cpp->op->area_iomem(area);

	return iomem;
}

/*
 * nfp_cpp_area_read - read data from CPP area
 *
 * @area:       CPP area handle
 * @offset:     offset into CPP area
 * @kernel_vaddr:   kernel address to put data into
 * @length:     number of bytes to read
 *
 * Read data from indicated CPP region.
 *
 * NOTE: @offset and @length must be 32-bit aligned values.
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 */
int
nfp_cpp_area_read(struct nfp_cpp_area *area,
		uint32_t offset,
		void *kernel_vaddr,
		size_t length)
{
	if ((offset + length) > area->size)
		return -EFAULT;

	return area->cpp->op->area_read(area, kernel_vaddr, offset, length);
}

/*
 * nfp_cpp_area_write - write data to CPP area
 *
 * @area:       CPP area handle
 * @offset:     offset into CPP area
 * @kernel_vaddr:   kernel address to read data from
 * @length:     number of bytes to write
 *
 * Write data to indicated CPP region.
 *
 * NOTE: @offset and @length must be 32-bit aligned values.
 *
 * NOTE: Area must have been locked down with an 'acquire'.
 */
int
nfp_cpp_area_write(struct nfp_cpp_area *area,
		uint32_t offset,
		const void *kernel_vaddr,
		size_t length)
{
	if ((offset + length) > area->size)
		return -EFAULT;

	return area->cpp->op->area_write(area, kernel_vaddr, offset, length);
}

/*
 * Return the correct CPP address, and fixup xpb_addr as needed,
 * based upon NFP model.
 */
static uint32_t
nfp_xpb_to_cpp(struct nfp_cpp *cpp,
		uint32_t *xpb_addr)
{
	int island;
	uint32_t xpb;

	xpb = NFP_CPP_ID(14, NFP_CPP_ACTION_RW, 0);

	/*
	 * Ensure that non-local XPB accesses go out through the
	 * global XPBM bus.
	 */
	island = ((*xpb_addr) >> 24) & 0x3f;

	if (island == 0)
		return xpb;

	if (island == 1) {
		/*
		 * Accesses to the ARM Island overlay uses Island 0
		 * Global Bit
		 */
		(*xpb_addr) &= ~0x7f000000;
		if (*xpb_addr < 0x60000)
			*xpb_addr |= (1 << 30);
		else
			/* And only non-ARM interfaces use island id = 1 */
			if (NFP_CPP_INTERFACE_TYPE_of(nfp_cpp_interface(cpp)) !=
					NFP_CPP_INTERFACE_TYPE_ARM)
				*xpb_addr |= (1 << 24);
	} else {
		(*xpb_addr) |= (1 << 30);
	}

	return xpb;
}

int
nfp_cpp_area_readl(struct nfp_cpp_area *area,
		uint32_t offset,
		uint32_t *value)
{
	int sz;
	uint32_t tmp = 0;

	sz = nfp_cpp_area_read(area, offset, &tmp, sizeof(tmp));
	*value = rte_le_to_cpu_32(tmp);

	return (sz == sizeof(*value)) ? 0 : -1;
}

int
nfp_cpp_area_writel(struct nfp_cpp_area *area,
		uint32_t offset,
		uint32_t value)
{
	int sz;

	value = rte_cpu_to_le_32(value);
	sz = nfp_cpp_area_write(area, offset, &value, sizeof(value));
	return (sz == sizeof(value)) ? 0 : -1;
}

int
nfp_cpp_area_readq(struct nfp_cpp_area *area,
		uint32_t offset,
		uint64_t *value)
{
	int sz;
	uint64_t tmp = 0;

	sz = nfp_cpp_area_read(area, offset, &tmp, sizeof(tmp));
	*value = rte_le_to_cpu_64(tmp);

	return (sz == sizeof(*value)) ? 0 : -1;
}

int
nfp_cpp_area_writeq(struct nfp_cpp_area *area,
		uint32_t offset,
		uint64_t value)
{
	int sz;

	value = rte_cpu_to_le_64(value);
	sz = nfp_cpp_area_write(area, offset, &value, sizeof(value));

	return (sz == sizeof(value)) ? 0 : -1;
}

int
nfp_cpp_readl(struct nfp_cpp *cpp,
		uint32_t cpp_id,
		uint64_t address,
		uint32_t *value)
{
	int sz;
	uint32_t tmp;

	sz = nfp_cpp_read(cpp, cpp_id, address, &tmp, sizeof(tmp));
	*value = rte_le_to_cpu_32(tmp);

	return (sz == sizeof(*value)) ? 0 : -1;
}

int
nfp_cpp_writel(struct nfp_cpp *cpp,
		uint32_t cpp_id,
		uint64_t address,
		uint32_t value)
{
	int sz;

	value = rte_cpu_to_le_32(value);
	sz = nfp_cpp_write(cpp, cpp_id, address, &value, sizeof(value));

	return (sz == sizeof(value)) ? 0 : -1;
}

int
nfp_cpp_readq(struct nfp_cpp *cpp,
		uint32_t cpp_id,
		uint64_t address,
		uint64_t *value)
{
	int sz;
	uint64_t tmp;

	sz = nfp_cpp_read(cpp, cpp_id, address, &tmp, sizeof(tmp));
	*value = rte_le_to_cpu_64(tmp);

	return (sz == sizeof(*value)) ? 0 : -1;
}

int
nfp_cpp_writeq(struct nfp_cpp *cpp,
		uint32_t cpp_id,
		uint64_t address,
		uint64_t value)
{
	int sz;

	value = rte_cpu_to_le_64(value);
	sz = nfp_cpp_write(cpp, cpp_id, address, &value, sizeof(value));

	return (sz == sizeof(value)) ? 0 : -1;
}

int
nfp_xpb_writel(struct nfp_cpp *cpp,
		uint32_t xpb_addr,
		uint32_t value)
{
	uint32_t cpp_dest;

	cpp_dest = nfp_xpb_to_cpp(cpp, &xpb_addr);

	return nfp_cpp_writel(cpp, cpp_dest, xpb_addr, value);
}

int
nfp_xpb_readl(struct nfp_cpp *cpp,
		uint32_t xpb_addr,
		uint32_t *value)
{
	uint32_t cpp_dest;

	cpp_dest = nfp_xpb_to_cpp(cpp, &xpb_addr);

	return nfp_cpp_readl(cpp, cpp_dest, xpb_addr, value);
}

static struct nfp_cpp *
nfp_cpp_alloc(struct rte_pci_device *dev,
		int driver_lock_needed)
{
	int err;
	struct nfp_cpp *cpp;
	const struct nfp_cpp_operations *ops;

	ops = nfp_cpp_transport_operations();

	if (ops == NULL || ops->init == NULL)
		return NULL;

	cpp = calloc(1, sizeof(*cpp));
	if (cpp == NULL)
		return NULL;

	cpp->op = ops;
	cpp->driver_lock_needed = driver_lock_needed;

	if (cpp->op->init) {
		err = cpp->op->init(cpp, dev);
		if (err < 0) {
			free(cpp);
			return NULL;
		}
	}

	if (NFP_CPP_MODEL_IS_6000(nfp_cpp_model(cpp))) {
		uint32_t xpbaddr;
		size_t tgt;

		for (tgt = 0; tgt < RTE_DIM(cpp->imb_cat_table); tgt++) {
			/* Hardcoded XPB IMB Base, island 0 */
			xpbaddr = 0x000a0000 + (tgt * 4);
			err = nfp_xpb_readl(cpp, xpbaddr,
					(uint32_t *)&cpp->imb_cat_table[tgt]);
			if (err < 0) {
				free(cpp);
				return NULL;
			}
		}
	}

	err = nfp_cpp_set_mu_locality_lsb(cpp);
	if (err < 0) {
		PMD_DRV_LOG(ERR, "Can't calculate MU locality bit offset");
		free(cpp);
		return NULL;
	}

	return cpp;
}

/*
 * nfp_cpp_free - free the CPP handle
 * @cpp:    CPP handle
 */
void
nfp_cpp_free(struct nfp_cpp *cpp)
{
	if (cpp->op != NULL && cpp->op->free != NULL)
		cpp->op->free(cpp);

	if (cpp->serial_len != 0)
		free(cpp->serial);

	free(cpp);
}

struct nfp_cpp *
nfp_cpp_from_device_name(struct rte_pci_device *dev,
		int driver_lock_needed)
{
	return nfp_cpp_alloc(dev, driver_lock_needed);
}

/*
 * nfp_cpp_read - read from CPP target
 * @cpp:        CPP handle
 * @destination:    CPP id
 * @address:        offset into CPP target
 * @kernel_vaddr:   kernel buffer for result
 * @length:     number of bytes to read
 */
int
nfp_cpp_read(struct nfp_cpp *cpp,
		uint32_t destination,
		uint64_t address,
		void *kernel_vaddr,
		size_t length)
{
	int err;
	struct nfp_cpp_area *area;

	area = nfp_cpp_area_alloc_acquire(cpp, destination, address, length);
	if (area == NULL) {
		PMD_DRV_LOG(ERR, "Area allocation/acquire failed for read");
		return -1;
	}

	err = nfp_cpp_area_read(area, 0, kernel_vaddr, length);

	nfp_cpp_area_release_free(area);
	return err;
}

/*
 * nfp_cpp_write - write to CPP target
 * @cpp:        CPP handle
 * @destination:    CPP id
 * @address:        offset into CPP target
 * @kernel_vaddr:   kernel buffer to read from
 * @length:     number of bytes to write
 */
int
nfp_cpp_write(struct nfp_cpp *cpp,
		uint32_t destination,
		uint64_t address,
		const void *kernel_vaddr,
		size_t length)
{
	int err;
	struct nfp_cpp_area *area;

	area = nfp_cpp_area_alloc_acquire(cpp, destination, address, length);
	if (area == NULL) {
		PMD_DRV_LOG(ERR, "Area allocation/acquire failed for write");
		return -1;
	}

	err = nfp_cpp_area_write(area, 0, kernel_vaddr, length);

	nfp_cpp_area_release_free(area);
	return err;
}

/*
 * NOTE: This code should not use nfp_xpb_* functions,
 * as those are model-specific
 */
uint32_t
__nfp_cpp_model_autodetect(struct nfp_cpp *cpp,
		uint32_t *model)
{
	int err;
	uint32_t reg;

	err = nfp_xpb_readl(cpp, NFP_XPB_DEVICE(1, 1, 16) + NFP_PL_DEVICE_ID,
			&reg);
	if (err < 0)
		return err;

	*model = reg & NFP_PL_DEVICE_MODEL_MASK;
	if ((*model & NFP_PL_DEVICE_ID_MASK) != 0)
		*model -= 0x10;

	return 0;
}

/*
 * nfp_cpp_map_area() - Helper function to map an area
 * @cpp:    NFP CPP handler
 * @cpp_id: CPP ID
 * @addr:   CPP address
 * @size:   Size of the area
 * @area:   Area handle (output)
 *
 * Map an area of IOMEM access.  To undo the effect of this function call
 * @nfp_cpp_area_release_free(*area).
 *
 * Return: Pointer to memory mapped area or NULL
 */
uint8_t *
nfp_cpp_map_area(struct nfp_cpp *cpp,
		uint32_t cpp_id,
		uint64_t addr,
		uint32_t size,
		struct nfp_cpp_area **area)
{
	uint8_t *res;

	*area = nfp_cpp_area_alloc_acquire(cpp, cpp_id, addr, size);
	if (*area == NULL) {
		PMD_DRV_LOG(ERR, "Area allocation/acquire failed for map");
		goto err_eio;
	}

	res = nfp_cpp_area_iomem(*area);
	if (res == NULL)
		goto err_release_free;

	return res;

err_release_free:
	nfp_cpp_area_release_free(*area);
err_eio:
	return NULL;
}

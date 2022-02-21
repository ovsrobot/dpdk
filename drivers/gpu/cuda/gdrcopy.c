/* SPDX-License-Identifier: BSD-3-Clause
* Copyright (c) 2022 NVIDIA Corporation & Affiliates
*/
#include <rte_common.h>
#include <rte_log.h>
#include "gdrcopy.h"

static RTE_LOG_REGISTER_DEFAULT(cuda_gdr_logtype, NOTICE);

/* Helper macro for logging */
#define rte_cuda_gdrc_log(level, fmt, ...) \
	rte_log(RTE_LOG_ ## level, cuda_gdr_logtype, fmt "\n", ##__VA_ARGS__)

static void *gdrclib;
static gdr_t (*sym_gdr_open)(void);
static int (*sym_gdr_close)(gdr_t g);
static int (*sym_gdr_pin_buffer)(gdr_t g, unsigned long addr, size_t size, uint64_t p2p_token, uint32_t va_space, gdr_mh_t *handle);
static int (*sym_gdr_unpin_buffer)(gdr_t g, gdr_mh_t handle);
static int (*sym_gdr_map)(gdr_t g, gdr_mh_t handle, void **va, size_t size);
static int (*sym_gdr_unmap)(gdr_t g, gdr_mh_t handle, void *va, size_t size);

static int
gdrcopy_loader(void)
{
	char gdrcopy_path[1024];

	if (getenv("GDRCOPY_PATH_L") == NULL)
		snprintf(gdrcopy_path, 1024, "%s", "libgdrapi.so");
	else
		snprintf(gdrcopy_path, 1024, "%s/%s", getenv("GDRCOPY_PATH_L"), "libgdrapi.so");

	gdrclib = dlopen(gdrcopy_path, RTLD_LAZY);
	if (gdrclib == NULL) {
		rte_cuda_gdrc_log(ERR, "Failed to find GDRCopy library %s (GDRCOPY_PATH_L=%s)\n",
				gdrcopy_path, getenv("GDRCOPY_PATH_L"));
		return -1;
	}

	sym_gdr_open = dlsym(gdrclib, "gdr_open");
	if (sym_gdr_open == NULL) {
		rte_cuda_gdrc_log(ERR, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_close = dlsym(gdrclib, "gdr_close");
	if (sym_gdr_close == NULL) {
		rte_cuda_gdrc_log(ERR, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_pin_buffer = dlsym(gdrclib, "gdr_pin_buffer");
	if (sym_gdr_pin_buffer == NULL) {
		rte_cuda_gdrc_log(ERR, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_unpin_buffer = dlsym(gdrclib, "gdr_unpin_buffer");
	if (sym_gdr_unpin_buffer == NULL) {
		rte_cuda_gdrc_log(ERR, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_map = dlsym(gdrclib, "gdr_map");
	if (sym_gdr_map == NULL) {
		rte_cuda_gdrc_log(ERR, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_unmap = dlsym(gdrclib, "gdr_unmap");
	if (sym_gdr_unmap == NULL) {
		rte_cuda_gdrc_log(ERR, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	return 0;
}

static int
gdrcopy_open(gdr_t *g)
{
	gdr_t g_;

	g_ = sym_gdr_open();
	if (!g_)
		return -1;
	*g = g_;

	return 0;
}

static int
gdrcopy_close(gdr_t *g)
{
	sym_gdr_close(*g);
	return 0;
}

int
gdrcopy_pin(gdr_t *gdrc_h, __rte_unused gdr_mh_t *mh, uint64_t d_addr, size_t size, void **h_addr)
{
#ifdef DRIVERS_GPU_CUDA_GDRCOPY_H
	if (*gdrc_h == NULL) {
		if (gdrcopy_loader())
			return -ENOTSUP;

		if (gdrcopy_open(gdrc_h)) {
			rte_cuda_gdrc_log(ERR,
					"GDRCopy gdrdrv kernel module not found. Can't CPU map GPU memory.");
			return -EPERM;
		}
	}

	/* Pin the device buffer */
	if (sym_gdr_pin_buffer(*gdrc_h, d_addr, size, 0, 0, mh) != 0) {
		rte_cuda_gdrc_log(ERR, "GDRCopy pin buffer error.");
		return -1;
	}

	/* Map the buffer to user space */
	if (sym_gdr_map(*gdrc_h, *mh, h_addr, size) != 0) {
		rte_cuda_gdrc_log(ERR, "GDRCopy map buffer error.");
		sym_gdr_unpin_buffer(*gdrc_h, *mh);
		return -1;
	}

	return 0;
#else
	rte_cuda_gdrc_log(ERR,
			"GDRCopy headers not provided at DPDK building time. Can't CPU map GPU memory.");
	return -ENOTSUP;
#endif
}

int
gdrcopy_unpin(gdr_t gdrc_h, __rte_unused gdr_mh_t mh, void *d_addr, size_t size)
{
	if (gdrc_h == NULL)
		return -EINVAL;

#ifdef DRIVERS_GPU_CUDA_GDRCOPY_H
	/* Unmap the buffer from user space */
	if (sym_gdr_unmap(gdrc_h, mh, d_addr, size) != 0) {
		rte_cuda_gdrc_log(ERR, "GDRCopy unmap buffer error.");
		return -1;
	}
	/* Unpin the device buffer */
	if (sym_gdr_unpin_buffer(gdrc_h, mh) != 0) {
		rte_cuda_gdrc_log(ERR, "GDRCopy unpin buffer error.");
		return -1;
	}
#endif

	return 0;
}

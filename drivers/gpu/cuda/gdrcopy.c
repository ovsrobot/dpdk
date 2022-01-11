/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#include "gdrcopy.h"

static void *gdrclib;

static gdr_t (*sym_gdr_open)(void);
static int (*sym_gdr_close)(gdr_t g);
static int (*sym_gdr_pin_buffer)(gdr_t g, unsigned long addr, size_t size, uint64_t p2p_token, uint32_t va_space, gdr_mh_t *handle);
static int (*sym_gdr_unpin_buffer)(gdr_t g, gdr_mh_t handle);
static int (*sym_gdr_map)(gdr_t g, gdr_mh_t handle, void **va, size_t size);
static int (*sym_gdr_unmap)(gdr_t g, gdr_mh_t handle, void *va, size_t size);

int
gdrcopy_loader(void)
{
	char gdrcopy_path[1024];

	if (getenv("GDRCOPY_PATH_L") == NULL)
		snprintf(gdrcopy_path, 1024, "%s", "libgdrapi.so");
	else
		snprintf(gdrcopy_path, 1024, "%s%s", getenv("GDRCOPY_PATH_L"), "libgdrapi.so");

	gdrclib = dlopen(gdrcopy_path, RTLD_LAZY);
	if (gdrclib == NULL) {
		fprintf(stderr, "Failed to find GDRCopy library in %s (GDRCOPY_PATH_L=%s)\n",
				gdrcopy_path, getenv("GDRCOPY_PATH_L"));
		return -1;
	}

	sym_gdr_open = dlsym(gdrclib, "gdr_open");
	if (sym_gdr_open == NULL) {
		fprintf(stderr, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_close = dlsym(gdrclib, "gdr_close");
	if (sym_gdr_close == NULL) {
		fprintf(stderr, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_pin_buffer = dlsym(gdrclib, "gdr_pin_buffer");
	if (sym_gdr_pin_buffer == NULL) {
		fprintf(stderr, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_unpin_buffer = dlsym(gdrclib, "gdr_unpin_buffer");
	if (sym_gdr_unpin_buffer == NULL) {
		fprintf(stderr, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_map = dlsym(gdrclib, "gdr_map");
	if (sym_gdr_map == NULL) {
		fprintf(stderr, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	sym_gdr_unmap = dlsym(gdrclib, "gdr_unmap");
	if (sym_gdr_unmap == NULL) {
		fprintf(stderr, "Failed to load GDRCopy symbols\n");
		return -1;
	}

	return 0;
}

int
gdrcopy_open(gdr_t *g)
{
#ifdef DRIVERS_GPU_CUDA_GDRCOPY_H
	gdr_t g_;

	g_ = sym_gdr_open();
	if (!g_)
		return -1;

	*g = g_;
#else
	*g = NULL;
#endif
	return 0;
}

int
gdrcopy_close(__rte_unused gdr_t *g)
{
#ifdef DRIVERS_GPU_CUDA_GDRCOPY_H
	sym_gdr_close(*g);
#endif
	return 0;
}

int
gdrcopy_pin(gdr_t g, __rte_unused gdr_mh_t *mh, uint64_t d_addr, size_t size, void **h_addr)
{
	if (g == NULL)
		return -ENOTSUP;

#ifdef DRIVERS_GPU_CUDA_GDRCOPY_H
	/* Pin the device buffer */
	if (sym_gdr_pin_buffer(g, d_addr, size, 0, 0, mh) != 0) {
		fprintf(stderr, "sym_gdr_pin_buffer\n");
		return -1;
	}

	/* Map the buffer to user space */
	if (sym_gdr_map(g, *mh, h_addr, size) != 0) {
		fprintf(stderr, "sym_gdr_map\n");
		sym_gdr_unpin_buffer(g, *mh);
		return -1;
	}
#endif
	return 0;
}

int
gdrcopy_unpin(gdr_t g, __rte_unused gdr_mh_t mh, void *d_addr, size_t size)
{
	if (g == NULL)
		return -ENOTSUP;

#ifdef DRIVERS_GPU_CUDA_GDRCOPY_H
	/* Unmap the buffer from user space */
	if (sym_gdr_unmap(g, mh, d_addr, size) != 0)
		fprintf(stderr, "sym_gdr_unmap\n");

	/* Pin the device buffer */
	if (sym_gdr_unpin_buffer(g, mh) != 0) {
		fprintf(stderr, "sym_gdr_pin_buffer\n");
		return -11;
	}
#endif
	return 0;
}

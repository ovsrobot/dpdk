/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "hw_mod_backend.h"

#include <stdlib.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const struct {
	const char *name;
	int (*allocate)(struct flow_api_backend_s *be);
	void (*free)(struct flow_api_backend_s *be);
	int (*reset)(struct flow_api_backend_s *be);
	bool (*present)(struct flow_api_backend_s *be);
} module[] = {
	{ "CAT", hw_mod_cat_alloc, hw_mod_cat_free, hw_mod_cat_reset, hw_mod_cat_present },
};
#define MOD_COUNT (ARRAY_SIZE(module))

void *callocate_mod(struct common_func_s *mod, int sets, ...)
{
#define MAX_SETS 38
	void *base = NULL;
	void **plist[MAX_SETS];
	int len[MAX_SETS];
	int offs[MAX_SETS];
	unsigned int total_bytes = 0;
	int cnt, elem_size;

	assert(sets <= MAX_SETS);
	assert(sets > 0);

	va_list args;
	va_start(args, sets);

	for (int i = 0; i < sets; i++) {
		plist[i] = va_arg(args, void *);
		cnt = va_arg(args, int);
		elem_size = va_arg(args, int);
		offs[i] = EXTRA_INDEXES * elem_size;
		len[i] = offs[i] + cnt * elem_size;
		total_bytes += len[i];
	}

	if (total_bytes > 0) {
		base = calloc(1, total_bytes);

		if (base) {
			char *p_b = (char *)base;

			for (int i = 0; i < sets; i++) {
				*plist[i] = (void *)((char *)p_b + offs[i]);
				p_b += len[i];
			}

		} else {
			NT_LOG(ERR, FILTER, "ERROR: module memory allocation failed\n");
		}

	} else {
		NT_LOG(ERR, FILTER, "ERROR: module request to allocate 0 bytes of memory\n");
	}

	va_end(args);

	mod->base = base;
	mod->alloced_size = total_bytes;

	return base;
}

void zero_module_cache(struct common_func_s *mod)
{
	memset(mod->base, 0, mod->alloced_size);
}

int flow_api_backend_init(struct flow_api_backend_s *dev,
	const struct flow_api_backend_ops *iface,
	void *be_dev)
{
	assert(dev);
	dev->iface = iface;
	dev->be_dev = be_dev;
	dev->num_phy_ports = iface->get_nb_phy_port(be_dev);
	dev->num_rx_ports = iface->get_nb_rx_port(be_dev);
	dev->max_categories = iface->get_nb_categories(be_dev);
	dev->max_queues = iface->get_nb_queues(be_dev);

	NT_LOG(DBG,
		FILTER,
		"*************** FLOW REGISTER MODULES AND INITIALIZE - SET ALL TO DEFAULT *****************\n");

	/*
	 * Create Cache and SW, version independent, NIC module representation
	 */
	for (unsigned int mod = 0; mod < MOD_COUNT; mod++) {
		if (!module[mod].present(dev))
			continue;

		if (module[mod].allocate(dev) == 0 && module[mod].reset(dev) == 0) {
			/* OK */
			continue;
		}

		NT_LOG(ERR,
			FILTER,
			"ERROR: Initialization of NIC module failed : [ %s ]\n",
			module[mod].name);
		flow_api_backend_done(dev);
		NT_LOG(ERR,
			FILTER,
			"*************** Failed to create Binary Flow API *******************\n");
		NT_LOG(ERR,
			FILTER,
			"******** ERROR ERROR: Binary Flow API will not be available ********\n");
		NT_LOG(ERR,
			FILTER,
			"********************************************************************\n");
		return -1;
	}

	return 0;
}

int flow_api_backend_done(struct flow_api_backend_s *dev)
{
	for (unsigned int mod = 0; mod < MOD_COUNT; mod++)
		module[mod].free(dev);

	return 0;
}

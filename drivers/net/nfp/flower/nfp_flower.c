/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#include <rte_common.h>
#include <ethdev_driver.h>
#include <rte_service_component.h>
#include <rte_malloc.h>
#include <ethdev_pci.h>
#include <ethdev_driver.h>

#include "../nfp_common.h"
#include "../nfp_logs.h"
#include "../nfp_ctrl.h"
#include "../nfp_cpp_bridge.h"
#include "nfp_flower.h"

static struct rte_service_spec flower_services[NFP_FLOWER_SERVICE_MAX] = {
};

static int
nfp_flower_enable_services(struct nfp_app_flower *app_flower)
{
	int i;
	int ret = 0;

	for (i = 0; i < NFP_FLOWER_SERVICE_MAX; i++) {
		/* Pass a pointer to the flower app to the service */
		flower_services[i].callback_userdata = (void *)app_flower;

		/* Register the flower services */
		ret = rte_service_component_register(&flower_services[i],
				&app_flower->flower_services_ids[i]);
		if (ret) {
			PMD_INIT_LOG(WARNING,
				"Could not register Flower PF vNIC service");
			break;
		}

		PMD_INIT_LOG(INFO, "Flower PF vNIC service registered");

		/* Map them to available service cores*/
		ret = nfp_map_service(app_flower->flower_services_ids[i]);
		if (ret)
			break;
	}

	return ret;
}

int
nfp_init_app_flower(struct nfp_pf_dev *pf_dev)
{
	int ret;
	unsigned int numa_node;
	struct nfp_net_hw *pf_hw;
	struct nfp_app_flower *app_flower;

	numa_node = rte_socket_id();

	/* Allocate memory for the Flower app */
	app_flower = rte_zmalloc_socket("nfp_app_flower", sizeof(*app_flower),
			RTE_CACHE_LINE_SIZE, numa_node);
	if (app_flower == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	pf_dev->app_priv = app_flower;

	/* Allocate memory for the PF AND ctrl vNIC here (hence the * 2) */
	pf_hw = rte_zmalloc_socket("nfp_pf_vnic", 2 * sizeof(struct nfp_net_adapter),
			RTE_CACHE_LINE_SIZE, numa_node);
	if (pf_hw == NULL) {
		ret = -ENOMEM;
		goto app_cleanup;
	}

	/* Start up flower services */
	if (nfp_flower_enable_services(app_flower)) {
		ret = -ESRCH;
		goto vnic_cleanup;
	}

	return 0;

vnic_cleanup:
	rte_free(pf_hw);
app_cleanup:
	rte_free(app_flower);
done:
	return ret;
}

int
nfp_secondary_init_app_flower(__rte_unused struct nfp_cpp *cpp)
{
	PMD_INIT_LOG(ERR, "Flower firmware not supported");
	return -ENOTSUP;
}

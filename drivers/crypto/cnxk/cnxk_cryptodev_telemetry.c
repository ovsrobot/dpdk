/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_cryptodev.h>
#include <rte_telemetry.h>
#include <cryptodev_pmd.h>

#include <cnxk_telemetry.h>
#include <roc_api.h>

#include "cnxk_cryptodev.h"

#define CRYPTO_CAPS_SZ													\
	(RTE_ALIGN_CEIL(sizeof(struct rte_cryptodev_capabilities),			\
					sizeof(uint64_t)) /									\
	 sizeof(uint64_t))

#define SEC_CAPS_SZ														\
	(RTE_ALIGN_CEIL(sizeof(struct rte_security_capability),				\
					sizeof(uint64_t)) /									\
	 sizeof(uint64_t))

static int
crypto_caps_array(struct rte_tel_data *d,
		  struct rte_cryptodev_capabilities *dev_caps,
		  size_t dev_caps_n)
{
	union caps_u {
		struct rte_cryptodev_capabilities dev_caps;
		uint64_t val[CRYPTO_CAPS_SZ];
	} caps;
	unsigned int i, j, n = 0;

	rte_tel_data_start_array(d, RTE_TEL_U64_VAL);

	for (i = 0; i < dev_caps_n; i++) {
		if (dev_caps[i].op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			break;

		memset(&caps, 0, sizeof(caps));
		rte_memcpy(&caps.dev_caps, &dev_caps[i], sizeof(dev_caps[0]));
		for (j = 0; j < CRYPTO_CAPS_SZ; j++)
			rte_tel_data_add_array_u64(d, caps.val[j]);
		++n;
	}

	return n;
}

static int
sec_caps_array(struct rte_tel_data *d, struct rte_security_capability *dev_caps,
	       size_t dev_caps_n)
{
	union caps_u {
		struct rte_security_capability dev_caps;
		uint64_t val[SEC_CAPS_SZ];
	} caps;
	unsigned int i, j, n = 0;

	rte_tel_data_start_array(d, RTE_TEL_U64_VAL);

	for (i = 0; i < dev_caps_n; i++) {
		memset(&caps, 0, sizeof(caps));
		rte_memcpy(&caps.dev_caps, &dev_caps[i], sizeof(dev_caps[0]));
		for (j = 0; j < SEC_CAPS_SZ; j++)
			rte_tel_data_add_array_u64(d, caps.val[j]);
		++n;
	}

	return n;
}

static int
cryptodev_tel_handle_caps(const char *cmd __rte_unused, const char *params,
			  struct rte_tel_data *d)
{
	struct rte_tel_data *sec_crypto_caps, *sec_caps;
	int sec_crypto_caps_n, sec_caps_n;
	struct rte_cryptodev *dev;
	struct cnxk_cpt_vf *vf;
	int dev_id;

	if (params == NULL || strlen(params) == 0 || !isdigit(*params))
		return -EINVAL;

	dev_id = strtol(params, NULL, 10);
	if (!rte_cryptodev_is_valid_dev(dev_id))
		return -EINVAL;

	dev = rte_cryptodev_pmd_get_dev(dev_id);
	if (!dev) {
		plt_err("No cryptodev for id %d available", dev_id);
		return -EINVAL;
	}

	vf = dev->data->dev_private;
	rte_tel_data_start_dict(d);

	/* Security Crypto capabilities */
	sec_crypto_caps = rte_tel_data_alloc();
	sec_crypto_caps_n = crypto_caps_array(
		sec_crypto_caps, vf->sec_crypto_caps, CNXK_SEC_CRYPTO_MAX_CAPS);
	rte_tel_data_add_dict_container(d, "sec_crypto_caps", sec_crypto_caps,
					0);
	rte_tel_data_add_dict_int(d, "sec_crypto_caps_n", sec_crypto_caps_n);

	/* Security capabilities */
	sec_caps = rte_tel_data_alloc();
	sec_caps_n = sec_caps_array(sec_caps, vf->sec_caps, CNXK_SEC_MAX_CAPS);
	rte_tel_data_add_dict_container(d, "sec_caps", sec_caps, 0);
	rte_tel_data_add_dict_int(d, "sec_caps_n", sec_caps_n);

	return 0;
}

RTE_INIT(cnxk_cryptodev_init_telemetry)
{
	rte_telemetry_register_cmd(
		"/cnxk/cryptodev/caps", cryptodev_tel_handle_caps,
		"Returns cryptodev capabilities. Parameters: int dev_id");
}

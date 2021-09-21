/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_telemetry.h>

#include <roc_api.h>

#include "cnxk_cryptodev.h"
#include "cnxk_telemetry.h"

#define CRYPTO_CAPS_SZ                                                         \
	(RTE_ALIGN_CEIL(sizeof(struct rte_cryptodev_capabilities),             \
			sizeof(uint64_t)) /                                    \
	 sizeof(uint64_t))

#define SEC_CAPS_SZ                                                            \
	(RTE_ALIGN_CEIL(sizeof(struct rte_security_capability),                \
			sizeof(uint64_t)) /                                    \
	 sizeof(uint64_t))

static int
cryptodev_tel_handle_list(const char *cmd __rte_unused,
			  const char *params __rte_unused,
			  struct rte_tel_data *d)
{
	struct rte_cryptodev *cryptodev;
	unsigned int i;

	rte_tel_data_start_array(d, RTE_TEL_STRING_VAL);

	for (i = 0; i < RTE_CRYPTO_MAX_DEVS; i++) {
		cryptodev = rte_cryptodev_pmd_get_dev(i);
		if (cryptodev->attached != RTE_CRYPTODEV_ATTACHED)
			continue;

		rte_tel_data_add_array_string(d, cryptodev->data->name);
	}

	return 0;
}

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
cryptodev_tel_handle_info(const char *cmd __rte_unused, const char *params,
			  struct rte_tel_data *d)
{
	struct rte_tel_data *crypto_caps, *sec_crypto_caps, *sec_caps;
	int crypto_caps_n, sec_crypto_caps_n, sec_caps_n;
	char name[RTE_CRYPTODEV_NAME_MAX_LEN];
	struct rte_cryptodev *dev;
	struct cnxk_cpt_vf *vf;

	if (params == NULL || strlen(params) == 0 || !isdigit(*params))
		return -1;

	rte_strlcpy(name, params, RTE_CRYPTODEV_NAME_LEN);
	dev = rte_cryptodev_pmd_get_named_dev(name);
	if (!dev) {
		plt_err("No cryptodev of name %s available", name);
		return -1;
	}

	vf = dev->data->dev_private;

	rte_tel_data_start_dict(d);
	CNXK_TEL_DICT_INT(d, dev->data, dev_id);
	CNXK_TEL_DICT_INT(d, dev->data, socket_id);
	CNXK_TEL_DICT_INT(d, dev->data, dev_started);

	/* Crypto capabilities */
	crypto_caps = rte_tel_data_alloc();
	crypto_caps_n = crypto_caps_array(crypto_caps, vf->crypto_caps,
					  CNXK_CPT_MAX_CAPS);
	rte_tel_data_add_dict_container(d, "crypto_caps", crypto_caps, 0);
	rte_tel_data_add_dict_int(d, "crypto_caps_n", crypto_caps_n);

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
		"/cnxk/cryptodev/list", cryptodev_tel_handle_list,
		"Returns list of available cryptodev. Takes no parameters");
	rte_telemetry_register_cmd(
		"/cnxk/cryptodev/info", cryptodev_tel_handle_info,
		"Returns cryptodev info. Parameters: pci id");
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2021 NXP
 */

#include <string.h>

#include <rte_common.h>
#include <rte_bus_vdev.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_kvargs.h>

#include <rte_bbdev.h>
#include <rte_bbdev_pmd.h>

#include <bbdev_la12xx_pmd_logs.h>
#include <bbdev_la12xx_ipc.h>
#include <bbdev_la12xx.h>

#define DRIVER_NAME baseband_la12xx

RTE_LOG_REGISTER(bbdev_la12xx_logtype, pmd.bb.la12xx, NOTICE);

/*  Initialisation params structure that can be used by LA12xx BBDEV driver */
struct bbdev_la12xx_params {
	uint8_t queues_num; /*< LA12xx BBDEV queues number */
	int8_t modem_id; /*< LA12xx modem instance id */
};

#define BBDEV_LA12XX_MAX_NB_QUEUES_ARG  "max_nb_queues"
#define BBDEV_LA12XX_VDEV_MODEM_ID_ARG	"modem"
#define LA12XX_MAX_MODEM 4

static const char * const bbdev_la12xx_valid_params[] = {
	BBDEV_LA12XX_MAX_NB_QUEUES_ARG,
	BBDEV_LA12XX_VDEV_MODEM_ID_ARG,
};

static inline int
parse_u16_arg(const char *key, const char *value, void *extra_args)
{
	uint16_t *u16 = extra_args;

	unsigned int long result;
	if ((value == NULL) || (extra_args == NULL))
		return -EINVAL;
	errno = 0;
	result = strtoul(value, NULL, 0);
	if ((result >= (1 << 16)) || (errno != 0)) {
		BBDEV_LA12XX_PMD_ERR("Invalid value %lu for %s", result, key);
		return -ERANGE;
	}
	*u16 = (uint16_t)result;
	return 0;
}

/* Parse integer from integer argument */
static int
parse_integer_arg(const char *key __rte_unused,
		const char *value, void *extra_args)
{
	int i;
	char *end;

	errno = 0;

	i = strtol(value, &end, 10);
	if (*end != 0 || errno != 0 || i < 0 || i > LA12XX_MAX_MODEM) {
		BBDEV_LA12XX_PMD_ERR("Supported Port IDS are 0 to %d",
			LA12XX_MAX_MODEM - 1);
		return -EINVAL;
	}

	*((uint32_t *)extra_args) = i;

	return 0;
}

/* Parse parameters used to create device */
static int
parse_bbdev_la12xx_params(struct bbdev_la12xx_params *params,
		const char *input_args)
{
	struct rte_kvargs *kvlist = NULL;
	int ret = 0;

	if (params == NULL)
		return -EINVAL;
	if (input_args) {
		kvlist = rte_kvargs_parse(input_args,
				bbdev_la12xx_valid_params);
		if (kvlist == NULL)
			return -EFAULT;

		ret = rte_kvargs_process(kvlist, bbdev_la12xx_valid_params[0],
					&parse_u16_arg, &params->queues_num);
		if (ret < 0)
			goto exit;

		ret = rte_kvargs_process(kvlist,
					bbdev_la12xx_valid_params[1],
					&parse_integer_arg,
					&params->modem_id);

		if (params->modem_id >= LA12XX_MAX_MODEM) {
			BBDEV_LA12XX_PMD_ERR("Invalid modem id, must be < %u",
					LA12XX_MAX_MODEM);
			goto exit;
		}
	}

exit:
	if (kvlist)
		rte_kvargs_free(kvlist);
	return ret;
}

/* Create device */
static int
la12xx_bbdev_create(struct rte_vdev_device *vdev,
		struct bbdev_la12xx_params *init_params)
{
	struct rte_bbdev *bbdev;
	const char *name = rte_vdev_device_name(vdev);
	struct bbdev_la12xx_private *priv;

	PMD_INIT_FUNC_TRACE();

	bbdev = rte_bbdev_allocate(name);
	if (bbdev == NULL)
		return -ENODEV;

	bbdev->data->dev_private = rte_zmalloc(name,
			sizeof(struct bbdev_la12xx_private),
			RTE_CACHE_LINE_SIZE);
	if (bbdev->data->dev_private == NULL) {
		rte_bbdev_release(bbdev);
		return -ENOMEM;
	}

	priv = bbdev->data->dev_private;
	priv->modem_id = init_params->modem_id;
	/* if modem id is not configured */
	if (priv->modem_id == -1)
		priv->modem_id = bbdev->data->dev_id;

	/* Reset Global variables */
	priv->num_ldpc_enc_queues = 0;
	priv->num_ldpc_dec_queues = 0;
	priv->num_valid_queues = 0;
	priv->max_nb_queues = init_params->queues_num;

	BBDEV_LA12XX_PMD_INFO("Setting Up %s: DevId=%d, ModemId=%d",
				name, bbdev->data->dev_id, priv->modem_id);
	bbdev->dev_ops = NULL;
	bbdev->device = &vdev->device;
	bbdev->data->socket_id = 0;
	bbdev->intr_handle = NULL;

	/* register rx/tx burst functions for data path */
	bbdev->dequeue_enc_ops = NULL;
	bbdev->dequeue_dec_ops = NULL;
	bbdev->enqueue_enc_ops = NULL;
	bbdev->enqueue_dec_ops = NULL;

	return 0;
}

/* Initialise device */
static int
la12xx_bbdev_probe(struct rte_vdev_device *vdev)
{
	struct bbdev_la12xx_params init_params = {
		RTE_BBDEV_DEFAULT_MAX_NB_QUEUES, -1,
	};
	const char *name;
	const char *input_args;

	PMD_INIT_FUNC_TRACE();

	if (vdev == NULL)
		return -EINVAL;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	input_args = rte_vdev_device_args(vdev);
	parse_bbdev_la12xx_params(&init_params, input_args);

	return la12xx_bbdev_create(vdev, &init_params);
}

/* Uninitialise device */
static int
la12xx_bbdev_remove(struct rte_vdev_device *vdev)
{
	struct rte_bbdev *bbdev;
	const char *name;

	PMD_INIT_FUNC_TRACE();

	if (vdev == NULL)
		return -EINVAL;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	bbdev = rte_bbdev_get_named_dev(name);
	if (bbdev == NULL)
		return -EINVAL;

	rte_free(bbdev->data->dev_private);

	return rte_bbdev_release(bbdev);
}

static struct rte_vdev_driver bbdev_la12xx_pmd_drv = {
	.probe = la12xx_bbdev_probe,
	.remove = la12xx_bbdev_remove
};

RTE_PMD_REGISTER_VDEV(DRIVER_NAME, bbdev_la12xx_pmd_drv);
RTE_PMD_REGISTER_PARAM_STRING(DRIVER_NAME,
	BBDEV_LA12XX_MAX_NB_QUEUES_ARG"=<int>"
	BBDEV_LA12XX_VDEV_MODEM_ID_ARG "=<int> ");

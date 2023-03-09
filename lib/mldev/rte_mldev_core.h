/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#ifndef _RTE_MLDEV_INTERNAL_H_
#define _RTE_MLDEV_INTERNAL_H_

/**
 * @file
 *
 * MLDEV internal header
 *
 * This file contains MLDEV private data structures and macros.
 *
 * @note
 * These APIs are for MLDEV PMDs and library only.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <dev_driver.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_mldev.h>

/* Device state */
#define ML_DEV_DETACHED (0)
#define ML_DEV_ATTACHED (1)

struct rte_ml_dev;

/**
 * Definitions of all functions exported by a driver through the generic structure of type
 * *ml_dev_ops* supplied in the *rte_ml_dev* structure associated with a device.
 */

/**
 * @internal
 *
 * Function used to get device information.
 *
 * @param dev
 *	ML device pointer.
 * @param dev_info
 *	Pointer to info structure.
 *
 * @return
 *	- 0 on success.
 *	- < 0, error code on failure.
 */
typedef int (*mldev_info_get_t)(struct rte_ml_dev *dev, struct rte_ml_dev_info *dev_info);

/**
 * @internal
 *
 * Function used to configure device.
 *
 * @param dev
 *	ML device pointer.
 * @param config
 *	ML device configurations.
 *
 * @return
 *	- 0 on success
 *	- < 0, error code on failure.
 */
typedef int (*mldev_configure_t)(struct rte_ml_dev *dev, const struct rte_ml_dev_config *config);

/**
 * @internal
 *
 * Function used to close a configured device.
 *
 * @param dev
 *	ML device pointer.
 *
 * @return
 *	- 0 on success.
 *	- -EAGAIN if can't close as device is busy.
 *	- < 0, error code on failure, other than busy.
 */
typedef int (*mldev_close_t)(struct rte_ml_dev *dev);

/**
 * @internal
 *
 * Function used to start a configured device.
 *
 * @param dev
 *	ML device pointer.
 *
 * @return
 *	- 0 on success.
 *	- < 0, error code on failure.
 */
typedef int (*mldev_start_t)(struct rte_ml_dev *dev);

/**
 * @internal
 *
 * Function used to stop a configured device.
 *
 * @param dev
 *	ML device pointer.
 *
 * @return
 *	- 0 on success.
 *	- < 0, error code on failure.
 */
typedef int (*mldev_stop_t)(struct rte_ml_dev *dev);

/**
 * @internal
 *
 * Setup a queue pair for a device.
 *
 * @param dev
 *	ML device pointer.
 * @param queue_pair_id
 *	Queue pair index.
 * @param queue_pair_conf
 *	Queue pair configuration structure.
 * @param socket_id
 *	Socket index.
 *
 * @return
 *	- 0 on success.
 *	- < 0, error on failure.
 */
typedef int (*mldev_queue_pair_setup_t)(struct rte_ml_dev *dev, uint16_t queue_pair_id,
					const struct rte_ml_dev_qp_conf *queue_pair_conf,
					int socket_id);

/**
 * @internal
 *
 * Release memory resources allocated by given queue pair.
 *
 * @param dev
 *	ML device pointer.
 * @param queue_pair_id
 *	Queue pair index.
 *
 * @return
 *	- 0 on success.
 *	- -EAGAIN, if can't close as device is busy.
 */
typedef int (*mldev_queue_pair_release_t)(struct rte_ml_dev *dev, uint16_t queue_pair_id);

/**
 * @internal
 *
 * Function used to load an ML model.
 *
 * @param dev
 *	ML device pointer.
 * @param params
 *	Model load params.
 * @param model_id
 *	Model ID returned by the library.
 *
 * @return
 *	- 0 on success.
 *	- < 0, error on failure.
 */
typedef int (*mldev_model_load_t)(struct rte_ml_dev *dev, struct rte_ml_model_params *params,
				  uint16_t *model_id);

/**
 * @internal
 *
 * Function used to unload an ML model.
 *
 * @param dev
 *	ML device pointer.
 * @param model_id
 *	Model ID to use.
 *
 * @return
 *	- 0 on success.
 *	- < 0, error on failure.
 */
typedef int (*mldev_model_unload_t)(struct rte_ml_dev *dev, uint16_t model_id);

/**
 * @internal
 *
 * Function used to start an ML model.
 *
 * @param dev
 *	ML device pointer.
 * @param model_id
 *	Model ID to use.
 *
 * @return
 *	- 0 on success.
 *	- <0, error on failure.
 */
typedef int (*mldev_model_start_t)(struct rte_ml_dev *dev, uint16_t model_id);

/**
 * @internal
 *
 * Function used to stop an ML model.
 *
 * @param dev
 *	ML device pointer.
 * @param model_id
 *	Model ID to use.
 *
 * @return
 *	- 0 on success.
 *	- <0, error on failure.
 */
typedef int (*mldev_model_stop_t)(struct rte_ml_dev *dev, uint16_t model_id);

/**
 * @internal
 *
 * Get info about a model.
 *
 * @param dev
 *	ML device pointer.
 * @param model_id
 *	Model ID to use.
 * @param model_info
 *	Pointer to model info structure.
 *
 * @return
 *	- 0 on success.
 *	- <0, error on failure.
 */
typedef int (*mldev_model_info_get_t)(struct rte_ml_dev *dev, uint16_t model_id,
				      struct rte_ml_model_info *model_info);

/**
 * @internal
 *
 * Update model params.
 *
 * @param dev
 *	ML device pointer.
 * @param model_id
 *	Model ID to use.
 * @param buffer
 *	Pointer to model params.
 *
 * @return
 *	- 0 on success.
 *	- <0, error on failure.
 */
typedef int (*mldev_model_params_update_t)(struct rte_ml_dev *dev, uint16_t model_id, void *buffer);

/**
 * @internal
 *
 * ML device operations function pointer table.
 */
struct rte_ml_dev_ops {
	/** Get device information. */
	mldev_info_get_t dev_info_get;

	/** Configure device. */
	mldev_configure_t dev_configure;

	/** Close device. */
	mldev_close_t dev_close;

	/** Start device. */
	mldev_start_t dev_start;

	/** Stop device. */
	mldev_stop_t dev_stop;

	/** Set up a device queue pair. */
	mldev_queue_pair_setup_t dev_queue_pair_setup;

	/** Release a device queue pair. */
	mldev_queue_pair_release_t dev_queue_pair_release;

	/** Load an ML model. */
	mldev_model_load_t model_load;

	/** Unload an ML model. */
	mldev_model_unload_t model_unload;

	/** Start an ML model. */
	mldev_model_start_t model_start;

	/** Stop an ML model. */
	mldev_model_stop_t model_stop;

	/** Get model information. */
	mldev_model_info_get_t model_info_get;

	/** Update model params. */
	mldev_model_params_update_t model_params_update;
};

/**
 * @internal
 *
 * The data part, with no function pointers, associated with each device. This structure is safe to
 * place in shared memory to be common among different processes in a multi-process configuration.
 */
struct rte_ml_dev_data {
	/** Device ID for this instance. */
	int16_t dev_id;

	/** Socket ID where memory is allocated. */
	int16_t socket_id;

	/** Device state: STOPPED(0) / STARTED(1) */
	__extension__ uint8_t dev_started : 1;

	/** Number of device queue pairs. */
	uint16_t nb_queue_pairs;

	/** Number of ML models. */
	uint16_t nb_models;

	/** Array of pointers to queue pairs. */
	void **queue_pairs;

	/** Array of pointers to ML models. */
	void **models;

	/** PMD-specific private data. */
	void *dev_private;

	/** Unique identifier name. */
	char name[RTE_ML_STR_MAX];
};

/**
 * @internal
 *
 * The data structure associated with each ML device.
 */
struct rte_ml_dev {
	/** Pointer to device data. */
	struct rte_ml_dev_data *data;

	/** Functions exported by PMD. */
	struct rte_ml_dev_ops *dev_ops;

	/** Backing RTE device. */
	struct rte_device *device;

	/** Flag indicating the device is attached. */
	__extension__ uint8_t attached : 1;
} __rte_cache_aligned;

/**
 * @internal
 *
 * Global structure used for maintaining state of allocated ML devices.
 */
struct rte_ml_dev_global {
	/** Device information array. */
	struct rte_ml_dev *devs;

	/** Device private data array. */
	struct rte_ml_dev_data **data;

	/** Number of devices found. */
	uint8_t nb_devs;

	/** Maximum number of devices. */
	uint8_t max_devs;
};

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MLDEV_INTERNAL_H_ */

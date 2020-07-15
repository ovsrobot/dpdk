/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <rte_hexdump.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_cryptodev.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <signal.h>
#include <inttypes.h>

#include "mp_crypto_parser.h"
#include "mp_crypto.h"

static void sigkill_handler(int __rte_unused sig,
				siginfo_t *siginfo __rte_unused,
				void *context __rte_unused)
{
	mp_crypto_exit_flag = 1;
	printf("\nInterrupted, finalizing...");
}

static int
mp_app_init(int argc, char *argv[])
{
	/* init EAL */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(-1, "Invalid EAL arguments!\n");

	argc -= ret;
	argv += ret;

	struct sigaction sigkill_action;

	memset(&sigkill_action, 0, sizeof(sigkill_action));
	sigkill_action.sa_sigaction = sigkill_handler;
	sigkill_action.sa_flags = SA_SIGINFO;

	if (sigaction(SIGINT, &sigkill_action, NULL) < 0) {
		MP_APP_LOG_2(ERR, COL_RED, "Cannot init sigation");
		return -1;
	}

	if (get_options(argc, argv) != 0) {
		MP_APP_LOG_2(ERR, COL_RED,
			"Get cmdln options returned an error\n");
		return -1;
	};

	/* Set driver id for this process */
	mp_app_driver_id =
		rte_cryptodev_driver_id_get(mp_app_params->devtype_name);
	MP_APP_LOG(INFO, COL_BLUE, "- Setting driver %d for this process",
		mp_app_driver_id);

	/* Register IPC and allocate memzones */
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		MP_APP_LOG_2(INFO, COL_NORM, "- Starting PRIMARY process");
		if (rte_mp_action_register(MP_APP_IPC_NAME,
			mp_crypto_primary_handler)) {
			RTE_LOG(ERR, USER1, "Cannot register IPC callback");
			return -1;
		}
		/* Setup memzone for shared data */
		mp_app_process_mz = rte_memzone_reserve(
				MP_APP_PROC_SHARED_NAME,
				sizeof(struct mp_app_process_data), 0, 0);
		if (mp_app_process_mz == NULL) {
			RTE_LOG(ERR, USER1,
				"%s: cannot create memzone for process",
				__func__);
			return -1;
		}
		mp_shared_data = mp_app_process_mz->addr;
		rte_spinlock_init(&mp_shared_data->sessions.lock);
	} else {
		MP_APP_LOG_2(INFO, COL_NORM, "- Starting SECONDARY process");
		if (rte_mp_action_register(MP_APP_IPC_NAME,
			mp_crypto_secondary_handler)) {
			RTE_LOG(ERR, USER1, "Cannot register IPC callback");
			return -1;
		}
		/* Setup memzone for shared data */
		mp_app_process_mz =
			rte_memzone_lookup(MP_APP_PROC_SHARED_NAME);
		if (mp_app_process_mz == NULL) {
			MP_APP_LOG(ERR, COL_RED,
				"Cannot find memzone by name %s",
			MP_APP_PROC_SHARED_NAME);
			return -1;
		}
		mp_shared_data = mp_app_process_mz->addr;
	}

	mp_shared_data->proc_counter++;
	mp_shared_data->proc_counter_total++;
	MP_APP_LOG(INFO, COL_GREEN, "Number of processes = %d",
		mp_shared_data->proc_counter);

	return 0;
}

void mp_crypto_exit_app(void)
{
	const int timeout = 10;
	int counter = 0;
	struct rte_mp_msg icp_msg;

	memset(&icp_msg, 0, sizeof(MP_APP_IPC_NAME));
	mp_crypto_exit_flag = 1;
	if (mp_shared_data == NULL)
		return;

/*	rte_mempool_free(mp_crypto_op_pool);
 *	rte_mempool_free(mp_crypto_mbuf_pool);
 */
	rte_mempool_free(mp_crypto_session_mempool_local);
	rte_mempool_free(mp_crypto_priv_session_mp_local);

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		/* Inform of exit intention,
		 * wait until all processes finish
		 */

		memcpy(icp_msg.name, MP_APP_IPC_NAME, sizeof(MP_APP_IPC_NAME));
		memcpy(icp_msg.param, PRIMARY_PROC_EXIT,
			sizeof(PRIMARY_PROC_EXIT));
		icp_msg.len_param = sizeof(PRIMARY_PROC_EXIT);
		icp_msg.num_fds = 0;
		if (rte_mp_sendmsg(&icp_msg) < 0) {
			MP_APP_LOG_2(ERR, COL_RED,
			"Error when sending IPC to secondary processes");
			return;
		}
		while (mp_shared_data->proc_counter > 1 && counter++
				< timeout) {
			rte_delay_ms(1000);
			MP_APP_LOG(INFO, COL_NORM,
			"Waiting for %d out of %d seconds", counter, timeout);
		}
		if (counter < timeout) {
			MP_APP_LOG_2(INFO, COL_GREEN,
			"All secondary processes exited normally");
		} else {
			MP_APP_LOG_2(ERR, COL_RED,
			"One or more processes did not exit normally");
		}

		rte_mempool_free(mp_crypto_session_mempool);
		rte_mempool_free(mp_crypto_priv_session_mp);

		mp_shared_data->proc_counter = 0;
	} else {
		/* Inform primary of exiting */
		mp_shared_data->proc_counter--;
	}
}

int
mp_crypto_init_devs(void)
{
	uint8_t valid_devs[RTE_CRYPTO_MAX_DEVS];
	struct rte_cryptodev_config conf;
	struct rte_cryptodev_info info;
	int nb_devs = 0;
	int i;

	for (i = 0; i < RTE_CRYPTO_MAX_DEVS; i++)
		mp_app_devs[i].id = -1;

	if (mp_app_driver_id == -1) {
		MP_APP_LOG(ERR, COL_RED, "No driver of type %s registered",
				mp_app_params->devtype_name);
		return -1;
	}

	nb_devs = rte_cryptodev_devices_get(mp_app_params->devtype_name,
					valid_devs, RTE_CRYPTO_MAX_DEVS);

	if (nb_devs < 1) {
		MP_APP_LOG(ERR, COL_RED, "No %s devices found",
				mp_app_params->devtype_name);
		return -1;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		mp_shared_data->devices_number = nb_devs;
	} else {
		if (mp_shared_data->devices_number != nb_devs) {
			MP_APP_LOG(INFO, COL_RED,
			"- Number of devices probed by primary process differs with current process config, number of devices = %d, number on primary = %d",
					nb_devs,
					mp_shared_data->devices_number);
			return -1;
		}
	}

	for (i = 0; i < nb_devs ; i++) {
		rte_cryptodev_info_get(valid_devs[i], &info);
		if (info.feature_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) {
			mp_app_devs[mp_app_devs_cnt].id = valid_devs[i];
			mp_app_devs[mp_app_devs_cnt].probed = 1;
			mp_app_devs[mp_app_devs_cnt++].max_queue_pairs =
					info.max_nb_queue_pairs;

			/* Last one is as good as first one */
			mp_app_max_queues = info.max_nb_queue_pairs;
			if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
				strncpy(mp_shared_data->prim_dev_name[i].name,
					info.device->name,
					MP_APP_DEV_NAME_LEN);
			} else {
				if (strncmp(
					mp_shared_data->prim_dev_name[i].name,
						info.device->name,
						MP_APP_DEV_NAME_LEN)) {
					MP_APP_LOG(INFO, COL_RED,
					"Wrong device: %s, are BDF passed to primary process the same?",
						info.device->name);
					return -1;
				}
			}
		}
	}
	/* Pick one device to be used for session creation,
	 * only valid when all devices of the same type.
	 */
	mp_app_device_id = mp_app_devs[0].id;
	MP_APP_LOG(INFO, COL_GREEN,
			"Configure devices according to mask: 0x%"PRIu64,
			mp_app_params->dev_to_configure_mask);

	uint64_t dev_mask_id;
	int dev_id;

	for (dev_mask_id = 1, dev_id = 0; dev_id <= MP_APP_MAX_DEVS;
			dev_mask_id <<= 1, dev_id++) {
		if (dev_mask_id & mp_app_params->dev_to_configure_mask) {
			if (!mp_app_devs[dev_id].probed)
				continue;

			/* TODO check if already configured */

			conf.nb_queue_pairs = info.max_nb_queue_pairs;
			conf.socket_id = SOCKET_ID_ANY;
			conf.ff_disable = RTE_CRYPTODEV_FF_SECURITY;

			if (rte_cryptodev_configure(mp_app_devs[dev_id].id,
				&conf) != 0) {
				RTE_LOG(ERR, USER1,
					"Error when configuring device number %d",
						dev_id);
				return -1;
			}

			mp_app_devs[dev_id].configured = 1;
			MP_APP_LOG(INFO, COL_BLUE, "- Configure Device id %d",
					mp_app_devs[dev_id].id);
		}
	}
	return 0;
}

static int
steup_qps_main_loop(int dev_id, int qp_id)
{
	while (1) {
		/* This could be is_dev_configured */
		int ret  = rte_cryptodev_get_qp_status(
			mp_app_devs[dev_id].id, qp_id);
		if (ret == 1) {
			mp_app_devs[dev_id].queue_pair_flag[
				qp_id] = 0;
			MP_APP_LOG_2(WARNING, COL_YEL,
				"Queue was already configured by other process, skipping");
			return 1;
		} else if (ret < 0) {
			char c;

			mp_app_devs[dev_id].queue_pair_flag[
				qp_id] = 0;
			MP_APP_LOG_2(ERR, COL_RED,
				"Error setting queues, was this device configured?");
			printf(
				"\n - Press 'w' to wait until other process will configure it");
			printf("\n - Press 'x' to exit");
			int __rte_unused r = scanf("%s", &c);

			if (c == 'w') {
				int timeout = 3;
				int counter = 1;

				while (timeout <= counter) {
					rte_delay_ms(1000);
					MP_APP_LOG(INFO,
					COL_NORM,
					"Waiting for %d out of %d seconds",
					counter++, 3);
				}
			} else if (c == 'x')
				return -1;
		} else if (ret == 0)
			return 0;
	}

}

int
mp_crypto_setup_qps(void)
{
	int dev_id;
	int qp_id;
	int queue_count = 0;
	int last_qp_on_device = mp_app_max_queues;

	MP_APP_LOG_2(INFO, COL_NORM, "- Configuring queues:");
	for (dev_id = 0; dev_id < MP_APP_MAX_DEVS; dev_id++) {
		if (!mp_app_devs[dev_id].probed)
			continue;
		for (qp_id = 0; qp_id < mp_app_max_queues; qp_id++) {
			if (mp_app_devs[dev_id].queue_pair_flag[qp_id]
					!= QP_TO_CONFIGURE)
				continue;
			struct rte_cryptodev_qp_conf qp_conf;
			int cont = steup_qps_main_loop(dev_id, qp_id);

			/* Queue was already set, continue */
			if (cont == 1)
				continue;
			else if (cont == -1)
				return -1;
			qp_conf.nb_descriptors = MP_CRYPTO_QP_DESC_NUM;
			qp_conf.mp_session = NULL;
			qp_conf.mp_session_private = NULL;
			if (rte_cryptodev_queue_pair_setup(
					mp_app_devs[dev_id].id,
					qp_id, &qp_conf,
					rte_cryptodev_socket_id(
					mp_app_devs[dev_id].id))) {
				RTE_LOG(ERR, USER1,
					"Error when setting up queue pair %d on dev %d",
					qp_id, dev_id);
				return -1;
			}
			MP_APP_LOG(INFO, COL_BLUE, "Created qp %d on dev %d",
					qp_id, mp_app_devs[dev_id].id);
			mp_app_devs[dev_id].queue_pair_flag[qp_id] = 1;
			queue_count++;
		}
	}

	for (dev_id = 0; dev_id < MP_APP_MAX_DEVS; dev_id++) {
		if (!mp_app_devs[dev_id].probed)
			continue;
		for (qp_id = last_qp_on_device; qp_id < MP_APP_QUEUE_PAIRS_NUM;
			qp_id++) {
			if (mp_app_devs[dev_id].queue_pair_flag[qp_id]
					== QP_TO_CONFIGURE) {
				MP_APP_LOG(WARNING, COL_YEL,
				"Cannot create qp %d on dev %d, maximum allowed by this device = %d (%d queue pairs)",
				qp_id, mp_app_devs[dev_id].id,
				mp_app_max_queues - 1,
				mp_app_max_queues);
			}
		}
	}

	MP_APP_LOG(INFO, COL_GREEN, "- Configured %d queues.", queue_count);
	return 0;
}

int mp_crypto_setup_mpool(void)
{
	int i;
	char crypto_op_mpool_name[RTE_MEMZONE_NAMESIZE];
	char mbuf_pool_name[RTE_MEMZONE_NAMESIZE];
	char session_mpool_name_local[RTE_MEMZONE_NAMESIZE];
	char session_priv_name_local[RTE_MEMZONE_NAMESIZE];

	/* Op pool */
	int n = snprintf(crypto_op_mpool_name, sizeof(crypto_op_mpool_name),
				"%s_%hu", MP_APP_CRYPTO_OP_POOL_NAME,
					mp_shared_data->proc_counter_total);

	if (n >= (int)sizeof(crypto_op_mpool_name)) {
		MP_APP_LOG_2(ERR, COL_RED, "Failed to create mpool name");
		return -1;
	}

	/* mbuf pool */
	n = snprintf(mbuf_pool_name, sizeof(mbuf_pool_name),
				"%s_%hu", MP_APP_MBUFPOOL_NAME,
				mp_shared_data->proc_counter_total);

	if (n >= (int)sizeof(mbuf_pool_name)) {
		RTE_LOG(ERR, USER1, "Failed to create mbuf pool name");
		return -1;
	}

	/* Local session pool */
	n = snprintf(session_mpool_name_local,
			sizeof(session_mpool_name_local),
			"%s_%hu", MP_APP_SESSION_POOL_NAME_LOC,
			mp_shared_data->proc_counter_total);

	if (n >= (int)sizeof(session_mpool_name_local)) {
		MP_APP_LOG_2(ERR, COL_RED,
			"Failed to local session mpool name");
		return -1;
	}

	/* Local priv session pool */
	n = snprintf(session_priv_name_local, sizeof(session_priv_name_local),
				"%s_%hu", MP_APP_PRIV_SESSION_POOL_NAME_LOC,
				mp_shared_data->proc_counter_total);

	if (n >= (int)sizeof(session_priv_name_local)) {
		MP_APP_LOG_2(ERR, COL_RED,
		"Failed to local session private mpool name");
		return -1;
	}

	/* Op pool */
	mp_crypto_op_pool =
		rte_mempool_lookup(crypto_op_mpool_name);

	if (!mp_crypto_op_pool) {
		mp_crypto_op_pool = rte_crypto_op_pool_create(
			crypto_op_mpool_name,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC,
			MP_APP_NUM_MBUFS, MP_APP_MBUF_CACHE_SIZE,
			MP_APP_DEFAULT_NUM_XFORMS *
			sizeof(struct rte_crypto_sym_xform) +
			MP_APP_MAXIMUM_IV_LENGTH,
			rte_socket_id());
	}

	if (mp_crypto_op_pool == NULL) {
		MP_APP_LOG_2(ERR, COL_RED, "Error in mempool creation for ops");
		return -1;
	}

	/* Set session pools for this process */
	mp_crypto_session_mempool_local =
		rte_cryptodev_sym_session_pool_create(
		session_mpool_name_local, MAX_NUM_OF_SESSIONS,
		sizeof(struct rte_cryptodev_sym_session), 0, 0,
		SOCKET_ID_ANY);

	if (!mp_crypto_session_mempool_local) {
		MP_APP_LOG_2(ERR, COL_RED,
		"Failed to create local session mpool");
		return -1;
	}

	/* Set private session pool for this process */
	mp_crypto_priv_session_mp_local = rte_mempool_create(
			session_priv_name_local,
			MAX_NUM_OF_SESSIONS,
			rte_cryptodev_sym_get_private_session_size(
				mp_app_device_id),
			0, 0, NULL, NULL, NULL,
			NULL, SOCKET_ID_ANY,
			0);
	if (!mp_crypto_priv_session_mp_local) {
		MP_APP_LOG_2(ERR, COL_RED,
			"Failed to create local session priv mpool");
		return -1;
	}

	int dev_id = mp_app_devs[0].id;
	/* All devices use same driver so the same size of private data */
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		/* Set mempools for sessions */
		mp_crypto_session_mempool =
			rte_cryptodev_sym_session_pool_create(
			MP_APP_SESSION_POOL_NAME, MAX_NUM_OF_SESSIONS,
			sizeof(struct rte_cryptodev_sym_session), 0, 0,
			SOCKET_ID_ANY);

		if (!mp_crypto_session_mempool) {
			MP_APP_LOG_2(ERR, COL_RED,
				"Failed to create session mpool");
			return -1;
		}

		mp_crypto_priv_session_mp = rte_mempool_create(
			MP_APP_PRIV_SESSION_POOL_NAME,
			MAX_NUM_OF_SESSIONS,
			rte_cryptodev_sym_get_private_session_size(dev_id),
			0, 0, NULL, NULL, NULL,
			NULL, SOCKET_ID_ANY,
			0);
		if (!mp_crypto_priv_session_mp) {
			MP_APP_LOG_2(ERR, COL_RED,
			"Failed to create priv mpool");
			return -1;
		}
		/* Set mempools for ops */

	} else {
		mp_crypto_session_mempool =
			rte_mempool_lookup(MP_APP_SESSION_POOL_NAME);
		if (!mp_crypto_session_mempool) {
			MP_APP_LOG_2(ERR, COL_RED,
			"Failed to get sess mpool, was it allocated?");
			return -1;
		}
		mp_crypto_priv_session_mp =
			rte_mempool_lookup(MP_APP_PRIV_SESSION_POOL_NAME);
		if (!mp_crypto_session_mempool) {
			MP_APP_LOG_2(ERR, COL_RED,
			"Failed to get priv session mpool, was it allocated?");
			return -1;
		}
	}

	/* Mbuf pool */
	mp_crypto_mbuf_pool =
		rte_mempool_lookup(mbuf_pool_name);
	if (mp_crypto_mbuf_pool == NULL) {
		mp_crypto_mbuf_pool = rte_pktmbuf_pool_create(
				mbuf_pool_name,
				MP_APP_NUM_MBUFS, MP_APP_MBUF_CACHE_SIZE, 0,
				MP_APP_MBUF_SIZE,
				rte_socket_id());
	}
	if (mp_crypto_mbuf_pool == NULL) {
		MP_APP_LOG_2(ERR, COL_RED,
			"Error in pool creation for mbuf data");
		return -1;
	}

	/* Create ops and mbufs */
	for (i = 0; i < MP_CRYPTO_QP_DESC_NUM; i++)	{
		mp_crypto_mbufs[i] = rte_pktmbuf_alloc(mp_crypto_mbuf_pool);
		if (mp_crypto_mbufs[i] == NULL)	{
			MP_APP_LOG_2(ERR, COL_RED, "Error allocating mbufs");
			return -1;
		}
		memset(rte_pktmbuf_mtod(mp_crypto_mbufs[i], uint8_t *), 0,
			rte_pktmbuf_data_len(mp_crypto_mbufs[i]));
	}

	for (i = 0; i < MP_CRYPTO_QP_DESC_NUM; i++) {
		mp_crypto_ops[i] = rte_crypto_op_alloc(mp_crypto_op_pool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
		if (mp_crypto_ops[i] == NULL) {
			MP_APP_LOG_2(ERR, COL_RED,
				"Error allocating crypto op");
			return -1;
		}
		mp_crypto_ops[i]->sym->m_src = mp_crypto_mbufs[i];
	}

	return 0;
}

int main(int argc, char *argv[])
{

	int ret = 0;

	if (mp_app_init(argc, argv) < 0) {
		MP_APP_LOG_2(ERR, COL_RED, "Error when initializing");
		goto err;
	};

	if (mp_crypto_init_devs() < 0) {
		MP_APP_LOG_2(ERR, COL_RED, "Devices cannot be initialized");
		goto err;
	};

	if (mp_crypto_setup_qps() < 0) {
		MP_APP_LOG_2(ERR, COL_RED, "Setup qps returned an error");
		goto err;
	};

	ret = mp_crypto_setup_mpool();
	if (ret < 0) {
		MP_APP_LOG_2(ERR, COL_RED, "Cannot create mempools");
		goto err;
	}

	mp_crypto_exit_app();
	return 0;
err:
	mp_crypto_exit_app();

	return 1;
}

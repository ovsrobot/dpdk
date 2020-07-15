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
	int ret = rte_eal_init(argc, argv)
;
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
		mp_app_process_mz = rte_memzone_reserve(MP_APP_PROC_SHARED_NAME,
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

		mp_shared_data->proc_counter = 0;
	} else {
		/* Inform primary of exiting */
		mp_shared_data->proc_counter--;
	}
}

int main(int argc, char *argv[])
{
	if (mp_app_init(argc, argv) < 0) {
		MP_APP_LOG_2(ERR, COL_RED, "Error when initializing");
		goto err;
	};

	mp_crypto_exit_app();
	return 0;
err:
	mp_crypto_exit_app();

	return 1;
}

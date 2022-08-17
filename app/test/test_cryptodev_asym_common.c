/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#include <stdint.h>

#include "test_cryptodev_asym_common.h"
#include "test.h"
#include "test_cryptodev.h"

int ats_common_setup(struct crypto_testsuite_params_asym* ts)
{
	uint16_t qp_id;

	/* Reconfigure device to default parameters */
	ts->conf.socket_id = SOCKET_ID_ANY;

	TEST_ASSERT_SUCCESS(rte_cryptodev_configure(ts->valid_devs[0],
			&ts->conf),
			"Failed to configure cryptodev %u",
			ts->valid_devs[0]);

	for (qp_id = 0; qp_id < ts->conf.nb_queue_pairs ; qp_id++) {
		TEST_ASSERT_SUCCESS(rte_cryptodev_queue_pair_setup(
			ts->valid_devs[0], qp_id,
			&ts->qp_conf,
			rte_cryptodev_socket_id(ts->valid_devs[0])),
			"Failed to setup queue pair %u on cryptodev %u",
			qp_id, ts->valid_devs[0]);
	}

	rte_cryptodev_stats_reset(ts->valid_devs[0]);

	/* Start the device */
	TEST_ASSERT_SUCCESS(rte_cryptodev_start(ts->valid_devs[0]),
						"Failed to start cryptodev %u",
						ts->valid_devs[0]);

	return TEST_SUCCESS;
}

void ats_common_teardown(struct crypto_testsuite_params_asym* ts)
{
	struct rte_cryptodev_stats stats;

	rte_cryptodev_stats_get(ts->valid_devs[0], &stats);

	rte_cryptodev_stop(ts->valid_devs[0]);
}

void ats_err_msg_cap(void)
{
	RTE_LOG(INFO, USER1, "Device doesn't support MODEX. Test Skipped\n");
}

void ats_err_msg_op(char* msg, uint32_t len, uint32_t line)
{
	snprintf(msg, len,
		"line %u FAILED: %s", line,
		"Failed to allocate asymmetric crypto operation struct");
}

void ats_err_msg_mod_len(char* msg, uint32_t len, uint32_t line)
{
	snprintf(msg, len,
		"line %u FAILED: %s", line,
		"Invalid MODULUS length specified");
}

void ats_err_msg_inv_alg(char* msg, uint32_t len, uint32_t line)
{
	snprintf(msg, len,
		"line %u FAILED: %s", line,
		"Invalid ASYM algorithm specified");
}

void ats_err_msg_sess_create(char* msg, uint32_t len, uint32_t line)
{
	snprintf(msg, len,
		"line %u FAILED: %s", line,
		"Session creation failed");
}

void ats_err_msg_sess_init(char* msg, uint32_t len, uint32_t line)
{
	snprintf(msg, len,
		"line %u FAILED: %s", line,
		"unabled to config sym session");
}

void ats_err_msg_enque(char* msg, uint32_t len, uint32_t line)
{
	snprintf(msg, len,
		"line %u FAILED: %s", line,
		"Error sending packet for operation");
}

void ats_err_msg_burst(char* msg, uint32_t len, uint32_t line)
{
	snprintf(msg, len,
		"line %u FAILED: %s", line,
		"Error sending packet for operation");
}

void ats_err_msg_deq(char* msg, uint32_t len, uint32_t line)
{
	snprintf(msg, len,
		"line %u FAILED: %s", line,
		"Failed to process asym crypto op");
}

void ats_err_msg_ver(char* msg, uint32_t len, uint32_t line)
{
	snprintf(msg, len,
			"line %u FAILED: %s", line,
			"Verification failed ");
}

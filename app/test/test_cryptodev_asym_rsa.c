/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#include "test_cryptodev_asym_common.h"
#include "test_cryptodev_asym_rsa.h"
#include "test_cryptodev_asym_vectors.h"

#include "test.h"
#include "test_cryptodev.h"
#include "test_cryptodev_asym_types.h"
#include "test_cryptodev_asym_vectors.h"

#define ASYM_TEST_MSG_LEN 256
#define TEST_DATA_SIZE 4096

struct crypto_unittest_params {
	struct rte_cryptodev_asym_session *sess;
	struct rte_crypto_op *op;
};

static struct asym_test_rsa_vct *vct;
static int vct_nb;

extern struct crypto_testsuite_params_asym testsuite_params_asym;

int ats_rsa_setup(void)
{
	vct = atv_rsa(&vct_nb);

	int status = ats_common_setup(&testsuite_params_asym);

	return status;
}

void ats_rsa_teardown(void)
{
	atv_free(vct);

	ats_common_teardown(&testsuite_params_asym);
}

static int ats_case_rsa_op(struct crypto_testsuite_params_asym *ts_params,
		struct asym_test_rsa_vct *data_tc, char *test_msg, int sessionless,
		enum rte_crypto_asym_op_type op_type,
		enum rte_crypto_rsa_priv_key_type key_type)
{
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *op = NULL;
	struct rte_crypto_op *result_op = NULL;
	struct rte_crypto_asym_xform xform_tc;
	void *sess = NULL;
	struct rte_cryptodev_asym_capability_idx cap_idx;
	const struct rte_cryptodev_asymmetric_xform_capability *capability;
	uint8_t dev_id = ts_params->valid_devs[0];
	uint8_t *result = NULL;
	uint8_t *data_expected = NULL, *data_received = NULL;
	size_t data_size = 0;

	int ret, status = TEST_SUCCESS;

	xform_tc.next = NULL;
	xform_tc.xform_type = data_tc->xform_type;

	cap_idx.type = xform_tc.xform_type;
	capability = rte_cryptodev_asym_capability_get(dev_id, &cap_idx);

	if (capability == NULL) {
		ats_err_msg_cap();
		return TEST_SKIPPED;
	}

	/* Generate crypto op data structure */
	op = rte_crypto_op_alloc(ts_params->op_mpool,
			RTE_CRYPTO_OP_TYPE_ASYMMETRIC);

	if (!op) {
		ats_err_msg_op(test_msg, ASYM_TEST_MSG_LEN, __LINE__);
		status = TEST_FAILED;
		goto error_exit;
	}

	asym_op = op->asym;

	switch (xform_tc.xform_type) {
	case RTE_CRYPTO_ASYM_XFORM_RSA:
		result = rte_zmalloc(NULL, data_tc->n.len, 0);
		op->asym->rsa.op_type = op_type;
		xform_tc.rsa.e.data = data_tc->e.data;
		xform_tc.rsa.e.length = data_tc->e.len;
		xform_tc.rsa.n.data = data_tc->n.data;
		xform_tc.rsa.n.length = data_tc->n.len;

		if (key_type == RTE_RSA_KEY_TYPE_EXP) {
			xform_tc.rsa.d.data = data_tc->d.data;
			xform_tc.rsa.d.length = data_tc->d.len;
		} else {
			xform_tc.rsa.qt.p.data = data_tc->p.data;
			xform_tc.rsa.qt.p.length = data_tc->p.len;
			xform_tc.rsa.qt.q.data = data_tc->q.data;
			xform_tc.rsa.qt.q.length = data_tc->q.len;
			xform_tc.rsa.qt.dP.data = data_tc->dP.data;
			xform_tc.rsa.qt.dP.length = data_tc->dP.len;
			xform_tc.rsa.qt.dQ.data = data_tc->dQ.data;
			xform_tc.rsa.qt.dQ.length = data_tc->dQ.len;
			xform_tc.rsa.qt.qInv.data = data_tc->qInv.data;
			xform_tc.rsa.qt.qInv.length = data_tc->qInv.len;
		}

		xform_tc.rsa.key_type = key_type;
		op->asym->rsa.padding.type = data_tc->padding;

		if (op->asym->rsa.op_type == RTE_CRYPTO_ASYM_OP_ENCRYPT) {
			asym_op->rsa.message.data = data_tc->pt.data;
			asym_op->rsa.message.length = data_tc->pt.len;
			asym_op->rsa.cipher.data = result;
			asym_op->rsa.cipher.length = data_tc->n.len;
		} else if (op->asym->rsa.op_type == RTE_CRYPTO_ASYM_OP_DECRYPT) {
			asym_op->rsa.message.data = result;
			asym_op->rsa.message.length = 0;
			asym_op->rsa.cipher.data = data_tc->ct.data;
			asym_op->rsa.cipher.length = data_tc->ct.len;
		} else if (op->asym->rsa.op_type == RTE_CRYPTO_ASYM_OP_SIGN) {
			asym_op->rsa.sign.data = result;
			asym_op->rsa.sign.length = data_tc->n.len;
			asym_op->rsa.message.data = data_tc->digest.data;
			asym_op->rsa.message.length = data_tc->digest.len;
		} else if (op->asym->rsa.op_type == RTE_CRYPTO_ASYM_OP_VERIFY) {
			asym_op->rsa.cipher.data = result;
			asym_op->rsa.cipher.length = data_tc->n.len;
			asym_op->rsa.sign.data = data_tc->sign.data;
			asym_op->rsa.sign.length = data_tc->sign.len;
		}
		break;

	default:
		ats_err_msg_inv_alg(test_msg, ASYM_TEST_MSG_LEN, __LINE__);
		status = TEST_FAILED;
		goto error_exit;
	}

	if (!sessionless) {
		ret = rte_cryptodev_asym_session_create(dev_id, &xform_tc,
				ts_params->session_mpool, &sess);
		if (ret < 0) {
			ats_err_msg_sess_create(test_msg, ASYM_TEST_MSG_LEN, __LINE__);
			status = (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
			goto error_exit;
		}

		rte_crypto_op_attach_asym_session(op, sess);
	} else {
		asym_op->xform = &xform_tc;
		op->sess_type = RTE_CRYPTO_OP_SESSIONLESS;
	}
	RTE_LOG(DEBUG, USER1, "Process ASYM operation");

	/* Process crypto operation */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		ats_err_msg_enque(test_msg, ASYM_TEST_MSG_LEN, __LINE__);
		status = TEST_FAILED;
		goto error_exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		ats_err_msg_deq(test_msg, ASYM_TEST_MSG_LEN, __LINE__);
		status = TEST_FAILED;
		goto error_exit;
	}

	if (op->asym->rsa.op_type == RTE_CRYPTO_ASYM_OP_ENCRYPT) {
		data_size = xform_tc.rsa.n.length;
		data_received = result_op->asym->rsa.cipher.data;
		data_expected = data_tc->ct.data;
	} else if (op->asym->rsa.op_type == RTE_CRYPTO_ASYM_OP_DECRYPT) {
		data_size = xform_tc.rsa.n.length;
		data_expected = data_tc->pt.data;
		data_received = result_op->asym->rsa.message.data;
	} else if (op->asym->rsa.op_type == RTE_CRYPTO_ASYM_OP_SIGN) {
		data_size = xform_tc.rsa.n.length;
		data_expected = data_tc->sign.data;
		data_received = result_op->asym->rsa.sign.data;
	} else if (op->asym->rsa.op_type == RTE_CRYPTO_ASYM_OP_VERIFY) {
		data_size = xform_tc.rsa.n.length;
		data_expected = data_tc->digest.data;
		data_received = result_op->asym->rsa.cipher.data;
	}

	if ((memcmp(data_expected, data_received, data_size) != 0)
			|| (data_size == 0)) {
		ats_err_msg_ver(test_msg, ASYM_TEST_MSG_LEN, __LINE__);
		status = TEST_FAILED;
		goto error_exit;
	}

error_exit:
	if (sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, sess);

	if (op != NULL)
		rte_crypto_op_free(op);

	if (result != NULL)
		rte_free(result);

	return status;
}

int ats_rsa_run(void)
{
	int status = TEST_SUCCESS;
	int i, key_type;
	char test_msg[ASYM_TEST_MSG_LEN + 1];
	int sessionless = 0;
	struct crypto_testsuite_params_asym *ts_params = &testsuite_params_asym;
	uint8_t dev_id = ts_params->valid_devs[0];
	struct rte_cryptodev_info dev_info;

	rte_cryptodev_info_get(dev_id, &dev_info);
	if ((dev_info.feature_flags &
	RTE_CRYPTODEV_FF_ASYM_SESSIONLESS)) {
		sessionless = 1;
	}

	for (i = 0; i < vct_nb; i++) {

		printf("\n  %u) TestSubCase %s - %s\n", i + 1, vct[i].description,
				test_msg);
		debug_hexdump(stdout, "plaintext:", vct[i].pt.data, vct[i].pt.len);
		debug_hexdump(stdout, "ciphertext:", vct[i].ct.data, vct[i].ct.len);
		debug_hexdump(stdout, "digest:", vct[i].digest.data, vct[i].digest.len);
		debug_hexdump(stdout, "sign:", vct[i].sign.data, vct[i].sign.len);

		debug_hexdump(stdout, "e:", vct[i].e.data, vct[i].e.len);
		debug_hexdump(stdout, "d:", vct[i].d.data, vct[i].d.len);
		debug_hexdump(stdout, "n:", vct[i].n.data, vct[i].n.len);
		debug_hexdump(stdout, "p:", vct[i].p.data, vct[i].p.len);
		debug_hexdump(stdout, "q:", vct[i].q.data, vct[i].q.len);
		debug_hexdump(stdout, "dP:", vct[i].dP.data, vct[i].dP.len);
		debug_hexdump(stdout, "dQ:", vct[i].dQ.data, vct[i].dQ.len);
		debug_hexdump(stdout, "qInv:", vct[i].qInv.data, vct[i].qInv.len);

		for (key_type = RTE_RSA_KEY_TYPE_EXP;
				key_type < RTE_RSA_KEY_TYPE_LIST_END; key_type++) {

			int sess = 0;

			if (key_type == 0)
				printf("\n    RSA key is an exponent:\n");
			else
				printf("    RSA key is in quintuple format:\n");
			do {
				if (sess == 1 && sessionless != 1)
					break;

				if (sess == 0)
					printf("\n    With Session:\n");
				else
					printf("\n    Without Session:\n");

				if (ats_case_rsa_op(&testsuite_params_asym, &vct[sess],
						test_msg, sess, RTE_CRYPTO_ASYM_OP_ENCRYPT,
						key_type) != TEST_SUCCESS) {
					printf("    %-20s: %s\n", "Encryption", "FAIL");
					status = TEST_FAILED;
				} else {
					printf("    %-20s: %s\n", "Encryption", "PASS");
				}

				if (ats_case_rsa_op(&testsuite_params_asym, &vct[sess],
						test_msg, sess, RTE_CRYPTO_ASYM_OP_DECRYPT,
						key_type) != TEST_SUCCESS) {
					printf("    %-20s: %s\n", "Decryption", "FAIL");
					status = TEST_FAILED;
				} else {
					printf("    %-20s: %s\n", "Decryption", "PASS");
				}

				if (ats_case_rsa_op(&testsuite_params_asym, &vct[sess],
						test_msg, sess, RTE_CRYPTO_ASYM_OP_SIGN,
						key_type) != TEST_SUCCESS) {
					printf("    %-20s: %s\n", "Sign", "FAIL");
					status = TEST_FAILED;
				} else {
					printf("    %-20s: %s\n", "Sign", "PASS");
				}

				if (ats_case_rsa_op(&testsuite_params_asym, &vct[sess],
						test_msg, sess, RTE_CRYPTO_ASYM_OP_VERIFY,
						key_type) != TEST_SUCCESS) {
					printf("    %-20s: %s\n", "Verify", "FAIL");
					status = TEST_FAILED;
				} else {
					printf("    %-20s: %s\n", "Verify", "PASS");
				}

				sess++;

			} while (sess <= 1);
			printf("\n");
		}
	}

	TEST_ASSERT_EQUAL(status, 0, "Test failed");
	return status;
}

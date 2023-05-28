/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium Networks
 * Copyright (c) 2019-2023 Intel Corporation
 */

#include <rte_bus_vdev.h>
#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_pause.h>

#include <rte_cryptodev.h>
#include <rte_crypto.h>

#include "test_cryptodev.h"
#include "test_cryptodev_dh_test_vectors.h"
#include "test_cryptodev_dsa_test_vectors.h"
#include "test_cryptodev_ecdsa_test_vectors.h"
#include "test_cryptodev_ecpm_test_vectors.h"
#include "test_cryptodev_mod_test_vectors.h"
#include "test_cryptodev_rsa_test_vectors.h"
#include "test_cryptodev_asym_util.h"
#include "test.h"

#define TEST_NUM_BUFS 10
#define TEST_NUM_SESSIONS 4

#ifndef TEST_DATA_SIZE
	#define TEST_DATA_SIZE 4096
#endif
#define ASYM_TEST_MSG_LEN 256
#define TEST_VECTOR_SIZE 256
#define DEQ_TIMEOUT 50

static int gbl_driver_id;
struct crypto_testsuite_params_asym {
	struct rte_mempool *op_mpool;
	struct rte_mempool *session_mpool;
	struct rte_cryptodev_config conf;
	struct rte_cryptodev_qp_conf qp_conf;
	uint8_t valid_devs[RTE_CRYPTO_MAX_DEVS];
	uint8_t valid_dev_count;
} _testsuite_params, *params = &_testsuite_params;

static struct ut_args {
	void *sess;
	struct rte_crypto_op *op;
	struct rte_crypto_op *result_op;
} _args, *self = &_args;

union test_case_structure {
	struct modex_test_data modex;
	struct modinv_test_data modinv;
	struct rsa_test_data_2 rsa_data;
};

struct test_cases_array {
	uint32_t size;
	const void *address[TEST_VECTOR_SIZE];
};
static struct test_cases_array test_vector = {0, { NULL } };

static int
testsuite_setup(void)
{
	uint8_t valid_devs[RTE_CRYPTO_MAX_DEVS];
	struct rte_cryptodev_info info;
	int ret, dev_id = -1;
	uint32_t i, nb_devs;
	uint16_t qp_id;

	memset(params, 0, sizeof(*params));

	test_vector.size = 0;

	/* Device, op pool and session configuration for asymmetric crypto. 8< */
	params->op_mpool = rte_crypto_op_pool_create(
			"CRYPTO_ASYM_OP_POOL",
			RTE_CRYPTO_OP_TYPE_ASYMMETRIC,
			TEST_NUM_BUFS, 0,
			0,
			rte_socket_id());
	if (params->op_mpool == NULL) {
		RTE_LOG(ERR, USER1, "Can't create ASYM_CRYPTO_OP_POOL\n");
		return TEST_FAILED;
	}

	/* Create an OPENSSL device if required */
	if (gbl_driver_id == rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_OPENSSL_PMD))) {
		nb_devs = rte_cryptodev_device_count_by_driver(
				rte_cryptodev_driver_id_get(
				RTE_STR(CRYPTODEV_NAME_OPENSSL_PMD)));
		if (nb_devs < 1) {
			ret = rte_vdev_init(
				RTE_STR(CRYPTODEV_NAME_OPENSSL_PMD),
				NULL);

			TEST_ASSERT(ret == 0, "Failed to create "
				"instance of pmd : %s",
				RTE_STR(CRYPTODEV_NAME_OPENSSL_PMD));
		}
	}

	/* Get list of valid crypto devs */
	nb_devs = rte_cryptodev_devices_get(
				rte_cryptodev_driver_name_get(gbl_driver_id),
				valid_devs, RTE_CRYPTO_MAX_DEVS);
	if (nb_devs < 1) {
		RTE_LOG(ERR, USER1, "No crypto devices found?\n");
		return TEST_SKIPPED;
	}

	/*
	 * Get first valid asymmetric device found in test suite param and
	 * break
	 */
	for (i = 0; i < nb_devs ; i++) {
		rte_cryptodev_info_get(valid_devs[i], &info);
		if (info.feature_flags & RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO) {
			dev_id = params->valid_devs[0] = valid_devs[i];
			break;
		}
	}

	if (dev_id == -1) {
		RTE_LOG(ERR, USER1, "Device doesn't support asymmetric. "
			"Test skipped.\n");
		return TEST_FAILED;
	}

	/* Set valid device count */
	params->valid_dev_count = nb_devs;

	/* configure device with num qp */
	params->conf.nb_queue_pairs = info.max_nb_queue_pairs;
	params->conf.socket_id = SOCKET_ID_ANY;
	params->conf.ff_disable = RTE_CRYPTODEV_FF_SECURITY |
			RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO;
	TEST_ASSERT_SUCCESS(rte_cryptodev_configure(dev_id,
			&params->conf),
			"Failed to configure cryptodev %u with %u qps",
			dev_id, params->conf.nb_queue_pairs);

	/* configure qp */
	params->qp_conf.nb_descriptors = DEFAULT_NUM_OPS_INFLIGHT;
	params->qp_conf.mp_session = params->session_mpool;
	for (qp_id = 0; qp_id < info.max_nb_queue_pairs; qp_id++) {
		TEST_ASSERT_SUCCESS(rte_cryptodev_queue_pair_setup(
			dev_id, qp_id, &params->qp_conf,
			rte_cryptodev_socket_id(dev_id)),
			"Failed to setup queue pair %u on cryptodev %u ASYM",
			qp_id, dev_id);
	}

	params->session_mpool = rte_cryptodev_asym_session_pool_create(
			"test_asym_sess_mp", TEST_NUM_SESSIONS, 0, 0,
			SOCKET_ID_ANY);

	TEST_ASSERT_NOT_NULL(params->session_mpool,
			"session mempool allocation failed");
	/* >8 End of device, op pool and session configuration for asymmetric crypto section. */

	TEST_ASSERT_SUCCESS(rte_cryptodev_start(params->valid_devs[0]),
						"Failed to start cryptodev %u",
						params->valid_devs[0]);

	return TEST_SUCCESS;
}

static void
testsuite_teardown(void)
{
	params->qp_conf.mp_session = NULL;
	params->conf.ff_disable = 0;
	if (params->op_mpool != NULL) {
		rte_mempool_free(params->op_mpool);
		params->op_mpool = NULL;
	}
	if (params->session_mpool != NULL) {
		rte_mempool_free(params->session_mpool);
		params->session_mpool = NULL;
	}
	rte_cryptodev_stop(params->valid_devs[0]);
}

static inline void print_asym_capa(
		const struct rte_cryptodev_asymmetric_xform_capability *capa)
{
	int i = 0;

	printf("\nxform type: %s\n===================\n",
			rte_cryptodev_asym_get_xform_string(capa->xform_type));
	printf("operation supported -");

	for (i = 0; i < RTE_CRYPTO_ASYM_OP_LIST_END; i++) {
		/* check supported operations */
		if (rte_cryptodev_asym_xform_capability_check_optype(capa, i)) {
			if (capa->xform_type == RTE_CRYPTO_ASYM_XFORM_DH)
				printf(" %s", rte_crypto_asym_ke_strings[i]);
			else
				printf(" %s", rte_crypto_asym_op_strings[i]);
		}
	}
	switch (capa->xform_type) {
	case RTE_CRYPTO_ASYM_XFORM_RSA:
	case RTE_CRYPTO_ASYM_XFORM_MODINV:
	case RTE_CRYPTO_ASYM_XFORM_MODEX:
	case RTE_CRYPTO_ASYM_XFORM_DH:
	case RTE_CRYPTO_ASYM_XFORM_DSA:
		printf(" modlen: min %d max %d increment %d",
				capa->modlen.min,
				capa->modlen.max,
				capa->modlen.increment);
	break;
	case RTE_CRYPTO_ASYM_XFORM_ECDSA:
	case RTE_CRYPTO_ASYM_XFORM_ECPM:
	default:
		break;
	}
	printf("\n");
}

static int
test_capability(void)
{
	uint8_t dev_id = params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	const struct rte_cryptodev_capabilities *dev_capa;
	int i = 0;
	struct rte_cryptodev_asym_capability_idx idx;
	const struct rte_cryptodev_asymmetric_xform_capability *capa;

	rte_cryptodev_info_get(dev_id, &dev_info);
	if (!(dev_info.feature_flags &
				RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO)) {
		RTE_LOG(INFO, USER1,
				"Device doesn't support asymmetric. Test Skipped\n");
		return TEST_SUCCESS;
	}

	/* print xform capability */
	for (i = 0;
		dev_info.capabilities[i].op != RTE_CRYPTO_OP_TYPE_UNDEFINED;
		i++) {
		dev_capa = &(dev_info.capabilities[i]);
		if (dev_info.capabilities[i].op ==
				RTE_CRYPTO_OP_TYPE_ASYMMETRIC) {
			idx.type = dev_capa->asym.xform_capa.xform_type;

			capa = rte_cryptodev_asym_capability_get(dev_id,
				(const struct
				rte_cryptodev_asym_capability_idx *) &idx);
			print_asym_capa(capa);
			}
	}
	return TEST_SUCCESS;
}

static int send(struct rte_crypto_op **op,
		struct rte_crypto_op **result_op)
{
	int ticks = 0;

	if (rte_cryptodev_enqueue_burst(params->valid_devs[0], 0,
			op, 1) != 1) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: Error sending packet for operation on device %d",
			__LINE__, params->valid_devs[0]);
		return TEST_FAILED;
	}
	while (rte_cryptodev_dequeue_burst(params->valid_devs[0], 0,
			result_op, 1) == 0) {
		rte_delay_ms(1);
		ticks++;
		if (ticks >= DEQ_TIMEOUT) {
			RTE_LOG(ERR, USER1,
				"line %u FAILED: Cannot dequeue the crypto op on device %d",
				__LINE__, params->valid_devs[0]);
			return TEST_FAILED;
		}
	}
	TEST_ASSERT_NOT_NULL(*result_op,
			"line %u FAILED: Failed to process asym crypto op",
			__LINE__);
	TEST_ASSERT_SUCCESS((*result_op)->status,
			"line %u FAILED: Failed to process asym crypto op, error status received",
			__LINE__);
	return TEST_SUCCESS;
}

#define SET_RSA_PARAM(arg, vector, coef) \
	uint8_t coef[TEST_DATA_SIZE] = { }; \
	memcpy(coef, vector->coef.data, vector->coef.len); \
	arg.coef.data = coef; \
	arg.coef.length = vector->coef.len

#define SET_RSA_PARAM_QT(arg, vector, coef) \
	uint8_t coef[TEST_DATA_SIZE] = { }; \
	memcpy(coef, vector->coef.data, vector->coef.len); \
	arg.qt.coef.data = coef; \
	arg.qt.coef.length = vector->coef.len

static int
RSA_Sign_Verify(const struct rsa_test_data_2 *vector)
{
	uint8_t output_buf[TEST_DATA_SIZE];

	self->op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_SIGN;
	self->op->asym->rsa.sign.length = 0;
	self->op->asym->rsa.sign.data = output_buf;
	SET_RSA_PARAM(self->op->asym->rsa, vector, message);
	self->op->asym->rsa.padding.type = vector->padding;
	rte_crypto_op_attach_asym_session(self->op, self->sess);
	TEST_ASSERT_SUCCESS(send(&self->op, &self->result_op),
		"Failed to process crypto op (RSA Signature)");

	self->op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
	self->op->asym->rsa.padding.type = vector->padding;
	TEST_ASSERT_SUCCESS(send(&self->op, &self->result_op),
		"Failed to process crypto op (RSA Verify)");

	return TEST_SUCCESS;
}

static int
RSA_Encrypt(const struct rsa_test_data_2 *vector, uint8_t *cipher_buf)
{
	self->result_op = NULL;
	/* Compute encryption on the test vector */
	self->op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_ENCRYPT;
	self->op->asym->rsa.cipher.data = cipher_buf;
	self->op->asym->rsa.cipher.length = 0;
	SET_RSA_PARAM(self->op->asym->rsa, vector, message);
	self->op->asym->rsa.padding.type = vector->padding;

	rte_crypto_op_attach_asym_session(self->op, self->sess);
	TEST_ASSERT_SUCCESS(send(&self->op, &self->result_op),
		"Failed to process crypto op (Enryption)");

	return 0;
}

static int
RSA_Decrypt(const struct rsa_test_data_2 *vector, uint8_t *plaintext,
		const int use_op)
{
	uint8_t cipher[TEST_DATA_SIZE] = { 0 };

	if (use_op == 0) {
		memcpy(cipher, vector->cipher.data, vector->cipher.len);
		self->op->asym->rsa.cipher.data = cipher;
		self->op->asym->rsa.cipher.length = vector->cipher.len;
	}
	self->result_op = NULL;
	self->op->asym->rsa.message.data = plaintext;
	self->op->asym->rsa.message.length = 0;
	self->op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_DECRYPT;
	self->op->asym->rsa.padding.type = vector->padding;
	rte_crypto_op_attach_asym_session(self->op, self->sess);
	TEST_ASSERT_SUCCESS(send(&self->op, &self->result_op),
		"Failed to process crypto op (Decryption)");
	return 0;
}

static void
RSA_key_init_Exp(struct rte_crypto_asym_xform *xform,
		const struct rsa_test_data_2 *vector)
{
	SET_RSA_PARAM(xform->rsa, vector, n);
	SET_RSA_PARAM(xform->rsa, vector, e);
	SET_RSA_PARAM(xform->rsa, vector, d);
	xform->rsa.key_type = RTE_RSA_KEY_TYPE_EXP;
}

static void
RSA_key_init_CRT(struct rte_crypto_asym_xform *xform,
		const struct rsa_test_data_2 *vector)
{
	SET_RSA_PARAM(xform->rsa, vector, n);
	SET_RSA_PARAM(xform->rsa, vector, e);
	SET_RSA_PARAM_QT(xform->rsa, vector, p);
	SET_RSA_PARAM_QT(xform->rsa, vector, q);
	SET_RSA_PARAM_QT(xform->rsa, vector, dP);
	SET_RSA_PARAM_QT(xform->rsa, vector, dQ);
	SET_RSA_PARAM_QT(xform->rsa, vector, qInv);
	xform->rsa.key_type = RTE_RSA_KEY_TYPE_QT;
}

typedef void (*rsa_key_init_t)(struct rte_crypto_asym_xform *,
	const struct rsa_test_data_2 *);

static int
RSA_Init_Session(const struct rsa_test_data_2 *vector,
	rsa_key_init_t key_init)
{
	const uint8_t dev_id = params->valid_devs[0];
	struct rte_cryptodev_info dev_info;
	struct rte_crypto_asym_xform xform = { };
	int ret = 0;

	key_init(&xform, vector);
	xform.xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;

	rte_cryptodev_info_get(dev_id, &dev_info);
	if (!(dev_info.feature_flags & RTE_CRYPTODEV_FF_RSA_PRIV_OP_KEY_QT)) {
		RTE_LOG(INFO, USER1,
			"Device doesn't support decrypt op with quintuple key type. Test skipped\n");
		return TEST_SKIPPED;
	}
	ret = rte_cryptodev_asym_session_create(dev_id, &xform,
		params->session_mpool, &self->sess);
	if (ret < 0) {
		RTE_LOG(ERR, USER1,
			"Session creation failed for enc_dec_crt\n");
		return (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
	}
	return 0;
}

static int
PWCT_RSA_Encrypt_Decrypt(const void *data)
{
	uint8_t cipher_buf[TEST_DATA_SIZE] = {0};
	uint8_t message[TEST_DATA_SIZE] = {0};
	const struct rsa_test_data_2 *vector = data;
	int ret = RSA_Init_Session(vector, RSA_key_init_Exp);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to init session for RSA\n");
		return ret;
	}
	TEST_ASSERT_SUCCESS(RSA_Encrypt(vector, cipher_buf),
		"RSA: Failed to encrypt");
	TEST_ASSERT_SUCCESS(RSA_Decrypt(vector, message, 1),
		"RSA: Failed to decrypt");
	TEST_ASSERT_BUFFERS_ARE_EQUAL(vector->message.data,
		self->result_op->asym->rsa.message.data,
		vector->message.len,
		"operation verification failed\n");
	return TEST_SUCCESS;
}

static int
PWCT_RSA_CRT_Encrypt_Decrypt(const void *data)
{
	uint8_t cipher_buf[TEST_DATA_SIZE] = {0};
	uint8_t message[TEST_DATA_SIZE] = {0};
	const struct rsa_test_data_2 *vector = data;
	int ret = RSA_Init_Session(vector, RSA_key_init_CRT);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to init session for RSA\n");
		return ret;
	}
	TEST_ASSERT_SUCCESS(RSA_Encrypt(vector, cipher_buf),
		"RSA: Failed to encrypt");
	TEST_ASSERT_SUCCESS(RSA_Decrypt(vector, message, 1),
		"RSA: Failed to decrypt");
	TEST_ASSERT_BUFFERS_ARE_EQUAL(vector->message.data,
		self->result_op->asym->rsa.message.data,
		vector->message.len,
		"operation verification failed\n");
	return TEST_SUCCESS;
}

static int
PWCT_RSA_Sign_Verify(const void *data)
{
	const struct rsa_test_data_2 *vector = data;
	int ret = RSA_Init_Session(vector, RSA_key_init_Exp);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to init session for RSA\n");
		return ret;
	}
	TEST_ASSERT_SUCCESS(RSA_Sign_Verify(vector),
		"Failed to process RSA operation");
	return TEST_SUCCESS;
}

static int
PWCT_RSA_Sign_Verify_CRT(const void *data)
{
	const struct rsa_test_data_2 *vector = data;
	int ret = RSA_Init_Session(vector, RSA_key_init_CRT);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to init session for RSA\n");
		return ret;
	}
	TEST_ASSERT_SUCCESS(RSA_Sign_Verify(vector),
		"Failed to process RSA operation");
	return TEST_SUCCESS;
}

static int
KAT_RSA_Encrypt(const void *data)
{
	uint8_t cipher_buf[TEST_DATA_SIZE] = {0};
	const struct rsa_test_data_2 *vector = data;
	int ret = RSA_Init_Session(vector, RSA_key_init_Exp);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to init session for RSA\n");
		return ret;
	}
	TEST_ASSERT_SUCCESS(RSA_Encrypt(vector, cipher_buf),
		"RSA: Failed to encrypt");
	TEST_ASSERT_BUFFERS_ARE_EQUAL(vector->cipher.data,
		self->result_op->asym->rsa.cipher.data,
		vector->cipher.len,
		"operation verification failed\n");
	return 0;
}

static int
KAT_RSA_Decrypt(const void *data)
{
	uint8_t message[TEST_DATA_SIZE] = {0};
	const struct rsa_test_data_2 *vector = data;
	int ret = RSA_Init_Session(vector, RSA_key_init_Exp);

	if (ret) {
		RTE_LOG(ERR, USER1, "Failed to init session for RSA\n");
		return ret;
	}
	TEST_ASSERT_SUCCESS(RSA_Decrypt(vector, message, 0),
		"RSA: Failed to encrypt");
	TEST_ASSERT_BUFFERS_ARE_EQUAL(vector->message.data,
		self->result_op->asym->rsa.message.data,
		vector->message.len,
		"operation verification failed\n");
	return 0;
}

static int
test_dh_gen_shared_sec(struct rte_crypto_asym_xform *xfrm)
{
	struct rte_mempool *op_mpool = params->op_mpool;
	struct rte_mempool *sess_mpool = params->session_mpool;
	uint8_t dev_id = params->valid_devs[0];
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *op = NULL, *result_op = NULL;
	void *sess = NULL;
	int ret, status = TEST_SUCCESS;
	uint8_t output[TEST_DH_MOD_LEN];
	struct rte_crypto_asym_xform xform = *xfrm;
	uint8_t peer[] = "01234567890123456789012345678901234567890123456789";

	/* set up crypto op data structure */
	op = rte_crypto_op_alloc(op_mpool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (!op) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to allocate asymmetric crypto "
			"operation struct");
		status = TEST_FAILED;
		goto error_exit;
	}
	asym_op = op->asym;

	/* Setup a xform and op to generate private key only */
	xform.next = NULL;
	asym_op->dh.ke_type = RTE_CRYPTO_ASYM_KE_SHARED_SECRET_COMPUTE;
	asym_op->dh.priv_key.data = dh_test_params.priv_key.data;
	asym_op->dh.priv_key.length = dh_test_params.priv_key.length;
	asym_op->dh.pub_key.data = (uint8_t *)peer;
	asym_op->dh.pub_key.length = sizeof(peer);
	asym_op->dh.shared_secret.data = output;
	asym_op->dh.shared_secret.length = sizeof(output);

	ret = rte_cryptodev_asym_session_create(dev_id, &xform, sess_mpool, &sess);
	if (ret < 0) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Session creation failed");
		status = (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
		goto error_exit;
	}

	/* attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(op, sess);

	RTE_LOG(DEBUG, USER1, "Process ASYM operation");

	/* Process crypto operation */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Error sending packet for operation");
		status = TEST_FAILED;
		goto error_exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to process asym crypto op");
		status = TEST_FAILED;
		goto error_exit;
	}

	debug_hexdump(stdout, "shared secret:",
			asym_op->dh.shared_secret.data,
			asym_op->dh.shared_secret.length);

error_exit:
	if (sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, sess);
	rte_crypto_op_free(op);
	return status;
}

static int
test_dh_gen_priv_key(struct rte_crypto_asym_xform *xfrm)
{
	struct rte_mempool *op_mpool = params->op_mpool;
	struct rte_mempool *sess_mpool = params->session_mpool;
	uint8_t dev_id = params->valid_devs[0];
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *op = NULL, *result_op = NULL;
	void *sess = NULL;
	int ret, status = TEST_SUCCESS;
	uint8_t output[TEST_DH_MOD_LEN];
	struct rte_crypto_asym_xform xform = *xfrm;

	/* set up crypto op data structure */
	op = rte_crypto_op_alloc(op_mpool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (!op) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to allocate asymmetric crypto "
			"operation struct");
		status = TEST_FAILED;
		goto error_exit;
	}
	asym_op = op->asym;

	/* Setup a xform and op to generate private key only */
	xform.next = NULL;
	asym_op->dh.ke_type = RTE_CRYPTO_ASYM_KE_PRIV_KEY_GENERATE;
	asym_op->dh.priv_key.data = output;
	asym_op->dh.priv_key.length = sizeof(output);

	ret = rte_cryptodev_asym_session_create(dev_id, &xform, sess_mpool, &sess);
	if (ret < 0) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Session creation failed");
		status = (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
		goto error_exit;
	}

	/* attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(op, sess);

	RTE_LOG(DEBUG, USER1, "Process ASYM operation");

	/* Process crypto operation */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Error sending packet for operation");
		status = TEST_FAILED;
		goto error_exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to process asym crypto op");
		status = TEST_FAILED;
		goto error_exit;
	}

	debug_hexdump(stdout, "private key:",
			asym_op->dh.priv_key.data,
			asym_op->dh.priv_key.length);


error_exit:
	if (sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, sess);
	rte_crypto_op_free(op);

	return status;
}


static int
test_dh_gen_pub_key(struct rte_crypto_asym_xform *xfrm)
{
	struct rte_mempool *op_mpool = params->op_mpool;
	struct rte_mempool *sess_mpool = params->session_mpool;
	uint8_t dev_id = params->valid_devs[0];
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *op = NULL, *result_op = NULL;
	void *sess = NULL;
	int ret, status = TEST_SUCCESS;
	uint8_t output[TEST_DH_MOD_LEN];
	struct rte_crypto_asym_xform xform = *xfrm;

	/* set up crypto op data structure */
	op = rte_crypto_op_alloc(op_mpool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (!op) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to allocate asymmetric crypto "
			"operation struct");
		status = TEST_FAILED;
		goto error_exit;
	}
	asym_op = op->asym;
	/* Setup a xform chain to generate public key
	 * using test private key
	 *
	 */
	xform.next = NULL;

	asym_op->dh.ke_type = RTE_CRYPTO_ASYM_KE_PUB_KEY_GENERATE;
	asym_op->dh.pub_key.data = output;
	asym_op->dh.pub_key.length = sizeof(output);
	/* load pre-defined private key */
	asym_op->dh.priv_key.data = rte_malloc(NULL,
					dh_test_params.priv_key.length,
					0);
	asym_op->dh.priv_key = dh_test_params.priv_key;

	ret = rte_cryptodev_asym_session_create(dev_id, &xform, sess_mpool, &sess);
	if (ret < 0) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Session creation failed");
		status = (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
		goto error_exit;
	}

	/* attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(op, sess);

	RTE_LOG(DEBUG, USER1, "Process ASYM operation");

	/* Process crypto operation */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Error sending packet for operation");
		status = TEST_FAILED;
		goto error_exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to process asym crypto op");
		status = TEST_FAILED;
		goto error_exit;
	}

	debug_hexdump(stdout, "pub key:",
			asym_op->dh.pub_key.data, asym_op->dh.pub_key.length);

	debug_hexdump(stdout, "priv key:",
			asym_op->dh.priv_key.data, asym_op->dh.priv_key.length);

error_exit:
	if (sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, sess);
	rte_crypto_op_free(op);

	return status;
}

static int
test_dh_gen_kp(struct rte_crypto_asym_xform *xfrm)
{
	struct rte_mempool *op_mpool = params->op_mpool;
	struct rte_mempool *sess_mpool = params->session_mpool;
	uint8_t dev_id = params->valid_devs[0];
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *op = NULL, *result_op = NULL;
	void *sess = NULL;
	int ret, status = TEST_SUCCESS;
	uint8_t out_pub_key[TEST_DH_MOD_LEN];
	uint8_t out_prv_key[TEST_DH_MOD_LEN];
	struct rte_crypto_asym_xform pub_key_xform;
	struct rte_crypto_asym_xform xform = *xfrm;

	/* set up crypto op data structure */
	op = rte_crypto_op_alloc(op_mpool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (!op) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to allocate asymmetric crypto "
			"operation struct");
		status = TEST_FAILED;
		goto error_exit;
	}
	asym_op = op->asym;
	/* Setup a xform chain to generate
	 * private key first followed by
	 * public key
	 */
	pub_key_xform.xform_type = RTE_CRYPTO_ASYM_XFORM_DH;
	xform.next = &pub_key_xform;

	asym_op->dh.ke_type = RTE_CRYPTO_ASYM_KE_PUB_KEY_GENERATE;
	asym_op->dh.pub_key.data = out_pub_key;
	asym_op->dh.pub_key.length = sizeof(out_pub_key);
	asym_op->dh.priv_key.data = out_prv_key;
	asym_op->dh.priv_key.length = 0;

	ret = rte_cryptodev_asym_session_create(dev_id, &xform, sess_mpool, &sess);
	if (ret < 0) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Session creation failed");
		status = (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
		goto error_exit;
	}

	/* attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(op, sess);

	RTE_LOG(DEBUG, USER1, "Process ASYM operation");

	/* Process crypto operation */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Error sending packet for operation");
		status = TEST_FAILED;
		goto error_exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to process asym crypto op");
		status = TEST_FAILED;
		goto error_exit;
	}
	debug_hexdump(stdout, "priv key:",
			out_prv_key, asym_op->dh.priv_key.length);
	debug_hexdump(stdout, "pub key:",
			out_pub_key, asym_op->dh.pub_key.length);

error_exit:
	if (sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, sess);
	rte_crypto_op_free(op);

	return status;
}

static int
modular_multiplicative_inverse(const void *test_data)
{
	const struct modinv_test_data *vector = test_data;
	uint8_t input[TEST_DATA_SIZE] = { 0 };
	uint8_t modulus[TEST_DATA_SIZE] = { 0 };
	uint8_t result[TEST_DATA_SIZE] = { 0 };
	struct rte_cryptodev_asym_capability_idx cap_idx;
	const struct rte_cryptodev_asymmetric_xform_capability *capability;
	struct rte_crypto_asym_xform xform = { };
	const uint8_t dev_id = params->valid_devs[0];

	memcpy(input, vector->base.data, vector->base.len);
	memcpy(modulus, vector->modulus.data, vector->modulus.len);

	xform.xform_type = RTE_CRYPTO_ASYM_XFORM_MODINV;
	xform.modex.modulus.data = modulus;
	xform.modex.modulus.length = vector->modulus.len;
	cap_idx.type = xform.xform_type;
	capability = rte_cryptodev_asym_capability_get(dev_id,
					&cap_idx);
	if (capability == NULL) {
		RTE_LOG(INFO, USER1,
			"Device doesn't support MOD INV. Test Skipped\n");
		return TEST_SKIPPED;
	}

	if (rte_cryptodev_asym_xform_capability_check_modlen(
			capability,
			xform.modinv.modulus.length)) {
		RTE_LOG(ERR, USER1,
			 "Invalid MODULUS length specified\n");
		return TEST_SKIPPED;
	}
	if (rte_cryptodev_asym_session_create(dev_id, &xform,
			params->session_mpool, &self->sess) < 0) {
		RTE_LOG(ERR, USER1, "line %u FAILED: Session creation failed",
			__LINE__);
		return TEST_FAILED;
	}
	rte_crypto_op_attach_asym_session(self->op, self->sess);

	self->op->asym->modinv.base.data = input;
	self->op->asym->modinv.base.length = vector->base.len;
	self->op->asym->modinv.result.data = result;

	TEST_ASSERT_SUCCESS(send(&self->op, &self->result_op),
		"Failed to process crypto op");
	TEST_ASSERT_BUFFERS_ARE_EQUAL(vector->inverse.data,
		self->result_op->asym->modinv.result.data,
		self->result_op->asym->modinv.result.length,
		"operation verification failed\n");
	return TEST_SUCCESS;
}

static int
modular_exponentiation(const void *test_data)
{
	const struct modex_test_data *vector = test_data;
	uint8_t input[TEST_DATA_SIZE] = { 0 };
	uint8_t exponent[TEST_DATA_SIZE] = { 0 };
	uint8_t modulus[TEST_DATA_SIZE] = { 0 };
	uint8_t result[TEST_DATA_SIZE] = { 0 };
	struct rte_cryptodev_asym_capability_idx cap_idx;
	const struct rte_cryptodev_asymmetric_xform_capability *capability;
	struct rte_crypto_asym_xform xform = { };
	const uint8_t dev_id = params->valid_devs[0];

	memcpy(input, vector->base.data, vector->base.len);
	memcpy(exponent, vector->exponent.data, vector->exponent.len);
	memcpy(modulus, vector->modulus.data, vector->modulus.len);

	xform.xform_type = RTE_CRYPTO_ASYM_XFORM_MODEX;
	xform.modex.exponent.data = exponent;
	xform.modex.exponent.length = vector->exponent.len;
	xform.modex.modulus.data = modulus;
	xform.modex.modulus.length = vector->modulus.len;

	cap_idx.type = xform.xform_type;
	capability = rte_cryptodev_asym_capability_get(dev_id, &cap_idx);
	if (capability == NULL) {
		RTE_LOG(INFO, USER1,
			"Device doesn't support MOD EXP. Test Skipped\n");
		return TEST_SKIPPED;
	}
	if (rte_cryptodev_asym_xform_capability_check_modlen(
			capability, xform.modex.modulus.length)) {
		RTE_LOG(INFO, USER1,
			"Invalid MODULUS length specified, not supported on this device\n"
		);
		return TEST_SKIPPED;
	}
	if (rte_cryptodev_asym_session_create(dev_id, &xform,
			params->session_mpool, &self->sess) < 0) {
		RTE_LOG(ERR, USER1, "line %u FAILED: Session creation failed",
			__LINE__);
		return TEST_FAILED;
	}
	rte_crypto_op_attach_asym_session(self->op, self->sess);
	self->op->asym->modex.base.data = input;
	self->op->asym->modex.base.length = vector->base.len;
	self->op->asym->modex.result.data = result;

	TEST_ASSERT_SUCCESS(send(&self->op, &self->result_op),
		"Failed to process crypto op");
	TEST_ASSERT_BUFFERS_ARE_EQUAL(vector->reminder.data,
			self->result_op->asym->modex.result.data,
			self->result_op->asym->modex.result.length,
			"operation verification failed\n");
	return TEST_SUCCESS;
}

static int
test_dh_keygenration(void)
{
	int status;

	debug_hexdump(stdout, "p:", dh_xform.dh.p.data, dh_xform.dh.p.length);
	debug_hexdump(stdout, "g:", dh_xform.dh.g.data, dh_xform.dh.g.length);
	debug_hexdump(stdout, "priv_key:", dh_test_params.priv_key.data,
			dh_test_params.priv_key.length);

	RTE_LOG(INFO, USER1,
		"Test Public and Private key pair generation\n");

	status = test_dh_gen_kp(&dh_xform);
	TEST_ASSERT_EQUAL(status, 0, "Test failed");

	RTE_LOG(INFO, USER1,
		"Test Public Key Generation using pre-defined priv key\n");

	status = test_dh_gen_pub_key(&dh_xform);
	TEST_ASSERT_EQUAL(status, 0, "Test failed");

	RTE_LOG(INFO, USER1,
		"Test Private Key Generation only\n");

	status = test_dh_gen_priv_key(&dh_xform);
	TEST_ASSERT_EQUAL(status, 0, "Test failed");

	RTE_LOG(INFO, USER1,
		"Test shared secret compute\n");

	status = test_dh_gen_shared_sec(&dh_xform);
	TEST_ASSERT_EQUAL(status, 0, "Test failed");

	return status;
}

static int
test_dsa_sign(struct rte_crypto_dsa_op_param *dsa_op)
{
	struct rte_mempool *op_mpool = params->op_mpool;
	struct rte_mempool *sess_mpool = params->session_mpool;
	uint8_t dev_id = params->valid_devs[0];
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *op = NULL, *result_op = NULL;
	void *sess = NULL;
	int status = TEST_SUCCESS;
	int ret;

	ret = rte_cryptodev_asym_session_create(dev_id, &dsa_xform, sess_mpool, &sess);
	if (ret < 0) {
		RTE_LOG(ERR, USER1,
				 "line %u FAILED: %s", __LINE__,
				"Session creation failed");
		status = (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
		goto error_exit;
	}
	/* set up crypto op data structure */
	op = rte_crypto_op_alloc(op_mpool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (!op) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to allocate asymmetric crypto "
			"operation struct");
		status = TEST_FAILED;
		goto error_exit;
	}
	asym_op = op->asym;
	asym_op->dsa = *dsa_op;

	debug_hexdump(stdout, "p: ", dsa_xform.dsa.p.data,
			dsa_xform.dsa.p.length);
	debug_hexdump(stdout, "q: ", dsa_xform.dsa.q.data,
			dsa_xform.dsa.q.length);
	debug_hexdump(stdout, "g: ", dsa_xform.dsa.g.data,
			dsa_xform.dsa.g.length);
	debug_hexdump(stdout, "priv_key: ", dsa_xform.dsa.x.data,
			dsa_xform.dsa.x.length);

	/* attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(op, sess);
	asym_op->dsa.op_type = RTE_CRYPTO_ASYM_OP_SIGN;
	RTE_LOG(DEBUG, USER1, "Process ASYM operation");

	/* Process crypto operation */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Error sending packet for operation");
		status = TEST_FAILED;
		goto error_exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to process asym crypto op");
		status = TEST_FAILED;
		goto error_exit;
	}

	asym_op = result_op->asym;
	dsa_op->r.length = asym_op->dsa.r.length;
	dsa_op->s.length = asym_op->dsa.s.length;

	debug_hexdump(stdout, "r:",
			asym_op->dsa.r.data, asym_op->dsa.r.length);
	debug_hexdump(stdout, "s:",
			asym_op->dsa.s.data, asym_op->dsa.s.length);
error_exit:
	if (sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, sess);
	rte_crypto_op_free(op);
	return status;
}

static int
test_dsa_verify(struct rte_crypto_dsa_op_param *dsa_op)
{
	struct rte_mempool *op_mpool = params->op_mpool;
	struct rte_mempool *sess_mpool = params->session_mpool;
	uint8_t dev_id = params->valid_devs[0];
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *op = NULL, *result_op = NULL;
	void *sess = NULL;
	int status = TEST_SUCCESS;
	int ret;

	ret = rte_cryptodev_asym_session_create(dev_id, &dsa_xform, sess_mpool, &sess);
	if (ret < 0) {
		RTE_LOG(ERR, USER1,
				 "line %u FAILED: %s", __LINE__,
				"Session creation failed");
		status = (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
		goto error_exit;
	}
	/* set up crypto op data structure */
	op = rte_crypto_op_alloc(op_mpool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (!op) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to allocate asymmetric crypto "
			"operation struct");
		status = TEST_FAILED;
		goto error_exit;
	}
	asym_op = op->asym;
	asym_op->dsa = *dsa_op;

	debug_hexdump(stdout, "p: ", dsa_xform.dsa.p.data,
			dsa_xform.dsa.p.length);
	debug_hexdump(stdout, "q: ", dsa_xform.dsa.q.data,
			dsa_xform.dsa.q.length);
	debug_hexdump(stdout, "g: ", dsa_xform.dsa.g.data,
			dsa_xform.dsa.g.length);

	/* attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(op, sess);

	debug_hexdump(stdout, "r:",
			asym_op->dsa.r.data, asym_op->dsa.r.length);
	debug_hexdump(stdout, "s:",
			asym_op->dsa.s.data, asym_op->dsa.s.length);

	RTE_LOG(DEBUG, USER1, "Process ASYM verify operation");
	/* Test PMD DSA sign verification using signer public key */
	asym_op->dsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;

	/* copy signer public key */
	asym_op->dsa.y.data = dsa_test_params.y.data;
	asym_op->dsa.y.length = dsa_test_params.y.length;

	/* Process crypto operation */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Error sending packet for operation");
		status = TEST_FAILED;
		goto error_exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: %s",
			__LINE__, "Failed to process asym crypto op");
		status = TEST_FAILED;
		goto error_exit;
	}

	if (result_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s",
				__LINE__, "Failed to process asym crypto op");
		status = TEST_FAILED;
	}
error_exit:
	if (sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, sess);
	rte_crypto_op_free(op);
	return status;
}

static int
test_dsa(void)
{
	int status;
	uint8_t r[TEST_DH_MOD_LEN];
	uint8_t s[TEST_DH_MOD_LEN];
	struct rte_crypto_dsa_op_param dsa_op;
	uint8_t dgst[] = "35d81554afaad2cf18f3a1770d5fedc4ea5be344";

	dsa_op.message.data = dgst;
	dsa_op.message.length = sizeof(dgst);
	dsa_op.r.data = r;
	dsa_op.s.data = s;
	dsa_op.r.length = sizeof(r);
	dsa_op.s.length = sizeof(s);

	status = test_dsa_sign(&dsa_op);
	TEST_ASSERT_EQUAL(status, 0, "DSA sign test failed");
	status = test_dsa_verify(&dsa_op);
	TEST_ASSERT_EQUAL(status, 0, "DSA verify test failed");
	return status;
}

static int
test_ecdsa_sign_verify(enum curve curve_id)
{
	struct rte_mempool *sess_mpool = params->session_mpool;
	struct rte_mempool *op_mpool = params->op_mpool;
	struct crypto_testsuite_ecdsa_params input_params;
	void *sess = NULL;
	uint8_t dev_id = params->valid_devs[0];
	struct rte_crypto_op *result_op = NULL;
	uint8_t output_buf_r[TEST_DATA_SIZE];
	uint8_t output_buf_s[TEST_DATA_SIZE];
	struct rte_crypto_asym_xform xform;
	struct rte_crypto_asym_op *asym_op;
	struct rte_cryptodev_info dev_info;
	struct rte_crypto_op *op = NULL;
	int ret, status = TEST_SUCCESS;

	switch (curve_id) {
	case SECP192R1:
		input_params = ecdsa_param_secp192r1;
		break;
	case SECP224R1:
		input_params = ecdsa_param_secp224r1;
		break;
	case SECP256R1:
		input_params = ecdsa_param_secp256r1;
		break;
	case SECP384R1:
		input_params = ecdsa_param_secp384r1;
		break;
	case SECP521R1:
		input_params = ecdsa_param_secp521r1;
		break;
	default:
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Unsupported curve id\n");
		status = TEST_FAILED;
		goto exit;
	}

	rte_cryptodev_info_get(dev_id, &dev_info);

	/* Setup crypto op data structure */
	op = rte_crypto_op_alloc(op_mpool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (op == NULL) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Failed to allocate asymmetric crypto "
				"operation struct\n");
		status = TEST_FAILED;
		goto exit;
	}
	asym_op = op->asym;

	/* Setup asym xform */
	xform.next = NULL;
	xform.xform_type = RTE_CRYPTO_ASYM_XFORM_ECDSA;
	xform.ec.curve_id = input_params.curve;

	ret = rte_cryptodev_asym_session_create(dev_id, &xform, sess_mpool, &sess);
	if (ret < 0) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Session creation failed\n");
		status = (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
		goto exit;
	}

	/* Attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(op, sess);

	/* Compute sign */

	/* Populate op with operational details */
	op->asym->ecdsa.op_type = RTE_CRYPTO_ASYM_OP_SIGN;
	op->asym->ecdsa.message.data = input_params.digest.data;
	op->asym->ecdsa.message.length = input_params.digest.length;
	op->asym->ecdsa.k.data = input_params.scalar.data;
	op->asym->ecdsa.k.length = input_params.scalar.length;
	op->asym->ecdsa.pkey.data = input_params.pkey.data;
	op->asym->ecdsa.pkey.length = input_params.pkey.length;

	/* Init out buf */
	op->asym->ecdsa.r.data = output_buf_r;
	op->asym->ecdsa.s.data = output_buf_s;

	RTE_LOG(DEBUG, USER1, "Process ASYM operation\n");

	/* Process crypto operation */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Error sending packet for operation\n");
		status = TEST_FAILED;
		goto exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Failed to process asym crypto op\n");
		status = TEST_FAILED;
		goto exit;
	}

	if (result_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Failed to process asym crypto op\n");
		status = TEST_FAILED;
		goto exit;
	}

	asym_op = result_op->asym;

	debug_hexdump(stdout, "r:",
			asym_op->ecdsa.r.data, asym_op->ecdsa.r.length);
	debug_hexdump(stdout, "s:",
			asym_op->ecdsa.s.data, asym_op->ecdsa.s.length);

	ret = verify_ecdsa_sign(input_params.sign_r.data,
				input_params.sign_s.data, result_op);
	if (ret) {
		status = TEST_FAILED;
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"ECDSA sign failed.\n");
		goto exit;
	}

	/* Verify sign */

	/* Populate op with operational details */
	op->asym->ecdsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
	op->asym->ecdsa.q.x.data = input_params.pubkey_qx.data;
	op->asym->ecdsa.q.x.length = input_params.pubkey_qx.length;
	op->asym->ecdsa.q.y.data = input_params.pubkey_qy.data;
	op->asym->ecdsa.q.y.length = input_params.pubkey_qx.length;
	op->asym->ecdsa.r.data = asym_op->ecdsa.r.data;
	op->asym->ecdsa.r.length = asym_op->ecdsa.r.length;
	op->asym->ecdsa.s.data = asym_op->ecdsa.s.data;
	op->asym->ecdsa.s.length = asym_op->ecdsa.s.length;

	/* Enqueue sign result for verify */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		status = TEST_FAILED;
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Error sending packet for operation\n");
		goto exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		status = TEST_FAILED;
		goto exit;
	}
	if (result_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		status = TEST_FAILED;
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"ECDSA verify failed.\n");
		goto exit;
	}

exit:
	if (sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, sess);
	rte_crypto_op_free(op);
	return status;
};

static int
test_ecdsa_sign_verify_all_curve(void)
{
	int status, overall_status = TEST_SUCCESS;
	enum curve curve_id;
	int test_index = 0;
	const char *msg;

	for (curve_id = SECP192R1; curve_id < END_OF_CURVE_LIST; curve_id++) {
		status = test_ecdsa_sign_verify(curve_id);
		if (status == TEST_SUCCESS) {
			msg = "succeeded";
		} else {
			msg = "failed";
			overall_status = status;
		}
		printf("  %u) TestCase Sign/Veriy Curve %s  %s\n",
		       test_index ++, curve[curve_id], msg);
	}
	return overall_status;
}

static int
test_ecpm(enum curve curve_id)
{
	struct rte_mempool *sess_mpool = params->session_mpool;
	struct rte_mempool *op_mpool = params->op_mpool;
	struct crypto_testsuite_ecpm_params input_params;
	void *sess = NULL;
	uint8_t dev_id = params->valid_devs[0];
	struct rte_crypto_op *result_op = NULL;
	uint8_t output_buf_x[TEST_DATA_SIZE];
	uint8_t output_buf_y[TEST_DATA_SIZE];
	struct rte_crypto_asym_xform xform;
	struct rte_crypto_asym_op *asym_op;
	struct rte_cryptodev_info dev_info;
	struct rte_crypto_op *op = NULL;
	int ret, status = TEST_SUCCESS;

	switch (curve_id) {
	case SECP192R1:
		input_params = ecpm_param_secp192r1;
		break;
	case SECP224R1:
		input_params = ecpm_param_secp224r1;
		break;
	case SECP256R1:
		input_params = ecpm_param_secp256r1;
		break;
	case SECP384R1:
		input_params = ecpm_param_secp384r1;
		break;
	case SECP521R1:
		input_params = ecpm_param_secp521r1;
		break;
	default:
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Unsupported curve id\n");
		status = TEST_FAILED;
		goto exit;
	}

	rte_cryptodev_info_get(dev_id, &dev_info);

	/* Setup crypto op data structure */
	op = rte_crypto_op_alloc(op_mpool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (op == NULL) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Failed to allocate asymmetric crypto "
				"operation struct\n");
		status = TEST_FAILED;
		goto exit;
	}
	asym_op = op->asym;

	/* Setup asym xform */
	xform.next = NULL;
	xform.xform_type = RTE_CRYPTO_ASYM_XFORM_ECPM;
	xform.ec.curve_id = input_params.curve;

	ret = rte_cryptodev_asym_session_create(dev_id, &xform, sess_mpool, &sess);
	if (ret < 0) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Session creation failed\n");
		status = (ret == -ENOTSUP) ? TEST_SKIPPED : TEST_FAILED;
		goto exit;
	}

	/* Attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(op, sess);

	/* Populate op with operational details */
	op->asym->ecpm.p.x.data = input_params.gen_x.data;
	op->asym->ecpm.p.x.length = input_params.gen_x.length;
	op->asym->ecpm.p.y.data = input_params.gen_y.data;
	op->asym->ecpm.p.y.length = input_params.gen_y.length;
	op->asym->ecpm.scalar.data = input_params.privkey.data;
	op->asym->ecpm.scalar.length = input_params.privkey.length;

	/* Init out buf */
	op->asym->ecpm.r.x.data = output_buf_x;
	op->asym->ecpm.r.y.data = output_buf_y;

	RTE_LOG(DEBUG, USER1, "Process ASYM operation\n");

	/* Process crypto operation */
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Error sending packet for operation\n");
		status = TEST_FAILED;
		goto exit;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &result_op, 1) == 0)
		rte_pause();

	if (result_op == NULL) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Failed to process asym crypto op\n");
		status = TEST_FAILED;
		goto exit;
	}

	if (result_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"Failed to process asym crypto op\n");
		status = TEST_FAILED;
		goto exit;
	}

	asym_op = result_op->asym;

	debug_hexdump(stdout, "r x:",
			asym_op->ecpm.r.x.data, asym_op->ecpm.r.x.length);
	debug_hexdump(stdout, "r y:",
			asym_op->ecpm.r.y.data, asym_op->ecpm.r.y.length);

	ret = verify_ecpm(input_params.pubkey_x.data,
				input_params.pubkey_y.data, result_op);
	if (ret) {
		status = TEST_FAILED;
		RTE_LOG(ERR, USER1,
				"line %u FAILED: %s", __LINE__,
				"EC Point Multiplication failed.\n");
		goto exit;
	}

exit:
	if (sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, sess);
	rte_crypto_op_free(op);
	return status;
}

static int
test_ecpm_all_curve(void)
{
	int status, overall_status = TEST_SUCCESS;
	enum curve curve_id;
	int test_index = 0;
	const char *msg;

	for (curve_id = SECP192R1; curve_id < END_OF_CURVE_LIST; curve_id++) {
		status = test_ecpm(curve_id);
		if (status == TEST_SUCCESS) {
			msg = "succeeded";
		} else {
			msg = "failed";
			overall_status = status;
		}
		printf("  %u) TestCase EC Point Mul Curve %s  %s\n",
		       test_index ++, curve[curve_id], msg);
	}
	return overall_status;
}

static int
setup_generic(void)
{
	memset(self, 0, sizeof(*self));
	self->op = rte_crypto_op_alloc(params->op_mpool,
			RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (!self->op) {
		RTE_LOG(ERR, USER1,
			"line %u FAILED: Failed to allocate asymmetric crypto operation struct",
			__LINE__);
		return TEST_FAILED;
	}
	return TEST_SUCCESS;
}

static void
teardown_generic(void)
{
	uint8_t dev_id = params->valid_devs[0];

	if (self->sess != NULL)
		rte_cryptodev_asym_session_free(dev_id, self->sess);
	if (self->op != NULL)
		rte_crypto_op_free(self->op);
	self->sess = NULL;
	self->op = NULL;
	self->result_op = NULL;
}

static struct unit_test_suite cryptodev_openssl_asym_testsuite  = {
	.suite_name = "Crypto Device OPENSSL ASYM Unit Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(setup_generic, teardown_generic, test_capability),
		TEST_CASE_ST(setup_generic, teardown_generic, test_dsa),
		TEST_CASE_ST(setup_generic, teardown_generic,
				test_dh_keygenration),
		/* RSA */
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Encryption Decryption (n=128, pt=20, e=3) EXP",
			setup_generic, teardown_generic,
			PWCT_RSA_Encrypt_Decrypt, &RSA_vector_128_20_3_PKCS1),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Encryption Decryption (n=128, pt=20, e=3) CRT",
			setup_generic, teardown_generic,
			PWCT_RSA_CRT_Encrypt_Decrypt,
			&RSA_vector_128_20_3_PKCS1),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Sign Verify (n=128, pt=20, e=3) EXP",
			setup_generic, teardown_generic,
			PWCT_RSA_Sign_Verify, &RSA_vector_128_20_3_PKCS1),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Sign Verify (n=128, pt=20, e=3) CRT",
			setup_generic, teardown_generic,
			PWCT_RSA_Sign_Verify_CRT, &RSA_vector_128_20_3_PKCS1),
		/* Modular Exponentiation */
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=128, base=20, exp=3, res=128)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m128_b20_e3),
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=60, base=50, exp=40, res=60)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m60_b50_e40),
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=255, base=20, exp=10, res=255)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m255_b20_e10),
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=448, base=50, exp=40, res=448)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m448_b50_e40),
		/* Modular Multiplicative Inverse */
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Inverse (mod=128, base=20, exp=3, inv=128)",
			setup_generic, teardown_generic,
			modular_multiplicative_inverse, &modinv_test_case),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static struct unit_test_suite cryptodev_qat_asym_testsuite  = {
	.suite_name = "Crypto Device QAT ASYM Unit Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		/* RSA */
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Encryption (n=128, pt=20, e=3) EXP, Padding: NONE",
			setup_generic, teardown_generic,
			KAT_RSA_Encrypt, &RSA_vector_128_20_3_None),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Decryption (n=128, pt=20, e=3) EXP, Padding: NONE",
			setup_generic, teardown_generic,
			KAT_RSA_Decrypt, &RSA_vector_128_20_3_None),
		/* Modular Exponentiation */
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=128, base=20, exp=3, res=128)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m128_b20_e3),
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=60, base=50, exp=40, res=60)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m60_b50_e40),
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=255, base=20, exp=10, res=255)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m255_b20_e10),
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=448, base=50, exp=40, res=448)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m448_b50_e40),
		/* Modular Multiplicative Inverse */
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Inverse (mod=128, base=20, exp=3, inv=128)",
			setup_generic, teardown_generic,
			modular_multiplicative_inverse, &modinv_test_case),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static struct unit_test_suite cryptodev_octeontx_asym_testsuite  = {
	.suite_name = "Crypto Device OCTEONTX ASYM Unit Test Suite",
	.setup = testsuite_setup,
	.teardown = testsuite_teardown,
	.unit_test_cases = {
		TEST_CASE_ST(setup_generic, teardown_generic, test_capability),
		/* RSA */
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Encryption Decryption (n=128, pt=20, e=3) EXP",
			setup_generic, teardown_generic,
			PWCT_RSA_Encrypt_Decrypt, &RSA_vector_128_20_3_PKCS1),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Encryption Decryption (n=128, pt=20, e=3) CRT",
			setup_generic, teardown_generic,
			PWCT_RSA_CRT_Encrypt_Decrypt,
			&RSA_vector_128_20_3_PKCS1),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Sign Verify (n=128, pt=20, e=3) EXP",
			setup_generic, teardown_generic,
			PWCT_RSA_Sign_Verify, &RSA_vector_128_20_3_PKCS1),
		TEST_CASE_NAMED_WITH_DATA(
			"RSA Sign Verify (n=128, pt=20, e=3) CRT",
			setup_generic, teardown_generic,
			PWCT_RSA_Sign_Verify_CRT, &RSA_vector_128_20_3_PKCS1),
		TEST_CASE_ST(setup_generic, teardown_generic,
			     test_ecdsa_sign_verify_all_curve),
		TEST_CASE_ST(setup_generic, teardown_generic,
				test_ecpm_all_curve),
		/* Modular Exponentiation */
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=128, base=20, exp=3, res=128)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m128_b20_e3),
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=60, base=50, exp=40, res=60)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m60_b50_e40),
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=255, base=20, exp=10, res=255)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m255_b20_e10),
		TEST_CASE_NAMED_WITH_DATA(
			"Modular Exponentiation (mod=448, base=50, exp=40, res=448)",
			setup_generic, teardown_generic,
			modular_exponentiation, &modex_test_case_m448_b50_e40),
		TEST_CASES_END() /**< NULL terminate unit test array */
	}
};

static int
test_cryptodev_openssl_asym(void)
{
	gbl_driver_id = rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_OPENSSL_PMD));

	if (gbl_driver_id == -1) {
		RTE_LOG(ERR, USER1, "OPENSSL PMD must be loaded.\n");
		return TEST_SKIPPED;
	}

	return unit_test_suite_runner(&cryptodev_openssl_asym_testsuite);
}

static int
test_cryptodev_qat_asym(void)
{
	gbl_driver_id = rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_QAT_ASYM_PMD));

	if (gbl_driver_id == -1) {
		RTE_LOG(ERR, USER1, "QAT PMD must be loaded.\n");
		return TEST_SKIPPED;
	}

	return unit_test_suite_runner(&cryptodev_qat_asym_testsuite);
}

static int
test_cryptodev_octeontx_asym(void)
{
	gbl_driver_id = rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_OCTEONTX_SYM_PMD));
	if (gbl_driver_id == -1) {
		RTE_LOG(ERR, USER1, "OCTEONTX PMD must be loaded.\n");
		return TEST_SKIPPED;
	}
	return unit_test_suite_runner(&cryptodev_octeontx_asym_testsuite);
}

static int
test_cryptodev_cn9k_asym(void)
{
	gbl_driver_id = rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_CN9K_PMD));
	if (gbl_driver_id == -1) {
		RTE_LOG(ERR, USER1, "CN9K PMD must be loaded.\n");
		return TEST_SKIPPED;
	}

	/* Use test suite registered for crypto_octeontx PMD */
	return unit_test_suite_runner(&cryptodev_octeontx_asym_testsuite);
}

static int
test_cryptodev_cn10k_asym(void)
{
	gbl_driver_id = rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_CN10K_PMD));
	if (gbl_driver_id == -1) {
		RTE_LOG(ERR, USER1, "CN10K PMD must be loaded.\n");
		return TEST_SKIPPED;
	}

	/* Use test suite registered for crypto_octeontx PMD */
	return unit_test_suite_runner(&cryptodev_octeontx_asym_testsuite);
}

REGISTER_TEST_COMMAND(cryptodev_openssl_asym_autotest,
					  test_cryptodev_openssl_asym);

REGISTER_TEST_COMMAND(cryptodev_qat_asym_autotest, test_cryptodev_qat_asym);

REGISTER_TEST_COMMAND(cryptodev_octeontx_asym_autotest,
					  test_cryptodev_octeontx_asym);
REGISTER_TEST_COMMAND(cryptodev_cn9k_asym_autotest, test_cryptodev_cn9k_asym);
REGISTER_TEST_COMMAND(cryptodev_cn10k_asym_autotest, test_cryptodev_cn10k_asym);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */
#include <rte_cryptodev.h>
#include <rte_malloc.h>

#include "test.h"
#include "test_cryptodev.h"

#define MAX_NB_SESSIONS 1
#define MAX_TEST_STRING_LEN 256

/* Define list end for known algorithms */
#define CRYPTO_AUTH_MAX_IDX (RTE_CRYPTO_AUTH_SHA3_512_HMAC)
#define CRYPTO_CIPHER_MAX_IDX (RTE_CRYPTO_CIPHER_DES_DOCSISBPI)
#define CRYPTO_AEAD_MAX_IDX (RTE_CRYPTO_AEAD_CHACHA20_POLY1305)
#define CRYPTO_ALGOS_LEN (CRYPTO_AUTH_MAX_IDX + CRYPTO_CIPHER_MAX_IDX + CRYPTO_AEAD_MAX_IDX)

static struct rte_cryptodev_symmetric_capability common_symm_capas[CRYPTO_ALGOS_LEN];

static struct rte_cryptodev_symmetric_capability*
common_capability_get(int algo, enum rte_crypto_sym_xform_type xform_type)
{
	const int type_to_offset[] = {
		[RTE_CRYPTO_SYM_XFORM_AUTH] = 0,
		[RTE_CRYPTO_SYM_XFORM_CIPHER] = CRYPTO_AUTH_MAX_IDX,
		[RTE_CRYPTO_SYM_XFORM_AEAD] = CRYPTO_AUTH_MAX_IDX + CRYPTO_CIPHER_MAX_IDX,
	};

	return &common_symm_capas[type_to_offset[xform_type] + algo - 1];
}

enum capability_select_type {
	CAPABILITY_TYPE_MIN,
	CAPABILITY_TYPE_MAX,
	CAPABILITY_TYPE_LAST,
};

static const char * const capability_select_strings[] = {
	[CAPABILITY_TYPE_MIN] = "MIN",
	[CAPABILITY_TYPE_MAX] = "MAX",
};

static size_t input_length[] = { 64, 256, 512 };

static const char*
algo_name_get(const struct rte_cryptodev_symmetric_capability *capa)
{
	switch (capa->xform_type) {
	case RTE_CRYPTO_SYM_XFORM_AUTH:
		return rte_cryptodev_get_auth_algo_string(capa->auth.algo);
	case RTE_CRYPTO_SYM_XFORM_CIPHER:
		return rte_cryptodev_get_cipher_algo_string(capa->cipher.algo);
	case RTE_CRYPTO_SYM_XFORM_AEAD:
		return rte_cryptodev_get_aead_algo_string(capa->aead.algo);
	default:
		return NULL;
	}
}

/* Calculate number of test cases(combinations) per algorithm */
#define NB_TEST_CASES_PER_ALGO (CAPABILITY_TYPE_LAST * RTE_DIM(input_length))

enum crypto_op_type {
	OP_ENCRYPT,
	OP_DECRYPT,
};

struct crosscheck_test_profile {
	char name[MAX_TEST_STRING_LEN];
	size_t input_buf_len;
	uint16_t block_size;
	uint16_t key_size;
	uint8_t *key;
	uint16_t iv_size;
	uint8_t *iv;

	enum rte_crypto_sym_xform_type xform_type;
	union {
		struct {
			enum rte_crypto_auth_algorithm algo;
			uint16_t digest_size;
		} auth;
		struct {
			enum rte_crypto_cipher_algorithm algo;
			uint32_t dataunit_set;
		} cipher;
		struct {
			enum rte_crypto_aead_algorithm algo;
			uint16_t digest_size;
			uint16_t aad_size;
		} aead;
	};
};

struct meta_test_suite {
	char suite_name[MAX_TEST_STRING_LEN];
	struct crosscheck_test_profile profile[NB_TEST_CASES_PER_ALGO];
};

static struct crypto_testsuite_params testsuite_params;

static void
incrementing_generate(uint8_t *dst, uint8_t start, uint16_t size)
{
	int i;

	for (i = 0; i < size; i++)
		dst[i] = start + i;
}

static void
pattern_fill(uint8_t *input, const char *pattern, uint16_t size)
{
	size_t pattern_len = strlen(pattern);
	size_t filled_len = 0, to_fill;

	while (filled_len < size) {
		to_fill = RTE_MIN(pattern_len, size - filled_len);
		rte_memcpy(input, pattern, to_fill);
		filled_len += to_fill;
		input += to_fill;
	}
}

static struct crosscheck_test_profile
profile_create(struct rte_cryptodev_symmetric_capability *capa,
		enum capability_select_type capability_type, size_t input_len)
{
	struct crosscheck_test_profile profile;

	memset(&profile, 0, sizeof(profile));
	profile.xform_type = capa->xform_type;

	switch (capa->xform_type) {
	case RTE_CRYPTO_SYM_XFORM_AUTH:
		profile.block_size = capa->auth.block_size;
		profile.auth.algo = capa->auth.algo;

		switch (capability_type) {
		case CAPABILITY_TYPE_MIN:
			profile.key_size = capa->auth.key_size.min;
			profile.iv_size = capa->auth.iv_size.min;
			profile.auth.digest_size = capa->auth.digest_size.min;
			break;
		case CAPABILITY_TYPE_MAX:
			profile.key_size = capa->auth.key_size.max;
			profile.iv_size = capa->auth.iv_size.max;
			profile.auth.digest_size = capa->auth.digest_size.max;
			break;
		default:
			rte_panic("Wrong capability profile type: %i\n", capability_type);
			break;
		}
		break;
	case RTE_CRYPTO_SYM_XFORM_CIPHER:
		profile.block_size = capa->cipher.block_size;
		profile.cipher.algo = capa->cipher.algo;
		profile.cipher.dataunit_set = capa->cipher.dataunit_set;

		switch (capability_type) {
		case CAPABILITY_TYPE_MIN:
			profile.key_size = capa->cipher.key_size.min;
			profile.iv_size = capa->cipher.iv_size.min;
			break;
		case CAPABILITY_TYPE_MAX:
			profile.key_size = capa->cipher.key_size.max;
			profile.iv_size = capa->cipher.iv_size.max;
			break;
		default:
			rte_panic("Wrong capability profile type: %i\n", capability_type);
			break;
		}
		break;
	case RTE_CRYPTO_SYM_XFORM_AEAD:
		profile.block_size = capa->aead.block_size;
		profile.aead.algo = capa->aead.algo;

		switch (capability_type) {
		case CAPABILITY_TYPE_MIN:
			profile.key_size = capa->aead.key_size.min;
			profile.iv_size = capa->aead.iv_size.min;
			profile.aead.digest_size = capa->aead.digest_size.min;
			profile.aead.aad_size = capa->aead.aad_size.min;
			break;
		case CAPABILITY_TYPE_MAX:
			profile.key_size = capa->aead.key_size.max;
			profile.iv_size = capa->aead.iv_size.max;
			profile.aead.digest_size = capa->aead.digest_size.max;
			profile.aead.aad_size = capa->aead.aad_size.max;
			break;
		default:
			rte_panic("Wrong capability profile type: %i\n", capability_type);
			break;
		}
		break;
	default:
		rte_panic("Wrong xform profile type: %i\n", capa->xform_type);
		break;
	}

	profile.input_buf_len = RTE_ALIGN_CEIL(input_len, profile.block_size);

	if (profile.key_size) {
		profile.key = rte_zmalloc(NULL, profile.key_size, 0);
		RTE_VERIFY(profile.key != NULL);
		pattern_fill(profile.key, "*Secret key*", profile.key_size);
	}

	if (profile.iv_size) {
		profile.iv = rte_zmalloc(NULL, profile.iv_size, 0);
		RTE_VERIFY(profile.iv != NULL);
		pattern_fill(profile.iv, "IV ", profile.iv_size);
	}

	snprintf(profile.name, MAX_TEST_STRING_LEN,
			"'%s' - capabilities: '%s', input len: '%zu'",
			algo_name_get(capa), capability_select_strings[capability_type],
			input_len);

	return profile;
}

static inline int
common_range_set(struct rte_crypto_param_range *dst, const struct rte_crypto_param_range *src)
{
	/* Check if ranges overlaps */
	if ((dst->min > src->max) && (dst->max < src->min))
		return -1;
	dst->min = RTE_MAX(dst->min, src->min);
	dst->max = RTE_MIN(dst->max, src->max);

	return 0;
}

static void
capabilities_inspect(void)
{
	struct rte_cryptodev_sym_capability_idx cap_indexes[CRYPTO_ALGOS_LEN], *cap_idx;
	struct crypto_testsuite_params *ts_params = &testsuite_params;
	const struct rte_cryptodev_symmetric_capability *sym_capa;
	struct rte_cryptodev_symmetric_capability *common_capa;
	uint32_t algo, i, dev_id, caps_idx;

	caps_idx = 0;
	/* Create capability idx for known algorithms*/
	for (algo = 1; algo <= CRYPTO_AUTH_MAX_IDX; algo++) {
		cap_idx = &cap_indexes[caps_idx++];
		cap_idx->type = RTE_CRYPTO_SYM_XFORM_AUTH;
		cap_idx->algo.auth = algo;
	}
	for (algo = 1; algo <= CRYPTO_CIPHER_MAX_IDX; algo++) {
		cap_idx = &cap_indexes[caps_idx++];
		cap_idx->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
		cap_idx->algo.cipher = algo;
	}
	for (algo = 1; algo <= CRYPTO_AEAD_MAX_IDX; algo++) {
		cap_idx = &cap_indexes[caps_idx++];
		cap_idx->type = RTE_CRYPTO_SYM_XFORM_AEAD;
		cap_idx->algo.aead = algo;
	}

	for (caps_idx = 0; caps_idx < CRYPTO_ALGOS_LEN; caps_idx++) {
		/* Gather common capabilities */
		common_capa = &common_symm_capas[caps_idx];
		common_capa->xform_type = RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED;
		for (i = 0; i < ts_params->valid_dev_count; i++) {
			dev_id = ts_params->valid_devs[i];
			sym_capa = rte_cryptodev_sym_capability_get(dev_id,
					&cap_indexes[caps_idx]);
			if (sym_capa == NULL) {
				/* Capability not supported by one of devs, mark and skip */
				goto next_algo;
			}

			if (common_capa->xform_type == RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED) {
				/* First time initialization, copy data, go to next device  */
				*common_capa = *sym_capa;
				continue;
			}

			switch (sym_capa->xform_type) {
			case RTE_CRYPTO_SYM_XFORM_AUTH:
				if (common_capa->auth.algo != sym_capa->auth.algo)
					goto next_algo;

				if (common_capa->auth.block_size != sym_capa->auth.block_size)
					goto next_algo;

				if (common_range_set(&common_capa->auth.key_size,
							&sym_capa->auth.key_size))
					goto next_algo;
				if (common_range_set(&common_capa->auth.digest_size,
							&sym_capa->auth.digest_size))
					goto next_algo;
				if (common_range_set(&common_capa->auth.aad_size,
							&sym_capa->auth.aad_size))
					goto next_algo;
				if (common_range_set(&common_capa->auth.iv_size,
							&sym_capa->auth.iv_size))
					goto next_algo;
				break;
			case RTE_CRYPTO_SYM_XFORM_CIPHER:
				if (common_capa->cipher.algo != sym_capa->cipher.algo)
					goto next_algo;

				if (common_capa->cipher.block_size != sym_capa->cipher.block_size)
					goto next_algo;

				if (common_range_set(&common_capa->cipher.key_size,
							&sym_capa->cipher.key_size))
					goto next_algo;

				if (common_range_set(&common_capa->cipher.iv_size,
							&sym_capa->cipher.iv_size))
					goto next_algo;
				if (common_capa->cipher.dataunit_set !=
						sym_capa->cipher.dataunit_set)
					goto next_algo;
				break;
			case RTE_CRYPTO_SYM_XFORM_AEAD:
				if (common_capa->aead.algo != sym_capa->aead.algo)
					goto next_algo;

				if (common_capa->aead.block_size != sym_capa->aead.block_size)
					goto next_algo;

				if (common_range_set(&common_capa->aead.key_size,
							&sym_capa->aead.key_size))
					goto next_algo;
				if (common_range_set(&common_capa->aead.digest_size,
							&sym_capa->aead.digest_size))
					goto next_algo;
				if (common_range_set(&common_capa->aead.aad_size,
							&sym_capa->aead.aad_size))
					goto next_algo;
				if (common_range_set(&common_capa->aead.iv_size,
							&sym_capa->aead.iv_size))
					goto next_algo;
				break;
			default:
				RTE_LOG(ERR, USER1, "Unsupported xform_type!\n");
				goto next_algo;
			}
		}

		continue;
next_algo:
		common_capa->xform_type = RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED;
	}
}

static int
crosscheck_init(void)
{
	struct crypto_testsuite_params *ts_params = &testsuite_params;
	const uint32_t nb_queue_pairs = 1;
	struct rte_cryptodev_info info;
	uint32_t session_priv_size = 0;
	uint32_t nb_devs, dev_id;

	memset(ts_params, 0, sizeof(*ts_params));

	/* Create list of valid crypto devs */
	nb_devs = rte_cryptodev_count();
	for (dev_id = 0; dev_id < nb_devs; dev_id++) {
		rte_cryptodev_info_get(dev_id, &info);

		if (info.sym.max_nb_sessions != 0 && info.sym.max_nb_sessions < MAX_NB_SESSIONS)
			continue;
		if (info.max_nb_queue_pairs < nb_queue_pairs)
			continue;
		ts_params->valid_devs[ts_params->valid_dev_count++] = dev_id;
		/* Obtaining configuration parameters, that will satisfy all cryptodevs */
		session_priv_size = RTE_MAX(session_priv_size,
				rte_cryptodev_sym_get_private_session_size(dev_id));
	}

	if (ts_params->valid_dev_count < 2) {
		RTE_LOG(WARNING, USER1, "Min number of cryptodevs for test is 2, found (%d)\n",
				ts_params->valid_dev_count);
		return TEST_SKIPPED;
	}

	/* Create pools for mbufs, crypto operations and sessions */
	ts_params->mbuf_pool = rte_pktmbuf_pool_create("CRYPTO_MBUFPOOL", NUM_MBUFS,
			MBUF_CACHE_SIZE, 0, MBUF_SIZE, rte_socket_id());
	if (ts_params->mbuf_pool == NULL) {
		RTE_LOG(ERR, USER1, "Can't create CRYPTO_MBUFPOOL\n");
		return TEST_FAILED;
	}

	ts_params->op_mpool = rte_crypto_op_pool_create("MBUF_CRYPTO_SYM_OP_POOL",
			RTE_CRYPTO_OP_TYPE_SYMMETRIC, NUM_MBUFS, MBUF_CACHE_SIZE,
			DEFAULT_NUM_XFORMS * sizeof(struct rte_crypto_sym_xform) +
			MAXIMUM_IV_LENGTH, rte_socket_id());

	if (ts_params->op_mpool == NULL) {
		RTE_LOG(ERR, USER1, "Can't create CRYPTO_OP_POOL\n");
		return TEST_FAILED;
	}

	ts_params->session_mpool = rte_cryptodev_sym_session_pool_create("test_sess_mp",
			MAX_NB_SESSIONS, session_priv_size, 0, 0, SOCKET_ID_ANY);
	TEST_ASSERT_NOT_NULL(ts_params->session_mpool, "session mempool allocation failed");

	/* Setup queue pair conf params */
	ts_params->conf.nb_queue_pairs = nb_queue_pairs;
	ts_params->conf.socket_id = SOCKET_ID_ANY;
	ts_params->conf.ff_disable = RTE_CRYPTODEV_FF_SECURITY;
	ts_params->qp_conf.nb_descriptors = MAX_NUM_OPS_INFLIGHT;
	ts_params->qp_conf.mp_session = ts_params->session_mpool;

	capabilities_inspect();

	return TEST_SUCCESS;
}

static int
dev_configure_and_start(uint64_t ff_disable)
{
	struct crypto_testsuite_params *ts_params = &testsuite_params;
	uint8_t i, dev_id;
	uint16_t qp_id;

	/* Reconfigure device to default parameters */
	ts_params->conf.ff_disable = ff_disable;

	/* Configure cryptodevs */
	for (i = 0; i < ts_params->valid_dev_count; i++) {
		dev_id = ts_params->valid_devs[i];
		TEST_ASSERT_SUCCESS(rte_cryptodev_configure(dev_id, &ts_params->conf),
				"Failed to configure cryptodev %u with %u qps",
				dev_id, ts_params->conf.nb_queue_pairs);


		for (qp_id = 0; qp_id < ts_params->conf.nb_queue_pairs; qp_id++) {
			TEST_ASSERT_SUCCESS(rte_cryptodev_queue_pair_setup(
				dev_id, qp_id, &ts_params->qp_conf,
				rte_cryptodev_socket_id(dev_id)),
				"Failed to setup queue pair %u on cryptodev %u",
				qp_id, dev_id);
		}
		rte_cryptodev_stats_reset(dev_id);

		/* Start the device */
		TEST_ASSERT_SUCCESS(rte_cryptodev_start(dev_id), "Failed to start cryptodev %u",
				dev_id);
	}

	return TEST_SUCCESS;
}

static int
crosscheck_suite_setup(void)
{
	dev_configure_and_start(RTE_CRYPTODEV_FF_SECURITY);

	return 0;
}

static void
crosscheck_suite_teardown(void)
{
	struct crypto_testsuite_params *ts_params = &testsuite_params;
	uint8_t i, dev_id;

	for (i = 0; i < ts_params->valid_dev_count; i++) {
		dev_id = ts_params->valid_devs[i];
		rte_cryptodev_stop(dev_id);
	}
}

static struct rte_crypto_op *
crypto_request_process(uint8_t dev_id, struct rte_crypto_op *op)
{
	struct rte_crypto_op *res = NULL;

	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		RTE_LOG(ERR, USER1, "Error sending packet for encryption\n");
		return NULL;
	}

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &res, 1) == 0)
		rte_pause();

	if (res->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		RTE_LOG(ERR, USER1, "Operation status %d\n", res->status);
		return NULL;
	}

	if (res != op) {
		RTE_LOG(ERR, USER1, "Unexpected operation received!\n");
		rte_crypto_op_free(res);
		return NULL;
	}

	return res;
}

/* Create free room at the start of segment, by moving existing data further */
static uint8_t*
mbuf_room_create(struct rte_mbuf *m, size_t size)
{
	uint8_t *data;

	data = rte_pktmbuf_mtod(m, uint8_t*);
	memmove(data + size, data, m->data_len);
	m->data_len += size;
	m->pkt_len += size;

	return data;
}

static struct rte_cryptodev_sym_session*
session_create(const struct crosscheck_test_profile *profile, uint8_t dev_id,
		enum crypto_op_type op_type)
{
	struct rte_cryptodev_sym_session *session;
	struct rte_crypto_sym_xform xform;

	memset(&xform, 0, sizeof(xform));

	switch (profile->xform_type) {
	case RTE_CRYPTO_SYM_XFORM_AUTH:
		xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
		xform.next = NULL;
		xform.auth.algo = profile->auth.algo;
		xform.auth.op = op_type == OP_ENCRYPT ? RTE_CRYPTO_AUTH_OP_GENERATE :
			RTE_CRYPTO_AUTH_OP_VERIFY;
		xform.auth.digest_length = profile->auth.digest_size;
		xform.auth.key.length = profile->key_size;
		xform.auth.key.data = profile->key;
		xform.auth.iv.length = profile->iv_size;
		xform.auth.iv.offset = IV_OFFSET;
		break;
	case RTE_CRYPTO_SYM_XFORM_CIPHER:
		xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
		xform.next = NULL;
		xform.cipher.algo = profile->cipher.algo;
		xform.cipher.op = op_type == OP_ENCRYPT ? RTE_CRYPTO_CIPHER_OP_ENCRYPT :
			RTE_CRYPTO_CIPHER_OP_DECRYPT;
		xform.cipher.key.length = profile->key_size;
		xform.cipher.key.data = profile->key;
		xform.cipher.iv.length = profile->iv_size;
		xform.cipher.iv.offset = IV_OFFSET;
		break;
	case RTE_CRYPTO_SYM_XFORM_AEAD:
		xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
		xform.next = NULL;
		xform.aead.algo = profile->aead.algo;
		xform.aead.op = op_type == OP_ENCRYPT ? RTE_CRYPTO_AEAD_OP_ENCRYPT :
			RTE_CRYPTO_AEAD_OP_DECRYPT;
		xform.aead.digest_length = profile->aead.digest_size;
		xform.aead.key.length = profile->key_size;
		xform.aead.key.data = profile->key;
		xform.aead.iv.length = profile->iv_size;
		xform.aead.iv.offset = IV_OFFSET;
		xform.aead.aad_length = profile->aead.aad_size;
		break;
	default:
		return NULL;
	}

	session = rte_cryptodev_sym_session_create(dev_id, &xform, testsuite_params.session_mpool);

	return session;
}

static struct rte_mbuf*
mbuf_create(const uint8_t *input_buf, uint16_t input_len)
{
	struct rte_mbuf *pkt;
	uint8_t *pkt_data;

	pkt = rte_pktmbuf_alloc(testsuite_params.mbuf_pool);
	if (pkt == NULL) {
		RTE_LOG(ERR, USER1,  "Failed to allocate input buffer in mempool");
		return NULL;
	}

	/* zeroing tailroom */
	memset(rte_pktmbuf_mtod(pkt, uint8_t *), 0, rte_pktmbuf_tailroom(pkt));

	pkt_data = (uint8_t *)rte_pktmbuf_append(pkt, input_len);
	if (pkt_data == NULL) {
		RTE_LOG(ERR, USER1, "no room to append data, len: %d", input_len);
		goto error;
	}
	rte_memcpy(pkt_data, input_buf, input_len);

	return pkt;
error:
	rte_pktmbuf_free(pkt);
	return NULL;
}

static uint16_t
profile_digest_get(const struct crosscheck_test_profile *profile)
{
	switch (profile->xform_type) {
	case RTE_CRYPTO_SYM_XFORM_AUTH:
		return profile->auth.digest_size;
	case RTE_CRYPTO_SYM_XFORM_AEAD:
		return profile->aead.digest_size;
	default:
		return 0;
	}
}

static struct rte_crypto_op*
operation_create(const struct crosscheck_test_profile *profile,
		struct rte_mbuf *ibuf, enum crypto_op_type op_type)
{
	uint8_t *digest_data = NULL, *aad_data = NULL, *iv_ptr = NULL;
	uint16_t aad_size = 0, digest_size = 0, digest_offset = 0;
	uint16_t plaintext_len = profile->input_buf_len;
	rte_iova_t digest_addr = 0, aad_addr = 0;
	struct rte_crypto_sym_op *sym_op;
	struct rte_crypto_op *op;

	op = rte_crypto_op_alloc(testsuite_params.op_mpool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (op == NULL) {
		RTE_LOG(ERR, USER1, "Failed to allocate symmetric crypto operation struct");
		return NULL;
	}

	/* Obtain aad and digest sizes */
	digest_size = profile_digest_get(profile);
	if (profile->xform_type == RTE_CRYPTO_SYM_XFORM_AEAD)
		aad_size = profile->aead.aad_size;

	if (aad_size) {
		if (op_type == OP_ENCRYPT) {
			if (rte_pktmbuf_tailroom(ibuf) > plaintext_len + aad_size) {
				/* Put aad to data segment */
				aad_data = mbuf_room_create(ibuf, aad_size);
			} else {
				RTE_LOG(ERR, USER1, "No space for aad in single mbuf\n");
				goto error;
			}
			pattern_fill(aad_data, "This is an aad.", aad_size);
		} else {
			aad_data = rte_pktmbuf_mtod(ibuf, uint8_t *);
		}
		aad_addr = rte_pktmbuf_iova(ibuf);
	}

	if (digest_size) {
		digest_offset = aad_size + plaintext_len;
		if (op_type == OP_ENCRYPT) {
			digest_data = (uint8_t *)rte_pktmbuf_append(ibuf, digest_size);
			if (digest_data == NULL) {
				RTE_LOG(ERR, USER1, "No room to append digest\n");
				goto error;
			}
		} else {
			digest_data = rte_pktmbuf_mtod_offset(ibuf, uint8_t *, digest_offset);
		}
		digest_addr = rte_pktmbuf_iova_offset(ibuf, digest_offset);
	}

	sym_op = op->sym;
	memset(sym_op, 0, sizeof(*sym_op));

	iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
	rte_memcpy(iv_ptr, profile->iv, profile->iv_size);

	switch (profile->xform_type) {
	case RTE_CRYPTO_SYM_XFORM_AUTH:
		sym_op->auth.digest.phys_addr = digest_addr;
		sym_op->auth.digest.data = digest_data;
		sym_op->auth.data.length = plaintext_len;
		break;
	case RTE_CRYPTO_SYM_XFORM_CIPHER:
		sym_op->cipher.data.length = plaintext_len;
		break;
	case RTE_CRYPTO_SYM_XFORM_AEAD:
		sym_op->aead.aad.phys_addr = aad_addr;
		sym_op->aead.aad.data = aad_data;
		sym_op->aead.digest.phys_addr = digest_addr;
		sym_op->aead.digest.data = digest_data;
		sym_op->aead.data.offset = aad_size;
		sym_op->aead.data.length = plaintext_len;
		break;
	default:
		goto error;
	}

	sym_op->m_src = ibuf;

	return op;

error:
	rte_crypto_op_free(op);
	return NULL;
}

static void
mbuf_to_buf_copy(const struct rte_mbuf *m, uint8_t *res_buf, uint16_t *len)
{
	const uint8_t *out;

	*len = m->pkt_len;
	out = rte_pktmbuf_read(m, 0, *len, res_buf);
	/* Single segment buffer */
	if (out != res_buf)
		memcpy(res_buf, out, *len);
}

static int
single_dev_process(const struct crosscheck_test_profile *profile, uint16_t dev_id, enum
		crypto_op_type op_type, const uint8_t *input_buf, uint16_t input_len,
		uint8_t *output_buf, uint16_t *output_len)
{
	struct rte_cryptodev_sym_session *session = NULL;
	struct rte_mbuf *ibuf = NULL, *obuf = NULL;
	struct rte_crypto_op *op = NULL;
	int ret = -1;

	session = session_create(profile, dev_id, op_type);
	if (session == NULL)
		goto error;

	ibuf = mbuf_create(input_buf, input_len);
	if (ibuf == NULL)
		goto error;

	op = operation_create(profile, ibuf, op_type);
	if (op == NULL)
		goto error;

	debug_hexdump(stdout, "Input:", rte_pktmbuf_mtod(ibuf, uint8_t*), ibuf->pkt_len);

	rte_crypto_op_attach_sym_session(op, session);

	struct rte_crypto_op *res = crypto_request_process(dev_id, op);
	if (res == NULL)
		goto error;

	obuf = op->sym->m_src;
	if (obuf == NULL) {
		RTE_LOG(ERR, USER1, "Invalid packet received\n");
		goto error;
	}
	mbuf_to_buf_copy(obuf, output_buf, output_len);

	ret = 0;

error:
	if (session != NULL) {
		int sret;
		sret = rte_cryptodev_sym_session_free(dev_id, session);
		assert(sret == 0);
	}
	rte_pktmbuf_free(ibuf);
	rte_crypto_op_free(op);
	return ret;
}

static int
crosscheck_all_devices(const struct crosscheck_test_profile *profile, enum crypto_op_type op_type,
		const uint8_t *input_text, uint16_t input_len, uint8_t *output_text,
		uint16_t *output_len)
{
	struct crypto_testsuite_params *ts_params = &testsuite_params;
	uint16_t len = 0, expected_len = 0;
	uint8_t expected_text[MBUF_SIZE];
	uint8_t i, dev_id;
	int status;

	for (i = 0; i < ts_params->valid_dev_count; i++) {
		dev_id = ts_params->valid_devs[i];
		status = single_dev_process(profile, dev_id, op_type, input_text, input_len,
				output_text, &len);
		TEST_ASSERT_SUCCESS(status, "Error occurred during processing");

		if (i == 0) {
			/* First device, copy data for future comparisons */
			memcpy(expected_text, output_text, len);
			expected_len = len;
		} else {
			/* Compare output against expected(first) output */
			TEST_ASSERT_EQUAL(len, expected_len, "Length mismatch %d != %d !\n",
					len, expected_len);

			if (memcmp(output_text, expected_text, len)) {
				RTE_LOG(ERR, USER1, "Output mismatch between dev 0 and %i\n",
						dev_id);
				rte_hexdump(rte_log_get_stream(), "expected", expected_text, len);
				rte_hexdump(rte_log_get_stream(), "received", output_text, len);
				return TEST_FAILED;
			}
		}

		RTE_LOG(DEBUG, USER1, "DEV ID: %u finished processing\n", dev_id);
		debug_hexdump(stdout, "Output: ", output_text, len);
	}

	*output_len = len;

	return TEST_SUCCESS;
}

static int
check_negative_all_devices(const struct crosscheck_test_profile *profile,
		enum crypto_op_type op_type, const uint8_t *input_text, uint16_t input_len)
{
	struct crypto_testsuite_params *ts_params = &testsuite_params;
	uint8_t output_text[MBUF_SIZE];
	uint8_t i, dev_id;
	uint16_t len;
	int status;

	for (i = 0; i < ts_params->valid_dev_count; i++) {
		dev_id = ts_params->valid_devs[i];
		status = single_dev_process(profile, dev_id, op_type, input_text, input_len,
				output_text, &len);
		TEST_ASSERT_FAIL(status, "Error occurred during processing negative case");

	}

	return TEST_SUCCESS;
}

static int
crosscheck_with_profile_run(const struct crosscheck_test_profile *profile)
{
	uint8_t input_text[profile->input_buf_len];
	uint16_t output_len, encrypted_len;
	uint8_t encrypted_text[MBUF_SIZE];
	uint8_t output_text[MBUF_SIZE];
	int status;

	/* Encrypt Stage */
	RTE_LOG(DEBUG, USER1, "Executing encrypt stage\n");
	/* Fill input with incrementing pattern */
	incrementing_generate(input_text, 'a', profile->input_buf_len);
	status = crosscheck_all_devices(profile, OP_ENCRYPT, input_text, profile->input_buf_len,
			output_text, &output_len);
	TEST_ASSERT_SUCCESS(status, "Error occurred during encryption");

	/* Decrypt Stage */
	RTE_LOG(DEBUG, USER1, "Executing decrypt stage\n");
	/* Set up encrypted data as input */
	encrypted_len = output_len;
	memcpy(encrypted_text, output_text, output_len);
	status = crosscheck_all_devices(profile, OP_DECRYPT, encrypted_text, encrypted_len,
			output_text, &output_len);
	TEST_ASSERT_SUCCESS(status, "Error occurred during decryption");

	/* Negative Stage */
	RTE_LOG(DEBUG, USER1, "Executing negative stage\n");
	if (profile_digest_get(profile)) {
		/* Corrupting one byte of digest */
		encrypted_text[encrypted_len - 1] += 1;
		status = check_negative_all_devices(profile, OP_DECRYPT, encrypted_text,
				encrypted_len);
		TEST_ASSERT_SUCCESS(status, "Error occurred during decryption");
	}


	return TEST_SUCCESS;
}

static int
test_crosscheck_unit(const void *ptr)
{
	const struct crosscheck_test_profile *profile = ptr;

	if (profile->xform_type == RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED)
		return TEST_SKIPPED;

	return crosscheck_with_profile_run(profile);
}

static struct unit_test_suite*
sym_unit_test_suite_create(int algo, enum rte_crypto_sym_xform_type xform_type)
{
	struct rte_cryptodev_symmetric_capability *capabilities;
	size_t uts_size, total_size, input_sz;
	struct meta_test_suite *meta_ts;
	struct unit_test_suite *uts;
	const char *suite_prefix = NULL;
	const char *algo_name = NULL;
	uint64_t test_case_idx = 0;
	struct unit_test_case *utc;
	int cap_type;
	char *mem;

	switch (xform_type) {
	case RTE_CRYPTO_SYM_XFORM_AUTH:
		suite_prefix = "Algo AUTH ";
		algo_name = rte_cryptodev_get_auth_algo_string(algo);
		break;
	case RTE_CRYPTO_SYM_XFORM_CIPHER:
		suite_prefix = "Algo CIPHER";
		algo_name = rte_cryptodev_get_cipher_algo_string(algo);
		break;
	case RTE_CRYPTO_SYM_XFORM_AEAD:
		suite_prefix = "Algo AEAD";
		algo_name = rte_cryptodev_get_aead_algo_string(algo);
		break;
	default:
		return NULL;
	}

	/* Calculate size for test suite with all test cases +1 NULL case */
	uts_size = sizeof(struct unit_test_suite) +
		(NB_TEST_CASES_PER_ALGO + 1) * sizeof(struct unit_test_case);

	/* Also allocate memory for suite meta data */
	total_size = uts_size + sizeof(struct meta_test_suite);
	mem = rte_zmalloc(NULL, total_size, 0);
	if (mem == NULL)
		return NULL;
	uts = (struct unit_test_suite *) mem;
	meta_ts = (struct meta_test_suite *) (mem + uts_size);

	/* Initialize test suite */
	snprintf(meta_ts->suite_name, MAX_TEST_STRING_LEN, "%s '%s'", suite_prefix, algo_name);
	uts->suite_name = meta_ts->suite_name;

	capabilities = common_capability_get(algo, xform_type);
	if (capabilities->xform_type == 0) /* Skip case if current algo is not supported */
		return uts;

	/* Initialize test cases */

	for (cap_type = 0; cap_type < CAPABILITY_TYPE_LAST; cap_type++) {
		for (input_sz = 0; input_sz < RTE_DIM(input_length); input_sz++) {
			meta_ts->profile[test_case_idx] = profile_create(
					capabilities, cap_type, input_length[input_sz]);
			utc = &uts->unit_test_cases[test_case_idx];
			utc->name = meta_ts->profile[test_case_idx].name;
			utc->data = (const void *) &meta_ts->profile[test_case_idx];
			utc->testcase_with_data = test_crosscheck_unit;
			utc->enabled = true;

			test_case_idx += 1;
			RTE_VERIFY(test_case_idx <= NB_TEST_CASES_PER_ALGO);
		}
	}

	return uts;
}

static void
sym_unit_test_suite_free(struct unit_test_suite *suite)
{
	struct crosscheck_test_profile profile;
	struct unit_test_case *utc;
	int i;

	for (i = 0; suite->unit_test_cases[i].testcase_with_data; i++) {
		utc = &suite->unit_test_cases[i];
		profile = *(const struct crosscheck_test_profile *)utc->data;
		rte_free(profile.key);
		rte_free(profile.iv);
	}

	rte_free(suite);
}

static int
test_crosscheck(void)
{
	int ret, i, ts_idx = 0;
	static struct unit_test_suite ts = {
		.suite_name = "Crosscheck Unit Test Suite",
		.setup = crosscheck_suite_setup,
		.teardown = crosscheck_suite_teardown,
		.unit_test_cases = {TEST_CASES_END()}
	};
	struct unit_test_suite *test_suites[CRYPTO_ALGOS_LEN+1] = {0};/* 1 for NULL-end suite */

	/* Allocate all required memory pools and crosscheck cryptodev capabilities */
	ret = crosscheck_init();
	if (ret)
		return ret;

	/* Create test suite for each known algorithm */
	ts.unit_test_suites = test_suites;
	for (i = 1; i <= CRYPTO_AUTH_MAX_IDX; i++) {
		ts.unit_test_suites[ts_idx++] = sym_unit_test_suite_create(i,
				RTE_CRYPTO_SYM_XFORM_AUTH);
	}
	for (i = 1; i <= CRYPTO_CIPHER_MAX_IDX; i++) {
		ts.unit_test_suites[ts_idx++] = sym_unit_test_suite_create(i,
				RTE_CRYPTO_SYM_XFORM_CIPHER);
	}
	for (i = 1; i <= CRYPTO_AEAD_MAX_IDX; i++) {
		/* AES_CCM requires special handling due to api requirements, skip now */
		if (i == RTE_CRYPTO_AEAD_AES_CCM)
			continue;
		ts.unit_test_suites[ts_idx++] = sym_unit_test_suite_create(i,
				RTE_CRYPTO_SYM_XFORM_AEAD);
	}

	ret = unit_test_suite_runner(&ts);

	for (i = 0; i < ts_idx; i++)
		sym_unit_test_suite_free(ts.unit_test_suites[i]);

	return ret;
}

REGISTER_TEST_COMMAND(cryptodev_crosscheck, test_crosscheck);

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <time.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <rte_crypto.h>

#include "test_cryptodev_asym_rsa_creator.h"
#include "test_cryptodev_asym_creator.h"

static int rsa_result(RSA *rsa, struct asym_test_rsa_vct *vct,
		enum rte_crypto_rsa_padding_type padding)
{
	int clen, state = 0;
	int padding_rsa;
	unsigned char digest[SHA256_DIGEST_LENGTH];

	if (padding == RTE_CRYPTO_RSA_PADDING_PKCS1_5)
		padding_rsa = RSA_PKCS1_PADDING;
	else
		padding_rsa = RSA_NO_PADDING;

	clen = RSA_public_encrypt(vct->pt.len, vct->pt.data, vct->ct.data, rsa,
			padding_rsa);

	if (clen >= 0)
		vct->ct.len = clen;
	else
		goto err;

	unsigned char dec_buffer[ASYM_DATA_SIZE] = { 0 };
	clen = RSA_private_decrypt(vct->ct.len, vct->ct.data, dec_buffer, rsa,
			padding_rsa);

	if (memcmp(dec_buffer, vct->pt.data, vct->pt.len) != 0)
		goto err;

	SHA256(vct->pt.data, vct->pt.len, digest);

	if (padding_rsa == RSA_NO_PADDING) {
		int rsa_size = RSA_size(rsa);
		if (RSA_padding_add_PKCS1_type_1(vct->digest.data, rsa_size, digest,
				SHA256_DIGEST_LENGTH) != 1)
			goto err;

		vct->digest.len = rsa_size;
	} else {
		memcpy(vct->digest.data, digest, SHA256_DIGEST_LENGTH);
		vct->digest.len = SHA256_DIGEST_LENGTH;
	}

	clen = RSA_private_encrypt(vct->digest.len, vct->digest.data,
			vct->sign.data, rsa, padding_rsa);

	if (clen >= 0)
		vct->sign.len = clen;
	else
		goto err;

	state = 1;

err:
	return state;
}

int atv_rsa_creator(struct asym_test_rsa_vct *vct,
		struct asym_test_rsa_rule *rule)
{
	int ret;
	BN_CTX *ctx = NULL;
	RSA *rsa = NULL;
	BIGNUM *exp = NULL;

	const BIGNUM *n = NULL;
	const BIGNUM *e = NULL;
	const BIGNUM *p = NULL;
	const BIGNUM *d = NULL;
	const BIGNUM *q = NULL;
	const BIGNUM *dmp1 = NULL;
	const BIGNUM *dmq1 = NULL;
	const BIGNUM *iqmp = NULL;

	for (;;) {
		vct->pt.len = rule->pt_len;
		atv_create_data(vct->pt.data, vct->pt.len);
		vct->pt.data[0] = 0xAA;

		ctx = BN_CTX_new();
		rsa = RSA_new();
		exp = BN_new();

		ret = BN_set_word(exp, RSA_F4);
		if (ret == 0)
			goto err;

		ret = RSA_generate_key_ex(rsa, rule->key_size, exp, NULL);
		if (ret == 0)
			goto err;

		ret = rsa_result(rsa, vct, rule->padding);
		if (ret == 0)
			goto err;

		RSA_get0_key(rsa, &n, &e, &d);
		RSA_get0_factors(rsa, &p, &q);
		RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

		vct->n.len = BN_bn2bin(n, vct->n.data);
		vct->e.len = BN_bn2bin(e, vct->e.data);
		vct->d.len = BN_bn2bin(d, vct->d.data);
		vct->p.len = BN_bn2bin(p, vct->p.data);
		vct->q.len = BN_bn2bin(q, vct->q.data);

		vct->dP.len = BN_bn2bin(dmp1, vct->dP.data);
		vct->dQ.len = BN_bn2bin(dmq1, vct->dQ.data);
		vct->qInv.len = BN_bn2bin(iqmp, vct->qInv.data);

err:
		RSA_free(rsa);
		BN_free(exp);
		BN_CTX_free(ctx);

		if (ret == 1)
			break;
	}

	vct->xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;
	vct->padding = rule->padding,
	vct->op_type_flags = rule->operation;
	vct->key_exp = 1,
	vct->key_qt = 1,

	sprintf(vct->description, "RSA key size: %d bits", rule->key_size);
	return 0;
}

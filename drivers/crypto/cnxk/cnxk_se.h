/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _CNXK_SE_H_
#define _CNXK_SE_H_
#include <stdbool.h>

#include "roc_se.h"

struct cnxk_se_sess {
	uint16_t cpt_op : 4;
	uint16_t zsk_flag : 4;
	uint16_t aes_gcm : 1;
	uint16_t aes_ctr : 1;
	uint16_t chacha_poly : 1;
	uint16_t is_null : 1;
	uint16_t is_gmac : 1;
	uint16_t rsvd1 : 3;
	uint16_t aad_length;
	uint8_t mac_len;
	uint8_t iv_length;
	uint8_t auth_iv_length;
	uint16_t iv_offset;
	uint16_t auth_iv_offset;
	uint32_t salt;
	uint64_t cpt_inst_w7;
	struct roc_se_ctx roc_se_ctx;
} __rte_cache_aligned;

static uint8_t zuc_d[32] = {0x44, 0xD7, 0x26, 0xBC, 0x62, 0x6B, 0x13, 0x5E,
			    0x57, 0x89, 0x35, 0xE2, 0x71, 0x35, 0x09, 0xAF,
			    0x4D, 0x78, 0x2F, 0x13, 0x6B, 0xC4, 0x1A, 0xF1,
			    0x5E, 0x26, 0x3C, 0x4D, 0x78, 0x9A, 0x47, 0xAC};

static __rte_always_inline void
gen_key_snow3g(const uint8_t *ck, uint32_t *keyx)
{
	int i, base;

	for (i = 0; i < 4; i++) {
		base = 4 * i;
		keyx[3 - i] = (ck[base] << 24) | (ck[base + 1] << 16) |
			      (ck[base + 2] << 8) | (ck[base + 3]);
		keyx[3 - i] = rte_cpu_to_be_32(keyx[3 - i]);
	}
}

static __rte_always_inline int
cpt_mac_len_verify(struct rte_crypto_auth_xform *auth)
{
	uint16_t mac_len = auth->digest_length;
	int ret;

	switch (auth->algo) {
	case RTE_CRYPTO_AUTH_MD5:
	case RTE_CRYPTO_AUTH_MD5_HMAC:
		ret = (mac_len == 16) ? 0 : -1;
		break;
	case RTE_CRYPTO_AUTH_SHA1:
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		ret = (mac_len == 20) ? 0 : -1;
		break;
	case RTE_CRYPTO_AUTH_SHA224:
	case RTE_CRYPTO_AUTH_SHA224_HMAC:
		ret = (mac_len == 28) ? 0 : -1;
		break;
	case RTE_CRYPTO_AUTH_SHA256:
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
		ret = (mac_len == 32) ? 0 : -1;
		break;
	case RTE_CRYPTO_AUTH_SHA384:
	case RTE_CRYPTO_AUTH_SHA384_HMAC:
		ret = (mac_len == 48) ? 0 : -1;
		break;
	case RTE_CRYPTO_AUTH_SHA512:
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
		ret = (mac_len == 64) ? 0 : -1;
		break;
	case RTE_CRYPTO_AUTH_NULL:
		ret = 0;
		break;
	default:
		ret = -1;
	}

	return ret;
}

static __rte_always_inline void
cpt_fc_salt_update(struct roc_se_ctx *se_ctx, uint8_t *salt)
{
	struct roc_se_context *fctx = &se_ctx->se_ctx.fctx;
	memcpy(fctx->enc.encr_iv, salt, 4);
}

static __rte_always_inline int
cpt_fc_ciph_validate_key_aes(uint16_t key_len)
{
	switch (key_len) {
	case 16:
	case 24:
	case 32:
		return 0;
	default:
		return -1;
	}
}

static __rte_always_inline int
cpt_fc_ciph_set_type(roc_se_cipher_type type, struct roc_se_ctx *ctx,
		     uint16_t key_len)
{
	int fc_type = 0;
	switch (type) {
	case ROC_SE_PASSTHROUGH:
		fc_type = ROC_SE_FC_GEN;
		break;
	case ROC_SE_DES3_CBC:
	case ROC_SE_DES3_ECB:
		fc_type = ROC_SE_FC_GEN;
		break;
	case ROC_SE_AES_CBC:
	case ROC_SE_AES_ECB:
	case ROC_SE_AES_CFB:
	case ROC_SE_AES_CTR:
	case ROC_SE_AES_GCM:
		if (unlikely(cpt_fc_ciph_validate_key_aes(key_len) != 0))
			return -1;
		fc_type = ROC_SE_FC_GEN;
		break;
	case ROC_SE_CHACHA20:
		fc_type = ROC_SE_FC_GEN;
		break;
	case ROC_SE_AES_XTS:
		key_len = key_len / 2;
		if (unlikely(key_len == 24)) {
			CPT_LOG_DP_ERR("Invalid AES key len for XTS");
			return -1;
		}
		if (unlikely(cpt_fc_ciph_validate_key_aes(key_len) != 0))
			return -1;
		fc_type = ROC_SE_FC_GEN;
		break;
	case ROC_SE_ZUC_EEA3:
	case ROC_SE_SNOW3G_UEA2:
		if (unlikely(key_len != 16))
			return -1;
		/* No support for AEAD yet */
		if (unlikely(ctx->hash_type))
			return -1;
		fc_type = ROC_SE_PDCP;
		break;
	case ROC_SE_KASUMI_F8_CBC:
	case ROC_SE_KASUMI_F8_ECB:
		if (unlikely(key_len != 16))
			return -1;
		/* No support for AEAD yet */
		if (unlikely(ctx->hash_type))
			return -1;
		fc_type = ROC_SE_KASUMI;
		break;
	default:
		return -1;
	}

	ctx->fc_type = fc_type;
	return 0;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_passthrough(struct roc_se_ctx *se_ctx,
				struct roc_se_context *fctx)
{
	se_ctx->enc_cipher = 0;
	fctx->enc.enc_cipher = 0;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_set_aes_key_type(struct roc_se_context *fctx,
				     uint16_t key_len)
{
	roc_se_aes_type aes_key_type = 0;
	switch (key_len) {
	case 16:
		aes_key_type = ROC_SE_AES_128_BIT;
		break;
	case 24:
		aes_key_type = ROC_SE_AES_192_BIT;
		break;
	case 32:
		aes_key_type = ROC_SE_AES_256_BIT;
		break;
	default:
		/* This should not happen */
		CPT_LOG_DP_ERR("Invalid AES key len");
		return;
	}
	fctx->enc.aes_key = aes_key_type;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_snow3g_uea2(struct roc_se_ctx *se_ctx, const uint8_t *key,
				uint16_t key_len)
{
	struct roc_se_zuc_snow3g_ctx *zs_ctx = &se_ctx->se_ctx.zs_ctx;
	uint32_t keyx[4];

	se_ctx->pdcp_alg_type = ROC_SE_PDCP_ALG_TYPE_SNOW3G;
	gen_key_snow3g(key, keyx);
	memcpy(zs_ctx->ci_key, keyx, key_len);
	se_ctx->zsk_flags = 0;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_zuc_eea3(struct roc_se_ctx *se_ctx, const uint8_t *key,
			     uint16_t key_len)
{
	struct roc_se_zuc_snow3g_ctx *zs_ctx = &se_ctx->se_ctx.zs_ctx;

	se_ctx->pdcp_alg_type = ROC_SE_PDCP_ALG_TYPE_ZUC;
	memcpy(zs_ctx->ci_key, key, key_len);
	memcpy(zs_ctx->zuc_const, zuc_d, 32);
	se_ctx->zsk_flags = 0;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_kasumi_f8_ecb(struct roc_se_ctx *se_ctx, const uint8_t *key,
				  uint16_t key_len)
{
	struct roc_se_kasumi_ctx *k_ctx = &se_ctx->se_ctx.k_ctx;

	se_ctx->k_ecb = 1;
	memcpy(k_ctx->ci_key, key, key_len);
	se_ctx->zsk_flags = 0;
}

static __rte_always_inline void
cpt_fc_ciph_set_key_kasumi_f8_cbc(struct roc_se_ctx *se_ctx, const uint8_t *key,
				  uint16_t key_len)
{
	struct roc_se_kasumi_ctx *k_ctx = &se_ctx->se_ctx.k_ctx;

	memcpy(k_ctx->ci_key, key, key_len);
	se_ctx->zsk_flags = 0;
}

static __rte_always_inline int
cpt_fc_ciph_set_key(struct roc_se_ctx *se_ctx, roc_se_cipher_type type,
		    const uint8_t *key, uint16_t key_len, uint8_t *salt)
{
	struct roc_se_context *fctx = &se_ctx->se_ctx.fctx;
	int ret;

	ret = cpt_fc_ciph_set_type(type, se_ctx, key_len);
	if (unlikely(ret))
		return -1;

	if (se_ctx->fc_type == ROC_SE_FC_GEN) {
		/*
		 * We need to always say IV is from DPTR as user can
		 * sometimes iverride IV per operation.
		 */
		fctx->enc.iv_source = ROC_SE_FROM_DPTR;

		if (se_ctx->auth_key_len > 64)
			return -1;
	}

	switch (type) {
	case ROC_SE_PASSTHROUGH:
		cpt_fc_ciph_set_key_passthrough(se_ctx, fctx);
		goto success;
	case ROC_SE_DES3_CBC:
		/* CPT performs DES using 3DES with the 8B DES-key
		 * replicated 2 more times to match the 24B 3DES-key.
		 * Eg. If org. key is "0x0a 0x0b", then new key is
		 * "0x0a 0x0b 0x0a 0x0b 0x0a 0x0b"
		 */
		if (key_len == 8) {
			/* Skipping the first 8B as it will be copied
			 * in the regular code flow
			 */
			memcpy(fctx->enc.encr_key + key_len, key, key_len);
			memcpy(fctx->enc.encr_key + 2 * key_len, key, key_len);
		}
		break;
	case ROC_SE_DES3_ECB:
		/* For DES3_ECB IV need to be from CTX. */
		fctx->enc.iv_source = ROC_SE_FROM_CTX;
		break;
	case ROC_SE_AES_CBC:
	case ROC_SE_AES_ECB:
	case ROC_SE_AES_CFB:
	case ROC_SE_AES_CTR:
	case ROC_SE_CHACHA20:
		cpt_fc_ciph_set_key_set_aes_key_type(fctx, key_len);
		break;
	case ROC_SE_AES_GCM:
		/* Even though iv source is from dptr,
		 * aes_gcm salt is taken from ctx
		 */
		if (salt) {
			memcpy(fctx->enc.encr_iv, salt, 4);
			/* Assuming it was just salt update
			 * and nothing else
			 */
			if (!key)
				goto success;
		}
		cpt_fc_ciph_set_key_set_aes_key_type(fctx, key_len);
		break;
	case ROC_SE_AES_XTS:
		key_len = key_len / 2;
		cpt_fc_ciph_set_key_set_aes_key_type(fctx, key_len);

		/* Copy key2 for XTS into ipad */
		memset(fctx->hmac.ipad, 0, sizeof(fctx->hmac.ipad));
		memcpy(fctx->hmac.ipad, &key[key_len], key_len);
		break;
	case ROC_SE_SNOW3G_UEA2:
		cpt_fc_ciph_set_key_snow3g_uea2(se_ctx, key, key_len);
		goto success;
	case ROC_SE_ZUC_EEA3:
		cpt_fc_ciph_set_key_zuc_eea3(se_ctx, key, key_len);
		goto success;
	case ROC_SE_KASUMI_F8_ECB:
		cpt_fc_ciph_set_key_kasumi_f8_ecb(se_ctx, key, key_len);
		goto success;
	case ROC_SE_KASUMI_F8_CBC:
		cpt_fc_ciph_set_key_kasumi_f8_cbc(se_ctx, key, key_len);
		goto success;
	default:
		return -1;
	}

	/* Only for ROC_SE_FC_GEN case */

	/* For GMAC auth, cipher must be NULL */
	if (se_ctx->hash_type != ROC_SE_GMAC_TYPE)
		fctx->enc.enc_cipher = type;

	memcpy(fctx->enc.encr_key, key, key_len);

success:
	se_ctx->enc_cipher = type;

	return 0;
}

static __rte_always_inline int
cpt_fc_auth_set_key(struct roc_se_ctx *se_ctx, roc_se_auth_type type,
		    const uint8_t *key, uint16_t key_len, uint16_t mac_len)
{
	struct roc_se_zuc_snow3g_ctx *zs_ctx;
	struct roc_se_kasumi_ctx *k_ctx;
	struct roc_se_context *fctx;

	if (se_ctx == NULL)
		return -1;

	zs_ctx = &se_ctx->se_ctx.zs_ctx;
	k_ctx = &se_ctx->se_ctx.k_ctx;
	fctx = &se_ctx->se_ctx.fctx;

	if ((type >= ROC_SE_ZUC_EIA3) && (type <= ROC_SE_KASUMI_F9_ECB)) {
		uint32_t keyx[4];

		if (key_len != 16)
			return -1;
		/* No support for AEAD yet */
		if (se_ctx->enc_cipher)
			return -1;
		/* For ZUC/SNOW3G/Kasumi */
		switch (type) {
		case ROC_SE_SNOW3G_UIA2:
			se_ctx->pdcp_alg_type = ROC_SE_PDCP_ALG_TYPE_SNOW3G;
			gen_key_snow3g(key, keyx);
			memcpy(zs_ctx->ci_key, keyx, key_len);
			se_ctx->fc_type = ROC_SE_PDCP;
			se_ctx->zsk_flags = 0x1;
			break;
		case ROC_SE_ZUC_EIA3:
			se_ctx->pdcp_alg_type = ROC_SE_PDCP_ALG_TYPE_ZUC;
			memcpy(zs_ctx->ci_key, key, key_len);
			memcpy(zs_ctx->zuc_const, zuc_d, 32);
			se_ctx->fc_type = ROC_SE_PDCP;
			se_ctx->zsk_flags = 0x1;
			break;
		case ROC_SE_KASUMI_F9_ECB:
			/* Kasumi ECB mode */
			se_ctx->k_ecb = 1;
			memcpy(k_ctx->ci_key, key, key_len);
			se_ctx->fc_type = ROC_SE_KASUMI;
			se_ctx->zsk_flags = 0x1;
			break;
		case ROC_SE_KASUMI_F9_CBC:
			memcpy(k_ctx->ci_key, key, key_len);
			se_ctx->fc_type = ROC_SE_KASUMI;
			se_ctx->zsk_flags = 0x1;
			break;
		default:
			return -1;
		}
		se_ctx->mac_len = 4;
		se_ctx->hash_type = type;
		return 0;
	}

	if (!(se_ctx->fc_type == ROC_SE_FC_GEN && !type)) {
		if (!se_ctx->fc_type || !se_ctx->enc_cipher)
			se_ctx->fc_type = ROC_SE_HASH_HMAC;
	}

	if (se_ctx->fc_type == ROC_SE_FC_GEN && key_len > 64)
		return -1;

	/* For GMAC auth, cipher must be NULL */
	if (type == ROC_SE_GMAC_TYPE)
		fctx->enc.enc_cipher = 0;

	fctx->enc.hash_type = se_ctx->hash_type = type;
	fctx->enc.mac_len = se_ctx->mac_len = mac_len;

	if (key_len) {
		se_ctx->hmac = 1;
		memset(se_ctx->auth_key, 0, sizeof(se_ctx->auth_key));
		memcpy(se_ctx->auth_key, key, key_len);
		se_ctx->auth_key_len = key_len;
		memset(fctx->hmac.ipad, 0, sizeof(fctx->hmac.ipad));
		memset(fctx->hmac.opad, 0, sizeof(fctx->hmac.opad));

		if (key_len <= 64)
			memcpy(fctx->hmac.opad, key, key_len);
		fctx->enc.auth_input_type = 1;
	}
	return 0;
}

static __rte_always_inline int
fill_sess_aead(struct rte_crypto_sym_xform *xform, struct cnxk_se_sess *sess)
{
	struct rte_crypto_aead_xform *aead_form;
	roc_se_cipher_type enc_type = 0; /* NULL Cipher type */
	roc_se_auth_type auth_type = 0;	 /* NULL Auth type */
	uint32_t cipher_key_len = 0;
	uint8_t aes_gcm = 0;
	aead_form = &xform->aead;

	if (aead_form->op == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
		sess->cpt_op |= ROC_SE_OP_CIPHER_ENCRYPT;
		sess->cpt_op |= ROC_SE_OP_AUTH_GENERATE;
	} else if (aead_form->op == RTE_CRYPTO_AEAD_OP_DECRYPT) {
		sess->cpt_op |= ROC_SE_OP_CIPHER_DECRYPT;
		sess->cpt_op |= ROC_SE_OP_AUTH_VERIFY;
	} else {
		CPT_LOG_DP_ERR("Unknown aead operation\n");
		return -1;
	}
	switch (aead_form->algo) {
	case RTE_CRYPTO_AEAD_AES_GCM:
		enc_type = ROC_SE_AES_GCM;
		cipher_key_len = 16;
		aes_gcm = 1;
		break;
	case RTE_CRYPTO_AEAD_AES_CCM:
		CPT_LOG_DP_ERR("Crypto: Unsupported cipher algo %u",
			       aead_form->algo);
		return -1;
	case RTE_CRYPTO_AEAD_CHACHA20_POLY1305:
		enc_type = ROC_SE_CHACHA20;
		auth_type = ROC_SE_POLY1305;
		cipher_key_len = 32;
		sess->chacha_poly = 1;
		break;
	default:
		CPT_LOG_DP_ERR("Crypto: Undefined cipher algo %u specified",
			       aead_form->algo);
		return -1;
	}
	if (aead_form->key.length < cipher_key_len) {
		CPT_LOG_DP_ERR("Invalid cipher params keylen %u",
			       aead_form->key.length);
		return -1;
	}
	sess->zsk_flag = 0;
	sess->aes_gcm = aes_gcm;
	sess->mac_len = aead_form->digest_length;
	sess->iv_offset = aead_form->iv.offset;
	sess->iv_length = aead_form->iv.length;
	sess->aad_length = aead_form->aad_length;

	if (unlikely(cpt_fc_ciph_set_key(&sess->roc_se_ctx, enc_type,
					 aead_form->key.data,
					 aead_form->key.length, NULL)))
		return -1;

	if (unlikely(cpt_fc_auth_set_key(&sess->roc_se_ctx, auth_type, NULL, 0,
					 aead_form->digest_length)))
		return -1;

	return 0;
}

static __rte_always_inline int
fill_sess_cipher(struct rte_crypto_sym_xform *xform, struct cnxk_se_sess *sess)
{
	struct rte_crypto_cipher_xform *c_form;
	roc_se_cipher_type enc_type = 0; /* NULL Cipher type */
	uint32_t cipher_key_len = 0;
	uint8_t zsk_flag = 0, aes_ctr = 0, is_null = 0;

	c_form = &xform->cipher;

	if (c_form->op == RTE_CRYPTO_CIPHER_OP_ENCRYPT)
		sess->cpt_op |= ROC_SE_OP_CIPHER_ENCRYPT;
	else if (c_form->op == RTE_CRYPTO_CIPHER_OP_DECRYPT) {
		sess->cpt_op |= ROC_SE_OP_CIPHER_DECRYPT;
		if (xform->next != NULL &&
		    xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH) {
			/* Perform decryption followed by auth verify */
			sess->roc_se_ctx.template_w4.s.opcode_minor =
				ROC_SE_FC_MINOR_OP_HMAC_FIRST;
		}
	} else {
		CPT_LOG_DP_ERR("Unknown cipher operation\n");
		return -1;
	}

	switch (c_form->algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
		enc_type = ROC_SE_AES_CBC;
		cipher_key_len = 16;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		enc_type = ROC_SE_DES3_CBC;
		cipher_key_len = 24;
		break;
	case RTE_CRYPTO_CIPHER_DES_CBC:
		/* DES is implemented using 3DES in hardware */
		enc_type = ROC_SE_DES3_CBC;
		cipher_key_len = 8;
		break;
	case RTE_CRYPTO_CIPHER_AES_CTR:
		enc_type = ROC_SE_AES_CTR;
		cipher_key_len = 16;
		aes_ctr = 1;
		break;
	case RTE_CRYPTO_CIPHER_NULL:
		enc_type = 0;
		is_null = 1;
		break;
	case RTE_CRYPTO_CIPHER_KASUMI_F8:
		enc_type = ROC_SE_KASUMI_F8_ECB;
		cipher_key_len = 16;
		zsk_flag = ROC_SE_K_F8;
		break;
	case RTE_CRYPTO_CIPHER_SNOW3G_UEA2:
		enc_type = ROC_SE_SNOW3G_UEA2;
		cipher_key_len = 16;
		zsk_flag = ROC_SE_ZS_EA;
		break;
	case RTE_CRYPTO_CIPHER_ZUC_EEA3:
		enc_type = ROC_SE_ZUC_EEA3;
		cipher_key_len = 16;
		zsk_flag = ROC_SE_ZS_EA;
		break;
	case RTE_CRYPTO_CIPHER_AES_XTS:
		enc_type = ROC_SE_AES_XTS;
		cipher_key_len = 16;
		break;
	case RTE_CRYPTO_CIPHER_3DES_ECB:
		enc_type = ROC_SE_DES3_ECB;
		cipher_key_len = 24;
		break;
	case RTE_CRYPTO_CIPHER_AES_ECB:
		enc_type = ROC_SE_AES_ECB;
		cipher_key_len = 16;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CTR:
	case RTE_CRYPTO_CIPHER_AES_F8:
	case RTE_CRYPTO_CIPHER_ARC4:
		CPT_LOG_DP_ERR("Crypto: Unsupported cipher algo %u",
			       c_form->algo);
		return -1;
	default:
		CPT_LOG_DP_ERR("Crypto: Undefined cipher algo %u specified",
			       c_form->algo);
		return -1;
	}

	if (c_form->key.length < cipher_key_len) {
		CPT_LOG_DP_ERR("Invalid cipher params keylen %u",
			       c_form->key.length);
		return -1;
	}

	sess->zsk_flag = zsk_flag;
	sess->aes_gcm = 0;
	sess->aes_ctr = aes_ctr;
	sess->iv_offset = c_form->iv.offset;
	sess->iv_length = c_form->iv.length;
	sess->is_null = is_null;

	if (unlikely(cpt_fc_ciph_set_key(&sess->roc_se_ctx, enc_type,
					 c_form->key.data, c_form->key.length,
					 NULL)))
		return -1;

	return 0;
}

static __rte_always_inline int
fill_sess_auth(struct rte_crypto_sym_xform *xform, struct cnxk_se_sess *sess)
{
	struct rte_crypto_auth_xform *a_form;
	roc_se_auth_type auth_type = 0; /* NULL Auth type */
	uint8_t zsk_flag = 0, aes_gcm = 0, is_null = 0;

	if (xform->next != NULL &&
	    xform->next->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
	    xform->next->cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT) {
		/* Perform auth followed by encryption */
		sess->roc_se_ctx.template_w4.s.opcode_minor =
			ROC_SE_FC_MINOR_OP_HMAC_FIRST;
	}

	a_form = &xform->auth;

	if (a_form->op == RTE_CRYPTO_AUTH_OP_VERIFY)
		sess->cpt_op |= ROC_SE_OP_AUTH_VERIFY;
	else if (a_form->op == RTE_CRYPTO_AUTH_OP_GENERATE)
		sess->cpt_op |= ROC_SE_OP_AUTH_GENERATE;
	else {
		CPT_LOG_DP_ERR("Unknown auth operation");
		return -1;
	}

	switch (a_form->algo) {
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		/* Fall through */
	case RTE_CRYPTO_AUTH_SHA1:
		auth_type = ROC_SE_SHA1_TYPE;
		break;
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
	case RTE_CRYPTO_AUTH_SHA256:
		auth_type = ROC_SE_SHA2_SHA256;
		break;
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
	case RTE_CRYPTO_AUTH_SHA512:
		auth_type = ROC_SE_SHA2_SHA512;
		break;
	case RTE_CRYPTO_AUTH_AES_GMAC:
		auth_type = ROC_SE_GMAC_TYPE;
		aes_gcm = 1;
		break;
	case RTE_CRYPTO_AUTH_SHA224_HMAC:
	case RTE_CRYPTO_AUTH_SHA224:
		auth_type = ROC_SE_SHA2_SHA224;
		break;
	case RTE_CRYPTO_AUTH_SHA384_HMAC:
	case RTE_CRYPTO_AUTH_SHA384:
		auth_type = ROC_SE_SHA2_SHA384;
		break;
	case RTE_CRYPTO_AUTH_MD5_HMAC:
	case RTE_CRYPTO_AUTH_MD5:
		auth_type = ROC_SE_MD5_TYPE;
		break;
	case RTE_CRYPTO_AUTH_KASUMI_F9:
		auth_type = ROC_SE_KASUMI_F9_ECB;
		/*
		 * Indicate that direction needs to be taken out
		 * from end of src
		 */
		zsk_flag = ROC_SE_K_F9;
		break;
	case RTE_CRYPTO_AUTH_SNOW3G_UIA2:
		auth_type = ROC_SE_SNOW3G_UIA2;
		zsk_flag = ROC_SE_ZS_IA;
		break;
	case RTE_CRYPTO_AUTH_ZUC_EIA3:
		auth_type = ROC_SE_ZUC_EIA3;
		zsk_flag = ROC_SE_ZS_IA;
		break;
	case RTE_CRYPTO_AUTH_NULL:
		auth_type = 0;
		is_null = 1;
		break;
	case RTE_CRYPTO_AUTH_AES_XCBC_MAC:
	case RTE_CRYPTO_AUTH_AES_CMAC:
	case RTE_CRYPTO_AUTH_AES_CBC_MAC:
		CPT_LOG_DP_ERR("Crypto: Unsupported hash algo %u",
			       a_form->algo);
		return -1;
	default:
		CPT_LOG_DP_ERR("Crypto: Undefined Hash algo %u specified",
			       a_form->algo);
		return -1;
	}

	sess->zsk_flag = zsk_flag;
	sess->aes_gcm = aes_gcm;
	sess->mac_len = a_form->digest_length;
	sess->is_null = is_null;
	if (zsk_flag) {
		sess->auth_iv_offset = a_form->iv.offset;
		sess->auth_iv_length = a_form->iv.length;
	}
	if (unlikely(cpt_fc_auth_set_key(&sess->roc_se_ctx, auth_type,
					 a_form->key.data, a_form->key.length,
					 a_form->digest_length)))
		return -1;

	return 0;
}

static __rte_always_inline int
fill_sess_gmac(struct rte_crypto_sym_xform *xform, struct cnxk_se_sess *sess)
{
	struct rte_crypto_auth_xform *a_form;
	roc_se_cipher_type enc_type = 0; /* NULL Cipher type */
	roc_se_auth_type auth_type = 0;	 /* NULL Auth type */

	a_form = &xform->auth;

	if (a_form->op == RTE_CRYPTO_AUTH_OP_GENERATE)
		sess->cpt_op |= ROC_SE_OP_ENCODE;
	else if (a_form->op == RTE_CRYPTO_AUTH_OP_VERIFY)
		sess->cpt_op |= ROC_SE_OP_DECODE;
	else {
		CPT_LOG_DP_ERR("Unknown auth operation");
		return -1;
	}

	switch (a_form->algo) {
	case RTE_CRYPTO_AUTH_AES_GMAC:
		enc_type = ROC_SE_AES_GCM;
		auth_type = ROC_SE_GMAC_TYPE;
		break;
	default:
		CPT_LOG_DP_ERR("Crypto: Undefined cipher algo %u specified",
			       a_form->algo);
		return -1;
	}

	sess->zsk_flag = 0;
	sess->aes_gcm = 0;
	sess->is_gmac = 1;
	sess->iv_offset = a_form->iv.offset;
	sess->iv_length = a_form->iv.length;
	sess->mac_len = a_form->digest_length;

	if (unlikely(cpt_fc_ciph_set_key(&sess->roc_se_ctx, enc_type,
					 a_form->key.data, a_form->key.length,
					 NULL)))
		return -1;

	if (unlikely(cpt_fc_auth_set_key(&sess->roc_se_ctx, auth_type, NULL, 0,
					 a_form->digest_length)))
		return -1;

	return 0;
}

#endif /*_CNXK_SE_H_ */

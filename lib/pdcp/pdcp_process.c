/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_memcpy.h>
#include <rte_pdcp.h>
#include <rte_pdcp_hdr.h>

#include "pdcp_crypto.h"
#include "pdcp_entity.h"
#include "pdcp_process.h"

#define PDCP_MAC_I_LEN 4

/* Enum of supported algorithms for ciphering */
enum pdcp_cipher_algo {
	PDCP_CIPHER_ALGO_NULL,
	PDCP_CIPHER_ALGO_AES,
	PDCP_CIPHER_ALGO_ZUC,
	PDCP_CIPHER_ALGO_SNOW3G,
	PDCP_CIPHER_ALGO_MAX
};

/* Enum of supported algorithms for integrity */
enum pdcp_auth_algo {
	PDCP_AUTH_ALGO_NULL,
	PDCP_AUTH_ALGO_AES,
	PDCP_AUTH_ALGO_ZUC,
	PDCP_AUTH_ALGO_SNOW3G,
	PDCP_AUTH_ALGO_MAX
};

/* IV generation functions based on type of operation (cipher - auth) */

static void
pdcp_iv_gen_null_null(struct rte_crypto_op *cop, const struct entity_priv *en_priv, uint32_t count)
{
	/* No IV required for NULL cipher + NULL auth */
	RTE_SET_USED(cop);
	RTE_SET_USED(en_priv);
	RTE_SET_USED(count);
}

static void
pdcp_iv_gen_null_aes_cmac(struct rte_crypto_op *cop, const struct entity_priv *en_priv,
			  uint32_t count)
{
	struct rte_crypto_sym_op *op = cop->sym;
	struct rte_mbuf *mb = op->m_src;
	uint8_t *m_ptr;
	uint64_t m;

	/* AES-CMAC requires message to be prepended with info on count etc */

	/* Prepend by 8 bytes to add custom message */
	m_ptr = (uint8_t *)rte_pktmbuf_prepend(mb, 8);

	m = en_priv->auth_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));

	rte_memcpy(m_ptr, &m, 8);
}

static void
pdcp_iv_gen_null_zs(struct rte_crypto_op *cop, const struct entity_priv *en_priv, uint32_t count)
{
	uint64_t iv_u64[2];
	uint8_t *iv;

	iv = rte_crypto_op_ctod_offset(cop, uint8_t *, PDCP_IV_OFFSET);

	iv_u64[0] = en_priv->auth_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	rte_memcpy(iv, &iv_u64[0], 8);

	iv_u64[1] = iv_u64[0] ^ en_priv->auth_iv_part.u64[1];
	rte_memcpy(iv + 8, &iv_u64[1], 8);
}

static void
pdcp_iv_gen_aes_ctr_null(struct rte_crypto_op *cop, const struct entity_priv *en_priv,
			 uint32_t count)
{
	uint64_t iv_u64[2];
	uint8_t *iv;

	iv = rte_crypto_op_ctod_offset(cop, uint8_t *, PDCP_IV_OFFSET);

	iv_u64[0] = en_priv->cipher_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	iv_u64[1] = 0;
	rte_memcpy(iv, iv_u64, 16);
}

static void
pdcp_iv_gen_zs_null(struct rte_crypto_op *cop, const struct entity_priv *en_priv, uint32_t count)
{
	uint64_t iv_u64;
	uint8_t *iv;

	iv = rte_crypto_op_ctod_offset(cop, uint8_t *, PDCP_IV_OFFSET);

	iv_u64 = en_priv->cipher_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	rte_memcpy(iv, &iv_u64, 8);
	rte_memcpy(iv + 8, &iv_u64, 8);
}

static void
pdcp_iv_gen_zs_zs(struct rte_crypto_op *cop, const struct entity_priv *en_priv, uint32_t count)
{
	uint64_t iv_u64[2];
	uint8_t *iv;

	iv = rte_crypto_op_ctod_offset(cop, uint8_t *, PDCP_IV_OFFSET);

	/* Generating cipher IV */
	iv_u64[0] = en_priv->cipher_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	rte_memcpy(iv, &iv_u64[0], 8);
	rte_memcpy(iv + 8, &iv_u64[0], 8);

	iv += PDCP_IV_LENGTH;

	/* Generating auth IV */
	iv_u64[0] = en_priv->auth_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	rte_memcpy(iv, &iv_u64[0], 8);

	iv_u64[1] = iv_u64[0] ^ en_priv->auth_iv_part.u64[1];
	rte_memcpy(iv + 8, &iv_u64[1], 8);
}

static void
pdcp_iv_gen_zs_aes_cmac(struct rte_crypto_op *cop, const struct entity_priv *en_priv,
			uint32_t count)
{
	struct rte_crypto_sym_op *op = cop->sym;
	struct rte_mbuf *mb = op->m_src;
	uint8_t *m_ptr, *iv;
	uint64_t iv_u64[2];
	uint64_t m;

	iv = rte_crypto_op_ctod_offset(cop, uint8_t *, PDCP_IV_OFFSET);
	iv_u64[0] = en_priv->cipher_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	rte_memcpy(iv, &iv_u64[0], 8);
	rte_memcpy(iv + 8, &iv_u64[0], 8);

	m_ptr = (uint8_t *)rte_pktmbuf_prepend(mb, 8);
	m = en_priv->auth_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	rte_memcpy(m_ptr, &m, 8);
}

static void
pdcp_iv_gen_aes_ctr_aes_cmac(struct rte_crypto_op *cop, const struct entity_priv *en_priv,
			    uint32_t count)
{
	struct rte_crypto_sym_op *op = cop->sym;
	struct rte_mbuf *mb = op->m_src;
	uint8_t *m_ptr, *iv;
	uint64_t iv_u64[2];
	uint64_t m;

	iv = rte_crypto_op_ctod_offset(cop, uint8_t *, PDCP_IV_OFFSET);

	iv_u64[0] = en_priv->cipher_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	iv_u64[1] = 0;
	rte_memcpy(iv, iv_u64, PDCP_IV_LENGTH);

	m_ptr = (uint8_t *)rte_pktmbuf_prepend(mb, 8);
	m = en_priv->auth_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	rte_memcpy(m_ptr, &m, 8);
}

static void
pdcp_iv_gen_aes_ctr_zs(struct rte_crypto_op *cop, const struct entity_priv *en_priv, uint32_t count)
{
	uint64_t iv_u64[2];
	uint8_t *iv;

	iv = rte_crypto_op_ctod_offset(cop, uint8_t *, PDCP_IV_OFFSET);

	iv_u64[0] = en_priv->cipher_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	iv_u64[1] = 0;
	rte_memcpy(iv, iv_u64, PDCP_IV_LENGTH);

	iv += PDCP_IV_LENGTH;

	iv_u64[0] = en_priv->auth_iv_part.u64[0] | ((uint64_t)(rte_cpu_to_be_32(count)));
	rte_memcpy(iv, &iv_u64[0], 8);

	iv_u64[1] = iv_u64[0] ^ en_priv->auth_iv_part.u64[1];
	rte_memcpy(iv + 8, &iv_u64[1], 8);
}

static int
pdcp_crypto_xfrm_get(const struct rte_pdcp_entity_conf *conf, struct rte_crypto_sym_xform **c_xfrm,
		     struct rte_crypto_sym_xform **a_xfrm)
{
	*c_xfrm = NULL;
	*a_xfrm = NULL;

	if (conf->crypto_xfrm == NULL)
		return -EINVAL;

	if (conf->crypto_xfrm->type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
		*c_xfrm = conf->crypto_xfrm;
		*a_xfrm = conf->crypto_xfrm->next;
	} else if (conf->crypto_xfrm->type == RTE_CRYPTO_SYM_XFORM_AUTH) {
		*a_xfrm = conf->crypto_xfrm;
		*c_xfrm = conf->crypto_xfrm->next;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int
pdcp_iv_gen_func_set(struct rte_pdcp_entity *entity, const struct rte_pdcp_entity_conf *conf)
{
	struct rte_crypto_sym_xform *c_xfrm, *a_xfrm;
	enum rte_security_pdcp_direction direction;
	enum pdcp_cipher_algo ciph_algo;
	enum pdcp_auth_algo auth_algo;
	struct entity_priv *en_priv;
	int ret;

	en_priv = entity_priv_get(entity);

	direction = conf->pdcp_xfrm.pkt_dir;
	if (conf->reverse_iv_direction)
		direction = !direction;

	ret = pdcp_crypto_xfrm_get(conf, &c_xfrm, &a_xfrm);
	if (ret)
		return ret;

	if (c_xfrm == NULL)
		return -EINVAL;

	memset(&en_priv->auth_iv_part, 0, sizeof(en_priv->auth_iv_part));
	memset(&en_priv->cipher_iv_part, 0, sizeof(en_priv->cipher_iv_part));

	switch (c_xfrm->cipher.algo) {
	case RTE_CRYPTO_CIPHER_NULL:
		ciph_algo = PDCP_CIPHER_ALGO_NULL;
		break;
	case RTE_CRYPTO_CIPHER_AES_CTR:
		ciph_algo = PDCP_CIPHER_ALGO_AES;
		en_priv->cipher_iv_part.aes_ctr.bearer = conf->pdcp_xfrm.bearer;
		en_priv->cipher_iv_part.aes_ctr.direction = direction;
		break;
	case RTE_CRYPTO_CIPHER_SNOW3G_UEA2:
		ciph_algo = PDCP_CIPHER_ALGO_SNOW3G;
		en_priv->cipher_iv_part.zs.bearer = conf->pdcp_xfrm.bearer;
		en_priv->cipher_iv_part.zs.direction = direction;
		break;
	case RTE_CRYPTO_CIPHER_ZUC_EEA3:
		ciph_algo = PDCP_CIPHER_ALGO_ZUC;
		en_priv->cipher_iv_part.zs.bearer = conf->pdcp_xfrm.bearer;
		en_priv->cipher_iv_part.zs.direction = direction;
		break;
	default:
		return -ENOTSUP;
	}

	if (a_xfrm != NULL) {
		switch (a_xfrm->auth.algo) {
		case RTE_CRYPTO_AUTH_NULL:
			auth_algo = PDCP_AUTH_ALGO_NULL;
			break;
		case RTE_CRYPTO_AUTH_AES_CMAC:
			auth_algo = PDCP_AUTH_ALGO_AES;
			en_priv->auth_iv_part.aes_cmac.bearer = conf->pdcp_xfrm.bearer;
			en_priv->auth_iv_part.aes_cmac.direction = direction;
			break;
		case RTE_CRYPTO_AUTH_SNOW3G_UIA2:
			auth_algo = PDCP_AUTH_ALGO_SNOW3G;
			en_priv->auth_iv_part.zs.bearer = conf->pdcp_xfrm.bearer;
			en_priv->auth_iv_part.zs.direction_64 = direction;
			en_priv->auth_iv_part.zs.direction_112 = direction;
			break;
		case RTE_CRYPTO_AUTH_ZUC_EIA3:
			auth_algo = PDCP_AUTH_ALGO_ZUC;
			en_priv->auth_iv_part.zs.bearer = conf->pdcp_xfrm.bearer;
			en_priv->auth_iv_part.zs.direction_64 = direction;
			en_priv->auth_iv_part.zs.direction_112 = direction;
			break;
		default:
			return -ENOTSUP;
		}
	} else {
		auth_algo = PDCP_AUTH_ALGO_NULL;
	}

	static const iv_gen_t iv_gen_map[PDCP_CIPHER_ALGO_MAX][PDCP_AUTH_ALGO_MAX] = {
		[PDCP_CIPHER_ALGO_NULL][PDCP_AUTH_ALGO_NULL] = pdcp_iv_gen_null_null,
		[PDCP_CIPHER_ALGO_NULL][PDCP_AUTH_ALGO_AES] = pdcp_iv_gen_null_aes_cmac,
		[PDCP_CIPHER_ALGO_NULL][PDCP_AUTH_ALGO_SNOW3G] = pdcp_iv_gen_null_zs,
		[PDCP_CIPHER_ALGO_NULL][PDCP_AUTH_ALGO_ZUC] = pdcp_iv_gen_null_zs,

		[PDCP_CIPHER_ALGO_AES][PDCP_AUTH_ALGO_NULL] = pdcp_iv_gen_aes_ctr_null,
		[PDCP_CIPHER_ALGO_AES][PDCP_AUTH_ALGO_AES] = pdcp_iv_gen_aes_ctr_aes_cmac,
		[PDCP_CIPHER_ALGO_AES][PDCP_AUTH_ALGO_SNOW3G] = pdcp_iv_gen_aes_ctr_zs,
		[PDCP_CIPHER_ALGO_AES][PDCP_AUTH_ALGO_ZUC] = pdcp_iv_gen_aes_ctr_zs,

		[PDCP_CIPHER_ALGO_SNOW3G][PDCP_AUTH_ALGO_NULL] = pdcp_iv_gen_zs_null,
		[PDCP_CIPHER_ALGO_SNOW3G][PDCP_AUTH_ALGO_AES] = pdcp_iv_gen_zs_aes_cmac,
		[PDCP_CIPHER_ALGO_SNOW3G][PDCP_AUTH_ALGO_SNOW3G] = pdcp_iv_gen_zs_zs,
		[PDCP_CIPHER_ALGO_SNOW3G][PDCP_AUTH_ALGO_ZUC] = pdcp_iv_gen_zs_zs,

		[PDCP_CIPHER_ALGO_ZUC][PDCP_AUTH_ALGO_NULL] = pdcp_iv_gen_zs_null,
		[PDCP_CIPHER_ALGO_ZUC][PDCP_AUTH_ALGO_AES] = pdcp_iv_gen_zs_aes_cmac,
		[PDCP_CIPHER_ALGO_ZUC][PDCP_AUTH_ALGO_SNOW3G] = pdcp_iv_gen_zs_zs,
		[PDCP_CIPHER_ALGO_ZUC][PDCP_AUTH_ALGO_ZUC] = pdcp_iv_gen_zs_zs,
	};

	en_priv->iv_gen = iv_gen_map[ciph_algo][auth_algo];

	return 0;
}

static inline void
cop_prepare(const struct entity_priv *en_priv, struct rte_mbuf *mb, struct rte_crypto_op *cop,
	    uint8_t data_offset, uint32_t count, const bool is_auth)
{
	const struct rte_crypto_op cop_init = {
		.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED,
		.sess_type = RTE_CRYPTO_OP_WITH_SESSION,
	};
	struct rte_crypto_sym_op *op;
	uint32_t pkt_len;

	const uint8_t ciph_shift = 3 * en_priv->flags.is_ciph_in_bits;
	const uint8_t auth_shift = 3 * en_priv->flags.is_auth_in_bits;

	op = cop->sym;
	cop->raw = cop_init.raw;
	op->m_src = mb;
	op->m_dst = mb;

	/* Set IV */
	en_priv->iv_gen(cop, en_priv, count);

	/* Prepare op */
	pkt_len = rte_pktmbuf_pkt_len(mb);
	op->cipher.data.offset = data_offset << ciph_shift;
	op->cipher.data.length = (pkt_len - data_offset) << ciph_shift;

	if (is_auth) {
		op->auth.data.offset = 0;
		op->auth.data.length = (pkt_len - PDCP_MAC_I_LEN) << auth_shift;
		op->auth.digest.data = rte_pktmbuf_mtod_offset(mb, uint8_t *,
							       (pkt_len - PDCP_MAC_I_LEN));
	}

	__rte_crypto_sym_op_attach_sym_session(op, en_priv->crypto_sess);
}

static inline bool
pdcp_pre_process_uplane_sn_12_ul_set_sn(struct entity_priv *en_priv, struct rte_mbuf *mb,
					uint32_t *count)
{
	struct rte_pdcp_up_data_pdu_sn_12_hdr *pdu_hdr;
	const uint8_t hdr_sz = en_priv->hdr_sz;
	uint32_t sn;

	/* Prepend PDU header */
	pdu_hdr = (struct rte_pdcp_up_data_pdu_sn_12_hdr *)rte_pktmbuf_prepend(mb, hdr_sz);
	if (unlikely(pdu_hdr == NULL))
		return false;

	/* Update sequence num in the PDU header */
	*count = __atomic_fetch_add(&en_priv->state.tx_next, 1, __ATOMIC_RELAXED);
	sn = PDCP_GET_SN_12_FROM_COUNT(*count);

	pdu_hdr->d_c = PDCP_PDU_TYPE_DATA;
	pdu_hdr->sn_11_8 = ((sn & 0xf00) >> 8);
	pdu_hdr->sn_7_0 = (sn & 0xff);
	pdu_hdr->r = 0;
	return true;
}

static uint16_t
pdcp_pre_process_uplane_sn_12_ul(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				 struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	uint16_t nb_cop;
	uint32_t count;
	int i;

	const uint8_t data_offset = en_priv->hdr_sz + en_priv->aad_sz;

	nb_cop = rte_crypto_op_bulk_alloc(en_priv->cop_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, cop,
					  num);

	if (en_priv->flags.is_authenticated) {
		for (i = 0; i < nb_cop; i++) {
			if (unlikely(rte_pktmbuf_append(mb[i], PDCP_MAC_I_LEN) == NULL))
				goto cop_free;
			if (unlikely(!pdcp_pre_process_uplane_sn_12_ul_set_sn(en_priv, mb[i],
									      &count)))
				goto cop_free;
			cop_prepare(en_priv, mb[i], cop[i], data_offset, count, true);
		}
	} else {
		for (i = 0; i < nb_cop; i++) {
			if (unlikely(!pdcp_pre_process_uplane_sn_12_ul_set_sn(en_priv, mb[i],
									      &count)))
				goto cop_free;
			cop_prepare(en_priv, mb[i], cop[i], data_offset, count, false);
		}
	}

	*nb_err = num - nb_cop;
	return nb_cop;
cop_free:
	/* Using mempool API since crypto API is not providing bulk free */
	rte_mempool_put_bulk(en_priv->cop_pool, (void *)&cop[i], nb_cop - i);
	*nb_err = num - i;
	return i;
}

static inline bool
pdcp_pre_process_uplane_sn_18_ul_set_sn(struct entity_priv *en_priv, struct rte_mbuf *mb,
					uint32_t *count)
{
	struct rte_pdcp_up_data_pdu_sn_18_hdr *pdu_hdr;
	const uint8_t hdr_sz = en_priv->hdr_sz;
	uint32_t sn;

	/* Prepend PDU header */
	pdu_hdr = (struct rte_pdcp_up_data_pdu_sn_18_hdr *)rte_pktmbuf_prepend(mb, hdr_sz);
	if (unlikely(pdu_hdr == NULL))
		return false;

	/* Update sequence num in the PDU header */
	*count = __atomic_fetch_add(&en_priv->state.tx_next, 1, __ATOMIC_RELAXED);
	sn = PDCP_GET_SN_18_FROM_COUNT(*count);

	pdu_hdr->d_c = PDCP_PDU_TYPE_DATA;
	pdu_hdr->sn_17_16 = ((sn & 0x30000) >> 16);
	pdu_hdr->sn_15_8 = ((sn & 0xff00) >> 8);
	pdu_hdr->sn_7_0 = (sn & 0xff);
	pdu_hdr->r = 0;

	return true;
}

static inline uint16_t
pdcp_pre_process_uplane_sn_18_ul(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				 struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	uint16_t nb_cop;
	uint32_t count;
	int i;

	const uint8_t data_offset = en_priv->hdr_sz + en_priv->aad_sz;

	nb_cop = rte_crypto_op_bulk_alloc(en_priv->cop_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, cop,
					  num);

	if (en_priv->flags.is_authenticated) {
		for (i = 0; i < nb_cop; i++) {
			if (unlikely(rte_pktmbuf_append(mb[i], PDCP_MAC_I_LEN) == NULL))
				goto cop_free;
			if (unlikely(!pdcp_pre_process_uplane_sn_18_ul_set_sn(en_priv, mb[i],
									      &count)))
				goto cop_free;
			cop_prepare(en_priv, mb[i], cop[i], data_offset, count, true);
		}
	} else {
		for (i = 0; i < nb_cop; i++) {
			if (unlikely(!pdcp_pre_process_uplane_sn_18_ul_set_sn(en_priv, mb[i],
									      &count)))
				goto cop_free;
			cop_prepare(en_priv, mb[i], cop[i], data_offset, count, false);
		}
	}

	*nb_err = num - nb_cop;
	return nb_cop;

cop_free:
	/* Using mempool API since crypto API is not providing bulk free */
	rte_mempool_put_bulk(en_priv->cop_pool, (void *)&cop[i], nb_cop - i);
	*nb_err = num - i;
	return i;
}

static uint16_t
pdcp_pre_process_cplane_sn_12_ul(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				 struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	struct rte_pdcp_cp_data_pdu_sn_12_hdr *pdu_hdr;
	uint32_t count, sn;
	uint16_t nb_cop;
	int i;

	const uint8_t hdr_sz = en_priv->hdr_sz;
	const uint8_t data_offset = hdr_sz + en_priv->aad_sz;

	nb_cop = rte_crypto_op_bulk_alloc(en_priv->cop_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, cop,
					  num);

	for (i = 0; i < nb_cop; i++) {
		/* Prepend PDU header */
		pdu_hdr = (struct rte_pdcp_cp_data_pdu_sn_12_hdr *)rte_pktmbuf_prepend(mb[i],
										       hdr_sz);
		if (unlikely(pdu_hdr == NULL))
			goto cop_free;
		if (unlikely(rte_pktmbuf_append(mb[i], PDCP_MAC_I_LEN) == NULL))
			goto cop_free;

		/* Update sequence number in the PDU header */
		count = __atomic_fetch_add(&en_priv->state.tx_next, 1, __ATOMIC_RELAXED);
		sn = PDCP_GET_SN_12_FROM_COUNT(count);

		pdu_hdr->sn_11_8 = ((sn & 0xf00) >> 8);
		pdu_hdr->sn_7_0 = (sn & 0xff);
		pdu_hdr->r = 0;

		cop_prepare(en_priv, mb[i], cop[i], data_offset, count, true);
	}

	*nb_err = num - nb_cop;
	return nb_cop;

cop_free:
	/* Using mempool API since crypto API is not providing bulk free */
	rte_mempool_put_bulk(en_priv->cop_pool, (void *)&cop[i], nb_cop - i);
	*nb_err = num - i;
	return i;
}

static uint16_t
pdcp_post_process_uplane_sn_12_ul(const struct rte_pdcp_entity *entity,
				  struct rte_mbuf *in_mb[],
				  struct rte_mbuf *out_mb[],
				  uint16_t num, uint16_t *nb_err_ret)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	const uint32_t hdr_trim_sz = en_priv->aad_sz;
	int i, nb_success = 0, nb_err = 0;
	struct rte_mbuf *err_mb[num];
	struct rte_mbuf *mb;

	for (i = 0; i < num; i++) {
		mb = in_mb[i];
		if (unlikely(mb->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED)) {
			err_mb[nb_err++] = mb;
			continue;
		}

		if (hdr_trim_sz)
			rte_pktmbuf_adj(mb, hdr_trim_sz);

		out_mb[nb_success++] = mb;
	}

	if (unlikely(nb_err != 0))
		rte_memcpy(&out_mb[nb_success], err_mb, nb_err * sizeof(struct rte_mbuf *));

	*nb_err_ret = nb_err;
	return nb_success;
}

static uint16_t
pdcp_post_process_uplane_sn_18_ul(const struct rte_pdcp_entity *entity,
				  struct rte_mbuf *in_mb[],
				  struct rte_mbuf *out_mb[],
				  uint16_t num, uint16_t *nb_err_ret)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	const uint32_t hdr_trim_sz = en_priv->aad_sz;
	int i, nb_success = 0, nb_err = 0;
	struct rte_mbuf *err_mb[num];
	struct rte_mbuf *mb;

	for (i = 0; i < num; i++) {
		mb = in_mb[i];
		if (unlikely(mb->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED)) {
			err_mb[nb_err++] = mb;
			continue;
		}

		if (hdr_trim_sz)
			rte_pktmbuf_adj(mb, hdr_trim_sz);

		out_mb[nb_success++] = mb;
	}

	if (unlikely(nb_err != 0))
		rte_memcpy(&out_mb[nb_success], err_mb, nb_err * sizeof(struct rte_mbuf *));

	*nb_err_ret = nb_err;
	return nb_success;
}

static uint16_t
pdcp_post_process_cplane_sn_12_ul(const struct rte_pdcp_entity *entity,
				  struct rte_mbuf *in_mb[],
				  struct rte_mbuf *out_mb[],
				  uint16_t num, uint16_t *nb_err_ret)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	const uint32_t hdr_trim_sz = en_priv->aad_sz;
	int i, nb_success = 0, nb_err = 0;
	struct rte_mbuf *mb, *err_mb[num];

	for (i = 0; i < num; i++) {
		mb = in_mb[i];
		if (unlikely(mb->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED)) {
			err_mb[nb_err++] = mb;
			continue;
		}

		if (hdr_trim_sz)
			rte_pktmbuf_adj(mb, hdr_trim_sz);

		out_mb[nb_success++] = mb;
	}

	if (unlikely(nb_err != 0))
		rte_memcpy(&out_mb[nb_success], err_mb, nb_err * sizeof(struct rte_mbuf *));

	*nb_err_ret = nb_err;
	return nb_success;
}

static inline int
pdcp_sn_18_count_get(const struct rte_pdcp_entity *entity, int32_t rsn, uint32_t *count)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	uint32_t rhfn, rx_deliv;

	rx_deliv = __atomic_load_n(&en_priv->state.rx_deliv, __ATOMIC_RELAXED);
	rhfn = PDCP_GET_HFN_SN_18_FROM_COUNT(rx_deliv);

	if (rsn < (int32_t)(PDCP_GET_SN_18_FROM_COUNT(rx_deliv) - PDCP_SN_18_WINDOW_SZ)) {
		if (unlikely(rhfn == PDCP_SN_18_HFN_MAX))
			return -ERANGE;
		rhfn += 1;
	} else if ((uint32_t)rsn >= (PDCP_GET_SN_18_FROM_COUNT(rx_deliv) + PDCP_SN_18_WINDOW_SZ)) {
		if (unlikely(rhfn == PDCP_SN_18_HFN_MIN))
			return -ERANGE;
		rhfn -= 1;
	}

	*count = PDCP_SET_COUNT_FROM_HFN_SN_18(rhfn, rsn);

	return 0;
}

static inline int
pdcp_sn_12_count_get(const struct rte_pdcp_entity *entity, int32_t rsn, uint32_t *count)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	uint32_t rhfn, rx_deliv;

	rx_deliv = __atomic_load_n(&en_priv->state.rx_deliv, __ATOMIC_RELAXED);
	rhfn = PDCP_GET_HFN_SN_12_FROM_COUNT(rx_deliv);

	if (rsn < (int32_t)(PDCP_GET_SN_12_FROM_COUNT(rx_deliv) - PDCP_SN_12_WINDOW_SZ)) {
		if (unlikely(rhfn == PDCP_SN_12_HFN_MAX))
			return -ERANGE;
		rhfn += 1;
	} else if ((uint32_t)rsn >= (PDCP_GET_SN_12_FROM_COUNT(rx_deliv) + PDCP_SN_12_WINDOW_SZ)) {
		if (unlikely(rhfn == PDCP_SN_12_HFN_MIN))
			return -ERANGE;
		rhfn -= 1;
	}

	*count = PDCP_SET_COUNT_FROM_HFN_SN_12(rhfn, rsn);

	return 0;
}

static inline uint16_t
pdcp_pre_process_uplane_sn_12_dl_flags(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				       struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err,
				       const bool is_integ_protected)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	struct rte_pdcp_up_data_pdu_sn_12_hdr *pdu_hdr;
	uint16_t nb_cop;
	int32_t rsn = 0;
	uint32_t count;
	int i;

	const uint8_t data_offset = en_priv->hdr_sz + en_priv->aad_sz;

	nb_cop = rte_crypto_op_bulk_alloc(en_priv->cop_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, cop,
					  num);

	for (i = 0; i < nb_cop; i++) {

		pdu_hdr = rte_pktmbuf_mtod(mb[i], struct rte_pdcp_up_data_pdu_sn_12_hdr *);

		/* Check for PDU type */
		if (likely(pdu_hdr->d_c == PDCP_PDU_TYPE_DATA))
			rsn = ((pdu_hdr->sn_11_8 << 8) | (pdu_hdr->sn_7_0));
		else
			rte_panic("TODO: Control PDU not handled");

		if (unlikely(pdcp_sn_12_count_get(entity, rsn, &count)))
			break;
		cop_prepare(en_priv, mb[i], cop[i], data_offset, count, is_integ_protected);
	}

	*nb_err = num - nb_cop;

	return nb_cop;
}

static uint16_t
pdcp_pre_process_uplane_sn_12_dl_ip(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				    struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err)
{
	return pdcp_pre_process_uplane_sn_12_dl_flags(entity, mb, cop, num, nb_err, true);
}

static uint16_t
pdcp_pre_process_uplane_sn_12_dl(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				 struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err)
{
	return pdcp_pre_process_uplane_sn_12_dl_flags(entity, mb, cop, num, nb_err, false);
}

static inline uint16_t
pdcp_pre_process_uplane_sn_18_dl_flags(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				       struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err,
				       const bool is_integ_protected)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	struct rte_pdcp_up_data_pdu_sn_18_hdr *pdu_hdr;
	uint16_t nb_cop;
	int32_t rsn = 0;
	uint32_t count;
	int i;

	const uint8_t data_offset = en_priv->hdr_sz + en_priv->aad_sz;
	nb_cop = rte_crypto_op_bulk_alloc(en_priv->cop_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, cop,
					  num);

	for (i = 0; i < nb_cop; i++) {
		pdu_hdr = rte_pktmbuf_mtod(mb[i], struct rte_pdcp_up_data_pdu_sn_18_hdr *);

		/* Check for PDU type */
		if (likely(pdu_hdr->d_c == PDCP_PDU_TYPE_DATA))
			rsn = ((pdu_hdr->sn_17_16 << 16) | (pdu_hdr->sn_15_8 << 8) |
			       (pdu_hdr->sn_7_0));
		else
			rte_panic("TODO: Control PDU not handled");

		if (unlikely(pdcp_sn_18_count_get(entity, rsn, &count)))
			break;
		cop_prepare(en_priv, mb[i], cop[i], data_offset, count, is_integ_protected);
	}

	*nb_err = num - nb_cop;

	return nb_cop;
}

static uint16_t
pdcp_pre_process_uplane_sn_18_dl_ip(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				    struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err)
{
	return pdcp_pre_process_uplane_sn_18_dl_flags(entity, mb, cop, num, nb_err, true);
}

static uint16_t
pdcp_pre_process_uplane_sn_18_dl(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				 struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err)
{
	return pdcp_pre_process_uplane_sn_18_dl_flags(entity, mb, cop, num, nb_err, false);
}

static uint16_t
pdcp_pre_process_cplane_sn_12_dl(const struct rte_pdcp_entity *entity, struct rte_mbuf *mb[],
				 struct rte_crypto_op *cop[], uint16_t num, uint16_t *nb_err)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	struct rte_pdcp_cp_data_pdu_sn_12_hdr *pdu_hdr;
	uint16_t nb_cop;
	uint32_t count;
	int32_t rsn;
	int i;

	const uint8_t data_offset = en_priv->hdr_sz + en_priv->aad_sz;

	nb_cop = rte_crypto_op_bulk_alloc(en_priv->cop_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC, cop,
					  num);

	for (i = 0; i < nb_cop; i++) {
		pdu_hdr = rte_pktmbuf_mtod(mb[i], struct rte_pdcp_cp_data_pdu_sn_12_hdr *);
		rsn = ((pdu_hdr->sn_11_8 << 8) | (pdu_hdr->sn_7_0));
		if (unlikely(pdcp_sn_12_count_get(entity, rsn, &count)))
			break;
		cop_prepare(en_priv, mb[i], cop[i], data_offset, count, true);
	}

	*nb_err = num - nb_cop;
	return nb_cop;
}

static inline bool
pdcp_post_process_update_entity_state(const struct rte_pdcp_entity *entity,
				      const uint32_t count)
{
	struct entity_priv *en_priv = entity_priv_get(entity);

	if (count < __atomic_load_n(&en_priv->state.rx_deliv, __ATOMIC_RELAXED))
		return false;

	/* t-Reordering timer is not supported - SDU will be delivered immediately.
	 * Update RX_DELIV to the COUNT value of the first PDCP SDU which has not
	 * been delivered to upper layers
	 */
	__atomic_store_n(&en_priv->state.rx_deliv, (count + 1), __ATOMIC_RELAXED);

	if (count >= __atomic_load_n(&en_priv->state.rx_next, __ATOMIC_RELAXED))
		__atomic_store_n(&en_priv->state.rx_next, (count + 1), __ATOMIC_RELAXED);

	return true;
}

static inline uint16_t
pdcp_post_process_uplane_sn_12_dl_flags(const struct rte_pdcp_entity *entity,
					struct rte_mbuf *in_mb[],
					struct rte_mbuf *out_mb[],
					uint16_t num, uint16_t *nb_err_ret,
					const bool is_integ_protected)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	struct rte_pdcp_up_data_pdu_sn_12_hdr *pdu_hdr;
	int i, nb_success = 0, nb_err = 0, rsn = 0;
	const uint32_t aad_sz = en_priv->aad_sz;
	struct rte_mbuf *err_mb[num];
	struct rte_mbuf *mb;
	uint32_t count;

	const uint32_t hdr_trim_sz = en_priv->hdr_sz + aad_sz;

	for (i = 0; i < num; i++) {
		mb = in_mb[i];
		if (unlikely(mb->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED))
			goto error;
		pdu_hdr = rte_pktmbuf_mtod_offset(mb, struct rte_pdcp_up_data_pdu_sn_12_hdr *,
						  aad_sz);

		/* Check for PDU type */
		if (likely(pdu_hdr->d_c == PDCP_PDU_TYPE_DATA))
			rsn = ((pdu_hdr->sn_11_8 << 8) | (pdu_hdr->sn_7_0));
		else
			rte_panic("Control PDU should not be received");

		if (unlikely(pdcp_sn_12_count_get(entity, rsn, &count)))
			goto error;

		if (unlikely(!pdcp_post_process_update_entity_state(entity, count)))
			goto error;

		rte_pktmbuf_adj(mb, hdr_trim_sz);
		if (is_integ_protected)
			rte_pktmbuf_trim(mb, PDCP_MAC_I_LEN);
		out_mb[nb_success++] = mb;
		continue;

error:
		err_mb[nb_err++] = mb;
	}

	if (unlikely(nb_err != 0))
		rte_memcpy(&out_mb[nb_success], err_mb, nb_err * sizeof(struct rte_mbuf *));

	*nb_err_ret = nb_err;
	return nb_success;
}

static uint16_t
pdcp_post_process_uplane_sn_12_dl_ip(const struct rte_pdcp_entity *entity,
				     struct rte_mbuf *in_mb[],
				     struct rte_mbuf *out_mb[],
				     uint16_t num, uint16_t *nb_err)
{
	return pdcp_post_process_uplane_sn_12_dl_flags(entity, in_mb, out_mb, num, nb_err, true);
}

static uint16_t
pdcp_post_process_uplane_sn_12_dl(const struct rte_pdcp_entity *entity,
				  struct rte_mbuf *in_mb[],
				  struct rte_mbuf *out_mb[],
				  uint16_t num, uint16_t *nb_err)
{
	return pdcp_post_process_uplane_sn_12_dl_flags(entity, in_mb, out_mb, num, nb_err, false);
}

static inline uint16_t
pdcp_post_process_uplane_sn_18_dl_flags(const struct rte_pdcp_entity *entity,
					struct rte_mbuf *in_mb[],
					struct rte_mbuf *out_mb[],
					uint16_t num, uint16_t *nb_err_ret,
					const bool is_integ_protected)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	struct rte_pdcp_up_data_pdu_sn_18_hdr *pdu_hdr;
	const uint32_t aad_sz = en_priv->aad_sz;
	int i, nb_success = 0, nb_err = 0;
	struct rte_mbuf *mb, *err_mb[num];
	int32_t rsn = 0;
	uint32_t count;

	const uint32_t hdr_trim_sz = en_priv->hdr_sz + aad_sz;

	for (i = 0; i < num; i++) {
		mb = in_mb[i];
		if (unlikely(mb->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED))
			goto error;

		pdu_hdr = rte_pktmbuf_mtod_offset(mb, struct rte_pdcp_up_data_pdu_sn_18_hdr *,
						  aad_sz);

		/* Check for PDU type */
		if (likely(pdu_hdr->d_c == PDCP_PDU_TYPE_DATA))
			rsn = ((pdu_hdr->sn_17_16 << 16) | (pdu_hdr->sn_15_8 << 8) |
			       (pdu_hdr->sn_7_0));
		else
			rte_panic("Control PDU should not be received");

		if (unlikely(pdcp_sn_18_count_get(entity, rsn, &count)))
			goto error;

		if (unlikely(!pdcp_post_process_update_entity_state(entity, count)))
			goto error;

		rte_pktmbuf_adj(mb, hdr_trim_sz);
		if (is_integ_protected)
			rte_pktmbuf_trim(mb, PDCP_MAC_I_LEN);
		out_mb[nb_success++] = mb;
		continue;

error:
		err_mb[nb_err++] = mb;
	}

	if (unlikely(nb_err != 0))
		rte_memcpy(&out_mb[nb_success], err_mb, nb_err * sizeof(struct rte_mbuf *));

	*nb_err_ret = nb_err;
	return nb_success;
}

static uint16_t
pdcp_post_process_uplane_sn_18_dl_ip(const struct rte_pdcp_entity *entity,
				     struct rte_mbuf *in_mb[],
				     struct rte_mbuf *out_mb[],
				     uint16_t num, uint16_t *nb_err)
{
	return pdcp_post_process_uplane_sn_18_dl_flags(entity, in_mb, out_mb, num, nb_err, true);
}

static uint16_t
pdcp_post_process_uplane_sn_18_dl(const struct rte_pdcp_entity *entity,
				  struct rte_mbuf *in_mb[],
				  struct rte_mbuf *out_mb[],
				  uint16_t num, uint16_t *nb_err)
{
	return pdcp_post_process_uplane_sn_18_dl_flags(entity, in_mb, out_mb, num, nb_err, false);
}

static uint16_t
pdcp_post_process_cplane_sn_12_dl(const struct rte_pdcp_entity *entity,
				  struct rte_mbuf *in_mb[],
				  struct rte_mbuf *out_mb[],
				  uint16_t num, uint16_t *nb_err_ret)
{
	struct entity_priv *en_priv = entity_priv_get(entity);
	struct rte_pdcp_cp_data_pdu_sn_12_hdr *pdu_hdr;
	const uint32_t aad_sz = en_priv->aad_sz;
	int i, nb_success = 0, nb_err = 0;
	struct rte_mbuf *err_mb[num];
	struct rte_mbuf *mb;
	uint32_t count;
	int32_t rsn;

	const uint32_t hdr_trim_sz = en_priv->hdr_sz + aad_sz;

	for (i = 0; i < num; i++) {
		mb = in_mb[i];
		if (unlikely(mb->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED))
			goto error;

		pdu_hdr = rte_pktmbuf_mtod_offset(mb, struct rte_pdcp_cp_data_pdu_sn_12_hdr *,
						  aad_sz);
		rsn = ((pdu_hdr->sn_11_8 << 8) | (pdu_hdr->sn_7_0));

		if (unlikely(pdcp_sn_12_count_get(entity, rsn, &count)))
			goto error;

		if (unlikely(!pdcp_post_process_update_entity_state(entity, count)))
			goto error;

		rte_pktmbuf_adj(mb, hdr_trim_sz);
		rte_pktmbuf_trim(mb, PDCP_MAC_I_LEN);
		out_mb[nb_success++] = mb;
		continue;

error:
		err_mb[nb_err++] = mb;
	}

	if (unlikely(nb_err != 0))
		rte_memcpy(&out_mb[nb_success], err_mb, nb_err * sizeof(struct rte_mbuf *));

	*nb_err_ret = nb_err;
	return nb_success;
}

static int
pdcp_pre_process_func_set(struct rte_pdcp_entity *entity, const struct rte_pdcp_entity_conf *conf)
{
	struct entity_priv *en_priv = entity_priv_get(entity);

	entity->pre_process = NULL;
	entity->post_process = NULL;

	if ((conf->pdcp_xfrm.domain == RTE_SECURITY_PDCP_MODE_CONTROL) &&
	    (conf->pdcp_xfrm.sn_size == RTE_SECURITY_PDCP_SN_SIZE_12) &&
	    (conf->pdcp_xfrm.pkt_dir == RTE_SECURITY_PDCP_UPLINK)) {
		entity->pre_process = pdcp_pre_process_cplane_sn_12_ul;
		entity->post_process = pdcp_post_process_cplane_sn_12_ul;
	}

	if ((conf->pdcp_xfrm.domain == RTE_SECURITY_PDCP_MODE_CONTROL) &&
	    (conf->pdcp_xfrm.sn_size == RTE_SECURITY_PDCP_SN_SIZE_12) &&
	    (conf->pdcp_xfrm.pkt_dir == RTE_SECURITY_PDCP_DOWNLINK)) {
		entity->pre_process = pdcp_pre_process_cplane_sn_12_dl;
		entity->post_process = pdcp_post_process_cplane_sn_12_dl;
	}

	if ((conf->pdcp_xfrm.domain == RTE_SECURITY_PDCP_MODE_DATA) &&
	    (conf->pdcp_xfrm.sn_size == RTE_SECURITY_PDCP_SN_SIZE_12) &&
	    (conf->pdcp_xfrm.pkt_dir == RTE_SECURITY_PDCP_UPLINK)) {
		entity->pre_process = pdcp_pre_process_uplane_sn_12_ul;
		entity->post_process = pdcp_post_process_uplane_sn_12_ul;
	}

	if ((conf->pdcp_xfrm.domain == RTE_SECURITY_PDCP_MODE_DATA) &&
	    (conf->pdcp_xfrm.sn_size == RTE_SECURITY_PDCP_SN_SIZE_18) &&
	    (conf->pdcp_xfrm.pkt_dir == RTE_SECURITY_PDCP_UPLINK)) {
		entity->pre_process = pdcp_pre_process_uplane_sn_18_ul;
		entity->post_process = pdcp_post_process_uplane_sn_18_ul;
	}

	if ((conf->pdcp_xfrm.domain == RTE_SECURITY_PDCP_MODE_DATA) &&
	    (conf->pdcp_xfrm.sn_size == RTE_SECURITY_PDCP_SN_SIZE_12) &&
	    (conf->pdcp_xfrm.pkt_dir == RTE_SECURITY_PDCP_DOWNLINK) &&
	    (en_priv->flags.is_authenticated)) {
		entity->pre_process = pdcp_pre_process_uplane_sn_12_dl_ip;
		entity->post_process = pdcp_post_process_uplane_sn_12_dl_ip;
	}

	if ((conf->pdcp_xfrm.domain == RTE_SECURITY_PDCP_MODE_DATA) &&
	    (conf->pdcp_xfrm.sn_size == RTE_SECURITY_PDCP_SN_SIZE_12) &&
	    (conf->pdcp_xfrm.pkt_dir == RTE_SECURITY_PDCP_DOWNLINK) &&
	    (!en_priv->flags.is_authenticated)) {
		entity->pre_process = pdcp_pre_process_uplane_sn_12_dl;
		entity->post_process = pdcp_post_process_uplane_sn_12_dl;
	}

	if ((conf->pdcp_xfrm.domain == RTE_SECURITY_PDCP_MODE_DATA) &&
	    (conf->pdcp_xfrm.sn_size == RTE_SECURITY_PDCP_SN_SIZE_18) &&
	    (conf->pdcp_xfrm.pkt_dir == RTE_SECURITY_PDCP_DOWNLINK) &&
	    (en_priv->flags.is_authenticated)) {
		entity->pre_process = pdcp_pre_process_uplane_sn_18_dl_ip;
		entity->post_process = pdcp_post_process_uplane_sn_18_dl_ip;
	}

	if ((conf->pdcp_xfrm.domain == RTE_SECURITY_PDCP_MODE_DATA) &&
	    (conf->pdcp_xfrm.sn_size == RTE_SECURITY_PDCP_SN_SIZE_18) &&
	    (conf->pdcp_xfrm.pkt_dir == RTE_SECURITY_PDCP_DOWNLINK) &&
	    (!en_priv->flags.is_authenticated)) {
		entity->pre_process = pdcp_pre_process_uplane_sn_18_dl;
		entity->post_process = pdcp_post_process_uplane_sn_18_dl;
	}

	if (entity->pre_process == NULL || entity->post_process == NULL)
		return -ENOTSUP;

	return 0;
}

static int
pdcp_entity_priv_populate(struct entity_priv *en_priv, const struct rte_pdcp_entity_conf *conf)
{
	struct rte_crypto_sym_xform *c_xfrm, *a_xfrm;
	int ret;

	/**
	 * flags.is_authenticated
	 *
	 * MAC-I would be added in case of control plane packets and when authentication
	 * transform is not NULL.
	 */

	if (conf->pdcp_xfrm.domain == RTE_SECURITY_PDCP_MODE_CONTROL)
		en_priv->flags.is_authenticated = 1;

	ret = pdcp_crypto_xfrm_get(conf, &c_xfrm, &a_xfrm);
	if (ret)
		return ret;

	if (a_xfrm != NULL)
		en_priv->flags.is_authenticated = 1;

	/**
	 * flags.is_ciph_in_bits
	 *
	 * For ZUC & SNOW3G cipher algos, offset & length need to be provided in bits.
	 */

	if ((c_xfrm->cipher.algo == RTE_CRYPTO_CIPHER_SNOW3G_UEA2) ||
	    (c_xfrm->cipher.algo == RTE_CRYPTO_CIPHER_ZUC_EEA3))
		en_priv->flags.is_ciph_in_bits = 1;

	/**
	 * flags.is_auth_in_bits
	 *
	 * For ZUC & SNOW3G authentication algos, offset & length need to be provided in bits.
	 */

	if (a_xfrm != NULL) {
		if ((a_xfrm->auth.algo == RTE_CRYPTO_AUTH_SNOW3G_UIA2) ||
		    (a_xfrm->auth.algo == RTE_CRYPTO_AUTH_ZUC_EIA3))
			en_priv->flags.is_auth_in_bits = 1;
	}

	/**
	 * flags.is_ul_entity
	 *
	 * Indicate whether the entity is UL/transmitting PDCP entity.
	 */
	if (conf->pdcp_xfrm.pkt_dir == RTE_SECURITY_PDCP_UPLINK)
		en_priv->flags.is_ul_entity = 1;

	/**
	 * hdr_sz
	 *
	 * PDCP header size of the entity
	 */
	en_priv->hdr_sz = pdcp_hdr_size_get(conf->pdcp_xfrm.sn_size);

	/**
	 * aad_sz
	 *
	 * For AES-CMAC, additional message is prepended for processing. Need to be trimmed after
	 * crypto processing is done.
	 */
	if (a_xfrm != NULL && a_xfrm->auth.algo == RTE_CRYPTO_AUTH_AES_CMAC)
		en_priv->aad_sz = 8;
	else
		en_priv->aad_sz = 0;

	return 0;
}

int
pdcp_process_func_set(struct rte_pdcp_entity *entity, const struct rte_pdcp_entity_conf *conf)
{
	struct entity_priv *en_priv;
	int ret;

	if (entity == NULL || conf == NULL)
		return -EINVAL;

	en_priv = entity_priv_get(entity);

	ret = pdcp_iv_gen_func_set(entity, conf);
	if (ret)
		return ret;

	ret = pdcp_entity_priv_populate(en_priv, conf);
	if (ret)
		return ret;

	ret = pdcp_pre_process_func_set(entity, conf);
	if (ret)
		return ret;

	return 0;
}

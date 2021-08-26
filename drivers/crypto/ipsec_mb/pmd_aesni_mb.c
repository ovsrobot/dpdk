/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2021 Intel Corporation
 */

/**
 * function used to process crypto workload using job API
 */
#include <intel-ipsec-mb.h>

#if defined(RTE_LIB_SECURITY)
#define AESNI_MB_DOCSIS_SEC_ENABLED 1
#include <rte_security.h>
#include <rte_security_driver.h>
#include <rte_ether.h>
#endif

#include "rte_ipsec_mb_pmd_private.h"

#define AES_CCM_DIGEST_MIN_LEN 4
#define AES_CCM_DIGEST_MAX_LEN 16
#define HMAC_MAX_BLOCK_SIZE 128
#define HMAC_IPAD_VALUE			(0x36)
#define HMAC_OPAD_VALUE			(0x5C)

static const struct rte_cryptodev_capabilities aesni_mb_capabilities[] = {
	{	/* MD5 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_MD5_HMAC,
				.block_size = 64,
				.key_size = {
					.min = 1,
					.max = 64,
					.increment = 1
				},
				.digest_size = {
					.min = 1,
					.max = 16,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA1 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA1_HMAC,
				.block_size = 64,
				.key_size = {
					.min = 1,
					.max = 65535,
					.increment = 1
				},
				.digest_size = {
					.min = 1,
					.max = 20,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA1 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA1,
				.block_size = 64,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 1,
					.max = 20,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA224 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA224_HMAC,
				.block_size = 64,
				.key_size = {
					.min = 1,
					.max = 65535,
					.increment = 1
				},
				.digest_size = {
					.min = 1,
					.max = 28,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA224 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA224,
				.block_size = 64,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 1,
					.max = 28,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA256 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA256_HMAC,
				.block_size = 64,
				.key_size = {
					.min = 1,
					.max = 65535,
					.increment = 1
				},
				.digest_size = {
					.min = 1,
					.max = 32,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA256 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA256,
				.block_size = 64,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 1,
					.max = 32,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA384 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA384_HMAC,
				.block_size = 128,
				.key_size = {
					.min = 1,
					.max = 65535,
					.increment = 1
				},
				.digest_size = {
					.min = 1,
					.max = 48,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA384 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA384,
				.block_size = 128,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 1,
					.max = 48,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA512 HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA512_HMAC,
				.block_size = 128,
				.key_size = {
					.min = 1,
					.max = 65535,
					.increment = 1
				},
				.digest_size = {
					.min = 1,
					.max = 64,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* SHA512  */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA512,
				.block_size = 128,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 1,
					.max = 64,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* AES XCBC HMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_AES_XCBC_MAC,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.digest_size = {
					.min = 12,
					.max = 12,
					.increment = 0
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* AES CBC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_CBC,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* AES CTR */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_CTR,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.iv_size = {
					.min = 12,
					.max = 16,
					.increment = 4
				}
			}, }
		}, }
	},
	{	/* AES DOCSIS BPI */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_DOCSISBPI,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 16
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* DES CBC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_DES_CBC,
				.block_size = 8,
				.key_size = {
					.min = 8,
					.max = 8,
					.increment = 0
				},
				.iv_size = {
					.min = 8,
					.max = 8,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/*  3DES CBC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_3DES_CBC,
				.block_size = 8,
				.key_size = {
					.min = 8,
					.max = 24,
					.increment = 8
				},
				.iv_size = {
					.min = 8,
					.max = 8,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* DES DOCSIS BPI */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_DES_DOCSISBPI,
				.block_size = 8,
				.key_size = {
					.min = 8,
					.max = 8,
					.increment = 0
				},
				.iv_size = {
					.min = 8,
					.max = 8,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* AES CCM */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AEAD,
			{.aead = {
				.algo = RTE_CRYPTO_AEAD_AES_CCM,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 16
				},
				.digest_size = {
					.min = 4,
					.max = 16,
					.increment = 2
				},
				.aad_size = {
					.min = 0,
					.max = 46,
					.increment = 1
				},
				.iv_size = {
					.min = 7,
					.max = 13,
					.increment = 1
				},
			}, }
		}, }
	},
	{	/* AES CMAC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_AES_CMAC,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.digest_size = {
					.min = 1,
					.max = 16,
					.increment = 1
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* AES GCM */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AEAD,
			{.aead = {
				.algo = RTE_CRYPTO_AEAD_AES_GCM,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.digest_size = {
					.min = 1,
					.max = 16,
					.increment = 1
				},
				.aad_size = {
					.min = 0,
					.max = 65535,
					.increment = 1
				},
				.iv_size = {
					.min = 12,
					.max = 12,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* AES GMAC (AUTH) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_AES_GMAC,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.digest_size = {
					.min = 1,
					.max = 16,
					.increment = 1
				},
				.iv_size = {
					.min = 12,
					.max = 12,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* AES ECB */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_ECB,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* ZUC (EIA3) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_ZUC_EIA3,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.digest_size = {
					.min = 4,
					.max = 4,
					.increment = 0
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* ZUC (EEA3) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_ZUC_EEA3,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
			}, }
		}, }
	},
	{	/* SNOW 3G (UIA2) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SNOW3G_UIA2,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.digest_size = {
					.min = 4,
					.max = 4,
					.increment = 0
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* SNOW 3G (UEA2) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_SNOW3G_UEA2,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* KASUMI (F9) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_KASUMI_F9,
				.block_size = 8,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.digest_size = {
					.min = 4,
					.max = 4,
					.increment = 0
				},
				.iv_size = { 0 }
			}, }
		}, }
	},
	{	/* KASUMI (F8) */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_KASUMI_F8,
				.block_size = 8,
				.key_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.iv_size = {
					.min = 8,
					.max = 8,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* CHACHA20-POLY1305 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AEAD,
			{.aead = {
				.algo = RTE_CRYPTO_AEAD_CHACHA20_POLY1305,
				.block_size = 64,
				.key_size = {
					.min = 32,
					.max = 32,
					.increment = 0
				},
				.digest_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
				.aad_size = {
					.min = 0,
					.max = 240,
					.increment = 1
				},
				.iv_size = {
					.min = 12,
					.max = 12,
					.increment = 0
				},
			}, }
		}, }
	},
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

uint8_t pmd_driver_id_aesni_mb;

struct aesni_mb_qp_data {
	uint8_t temp_digests[MAX_JOBS][DIGEST_LENGTH_MAX];
	/* *< Buffers used to store the digest generated
	 * by the driver when verifying a digest provided
	 * by the user (using authentication verify operation)
	 */
};

/* Maximum length for digest */
#define DIGEST_LENGTH_MAX 64
static const unsigned int auth_blocksize[] = {
		[NULL_HASH]			= 0,
		[MD5]				= 64,
		[SHA1]				= 64,
		[SHA_224]			= 64,
		[SHA_256]			= 64,
		[SHA_384]			= 128,
		[SHA_512]			= 128,
		[AES_XCBC]			= 16,
		[AES_CCM]			= 16,
		[AES_CMAC]			= 16,
		[AES_GMAC]			= 16,
		[PLAIN_SHA1]			= 64,
		[PLAIN_SHA_224]			= 64,
		[PLAIN_SHA_256]			= 64,
		[PLAIN_SHA_384]			= 128,
		[PLAIN_SHA_512]			= 128,
		[IMB_AUTH_ZUC_EIA3_BITLEN]	= 16,
		[IMB_AUTH_SNOW3G_UIA2_BITLEN]	= 16,
		[IMB_AUTH_KASUMI_UIA1]		= 16
};

/**
 * Get the blocksize in bytes for a specified authentication algorithm
 *
 * @Note: this function will not return a valid value for a non-valid
 * authentication algorithm
 */
static inline unsigned int
get_auth_algo_blocksize(JOB_HASH_ALG algo)
{
	return auth_blocksize[algo];
}

static const unsigned int auth_truncated_digest_byte_lengths[] = {
		[MD5]				= 12,
		[SHA1]				= 12,
		[SHA_224]			= 14,
		[SHA_256]			= 16,
		[SHA_384]			= 24,
		[SHA_512]			= 32,
		[AES_XCBC]			= 12,
		[AES_CMAC]			= 12,
		[AES_CCM]			= 8,
		[NULL_HASH]			= 0,
		[AES_GMAC]			= 12,
		[PLAIN_SHA1]			= 20,
		[PLAIN_SHA_224]			= 28,
		[PLAIN_SHA_256]			= 32,
		[PLAIN_SHA_384]			= 48,
		[PLAIN_SHA_512]			= 64,
		[IMB_AUTH_ZUC_EIA3_BITLEN]	= 4,
		[IMB_AUTH_SNOW3G_UIA2_BITLEN]	= 4,
		[IMB_AUTH_KASUMI_UIA1]		= 4
};

/**
 * Get the IPsec specified truncated length in bytes of the HMAC digest for a
 * specified authentication algorithm
 *
 * @Note: this function will not return a valid value for a non-valid
 * authentication algorithm
 */
static inline unsigned int
get_truncated_digest_byte_length(JOB_HASH_ALG algo)
{
	return auth_truncated_digest_byte_lengths[algo];
}

static const unsigned int auth_digest_byte_lengths[] = {
		[MD5]				= 16,
		[SHA1]				= 20,
		[SHA_224]			= 28,
		[SHA_256]			= 32,
		[SHA_384]			= 48,
		[SHA_512]			= 64,
		[AES_XCBC]			= 16,
		[AES_CMAC]			= 16,
		[AES_CCM]			= 16,
		[AES_GMAC]			= 16,
		[NULL_HASH]			= 0,
		[PLAIN_SHA1]			= 20,
		[PLAIN_SHA_224]			= 28,
		[PLAIN_SHA_256]			= 32,
		[PLAIN_SHA_384]			= 48,
		[PLAIN_SHA_512]			= 64,
		[IMB_AUTH_ZUC_EIA3_BITLEN]	= 4,
		[IMB_AUTH_SNOW3G_UIA2_BITLEN]	= 4,
		[IMB_AUTH_KASUMI_UIA1]		= 4
	/**< Vector mode dependent pointer table of the multi-buffer APIs */

};

/**
 * Get the full digest size in bytes for a specified authentication algorithm
 * (if available in the Multi-buffer library)
 *
 * @Note: this function will not return a valid value for a non-valid
 * authentication algorithm
 */
static inline unsigned int
get_digest_byte_length(JOB_HASH_ALG algo)
{
	return auth_digest_byte_lengths[algo];
}

/** AES-NI multi-buffer private session structure */
struct aesni_mb_session {
	JOB_CIPHER_MODE cipher_mode;
	JOB_CIPHER_DIRECTION cipher_direction;
	JOB_HASH_ALG hash_alg;
	JOB_CHAIN_ORDER chain_order;
	/*  common job fields */
	struct {
		uint16_t length;
		uint16_t offset;
	} iv;
	struct {
		uint16_t length;
		uint16_t offset;
	} auth_iv;
	/* *< IV parameters
	 */

	/* * Cipher Parameters
	 */
	struct {
		/* * Cipher direction - encrypt / decrypt */
		JOB_CIPHER_DIRECTION direction;
		/* * Cipher mode - CBC / Counter */
		JOB_CIPHER_MODE mode;

		uint64_t key_length_in_bytes;

		union {
			struct {
				uint32_t encode[60] __rte_aligned(16);
				/* *< encode key */
				uint32_t decode[60] __rte_aligned(16);
				/* *< decode key */
			} expanded_aes_keys;
			/* *< Expanded AES keys - Allocating space to
			 * contain the maximum expanded key size which
			 * is 240 bytes for 256 bit AES, calculate by:
			 * ((key size (bytes)) *
			 * ((number of rounds) + 1))
			 */
			struct {
				const void *ks_ptr[3];
				uint64_t key[3][16];
			} exp_3des_keys;
			/* *< Expanded 3DES keys */

			struct gcm_key_data gcm_key;
			/* *< Expanded GCM key */
			uint8_t zuc_cipher_key[16];
			/* *< ZUC cipher key */
			snow3g_key_schedule_t pKeySched_snow3g_cipher;
			/* *< SNOW3G scheduled cipher key */
			kasumi_key_sched_t pKeySched_kasumi_cipher;
			/* *< KASUMI scheduled cipher key */
		};
	} cipher;

	/* *< Authentication Parameters */
	struct {
		JOB_HASH_ALG algo; /* *< Authentication Algorithm */
		enum rte_crypto_auth_operation operation;
		/* *< auth operation generate or verify */
		union {
			struct {
				uint8_t inner[128] __rte_aligned(16);
				/* *< inner pad */
				uint8_t outer[128] __rte_aligned(16);
				/* *< outer pad */
			} pads;
			/* *< HMAC Authentication pads -
			 * allocating space for the maximum pad
			 * size supported which is 128 bytes for
			 * SHA512
			 */

			struct {
				uint32_t k1_expanded[44] __rte_aligned(16);
				/* *< k1 (expanded key). */
				uint8_t k2[16] __rte_aligned(16);
				/* *< k2. */
				uint8_t k3[16] __rte_aligned(16);
				/* *< k3. */
			} xcbc;

			struct {
				uint32_t expkey[60] __rte_aligned(16);
				/* *< k1 (expanded key). */
				uint32_t skey1[4] __rte_aligned(16);
				/* *< k2. */
				uint32_t skey2[4] __rte_aligned(16);
				/* *< k3. */
			} cmac;
			/* *< Expanded XCBC authentication keys */
			uint8_t zuc_auth_key[16];
			/* *< ZUC authentication key */
			snow3g_key_schedule_t pKeySched_snow3g_auth;
			/* *< SNOW3G scheduled authentication key */
			kasumi_key_sched_t pKeySched_kasumi_auth;
			/* *< KASUMI scheduled authentication key */
		};
		/* * Generated digest size by the Multi-buffer library */
		uint16_t gen_digest_len;
		/* * Requested digest size from Cryptodev */
		uint16_t req_digest_len;

	} auth;
	struct {
		/* * AAD data length */
		uint16_t aad_len;
	} aead;
} __rte_cache_aligned;

typedef void (*hash_one_block_t)(const void *data, void *digest);
typedef void (*aes_keyexp_t)(const void *key, void *enc_exp_keys,
			void *dec_exp_keys);


/**
 * Calculate the authentication pre-computes
 *
 * @param one_block_hash	Function pointer
 *				to calculate digest on ipad/opad
 * @param ipad			Inner pad output byte array
 * @param opad			Outer pad output byte array
 * @param hkey			Authentication key
 * @param hkey_len		Authentication key length
 * @param blocksize		Block size of selected hash algo
 */
static void
calculate_auth_precomputes(hash_one_block_t one_block_hash,
		uint8_t *ipad, uint8_t *opad,
		const uint8_t *hkey, uint16_t hkey_len,
		uint16_t blocksize)
{
	uint32_t i, length;

	uint8_t ipad_buf[blocksize] __rte_aligned(16);
	uint8_t opad_buf[blocksize] __rte_aligned(16);

	/* Setup inner and outer pads */
	memset(ipad_buf, HMAC_IPAD_VALUE, blocksize);
	memset(opad_buf, HMAC_OPAD_VALUE, blocksize);

	/* XOR hash key with inner and outer pads */
	length = hkey_len > blocksize ? blocksize : hkey_len;

	for (i = 0; i < length; i++) {
		ipad_buf[i] ^= hkey[i];
		opad_buf[i] ^= hkey[i];
	}

	/* Compute partial hashes */
	(*one_block_hash)(ipad_buf, ipad);
	(*one_block_hash)(opad_buf, opad);

	/* Clean up stack */
	memset(ipad_buf, 0, blocksize);
	memset(opad_buf, 0, blocksize);
}

static inline int
is_aead_algo(JOB_HASH_ALG hash_alg, JOB_CIPHER_MODE cipher_mode)
{
	return (hash_alg == IMB_AUTH_CHACHA20_POLY1305 || hash_alg == AES_CCM ||
		(hash_alg == AES_GMAC && cipher_mode == GCM));
}

/** Set session authentication parameters */
static int
aesni_mb_set_session_auth_parameters(const MB_MGR *mb_mgr,
		struct aesni_mb_session *sess,
		const struct rte_crypto_sym_xform *xform)
{
	hash_one_block_t hash_oneblock_fn = NULL;
	unsigned int key_larger_block_size = 0;
	uint8_t hashed_key[HMAC_MAX_BLOCK_SIZE] = { 0 };
	uint32_t auth_precompute = 1;

	if (xform == NULL) {
		sess->auth.algo = NULL_HASH;
		return 0;
	}

	if (xform->type != RTE_CRYPTO_SYM_XFORM_AUTH) {
		IPSEC_MB_LOG(ERR, "Crypto xform struct not of type auth");
		return -1;
	}

	/* Set IV parameters */
	sess->auth_iv.offset = xform->auth.iv.offset;
	sess->auth_iv.length = xform->auth.iv.length;

	/* Set the request digest size */
	sess->auth.req_digest_len = xform->auth.digest_length;

	/* Select auth generate/verify */
	sess->auth.operation = xform->auth.op;

	/* Set Authentication Parameters */
	if (xform->auth.algo == RTE_CRYPTO_AUTH_AES_XCBC_MAC) {
		sess->auth.algo = AES_XCBC;

		uint16_t xcbc_mac_digest_len =
			get_truncated_digest_byte_length(AES_XCBC);
		if (sess->auth.req_digest_len != xcbc_mac_digest_len) {
			IPSEC_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		sess->auth.gen_digest_len = sess->auth.req_digest_len;

		IMB_AES_XCBC_KEYEXP(mb_mgr, xform->auth.key.data,
				sess->auth.xcbc.k1_expanded,
				sess->auth.xcbc.k2, sess->auth.xcbc.k3);
		return 0;
	}

	if (xform->auth.algo == RTE_CRYPTO_AUTH_AES_CMAC) {
		uint32_t dust[4*15];

		sess->auth.algo = AES_CMAC;

		uint16_t cmac_digest_len = get_digest_byte_length(AES_CMAC);

		if (sess->auth.req_digest_len > cmac_digest_len) {
			IPSEC_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		/*
		 * Multi-buffer lib supports digest sizes from 4 to 16 bytes
		 * in version 0.50 and sizes of 12 and 16 bytes,
		 * in version 0.49.
		 * If size requested is different, generate the full digest
		 * (16 bytes) in a temporary location and then memcpy
		 * the requested number of bytes.
		 */
		if (sess->auth.req_digest_len < 4)
			sess->auth.gen_digest_len = cmac_digest_len;
		else
			sess->auth.gen_digest_len = sess->auth.req_digest_len;

		IMB_AES_KEYEXP_128(mb_mgr, xform->auth.key.data,
				sess->auth.cmac.expkey, dust);
		IMB_AES_CMAC_SUBKEY_GEN_128(mb_mgr, sess->auth.cmac.expkey,
				sess->auth.cmac.skey1, sess->auth.cmac.skey2);
		return 0;
	}

	if (xform->auth.algo == RTE_CRYPTO_AUTH_AES_GMAC) {
		if (xform->auth.op == RTE_CRYPTO_AUTH_OP_GENERATE) {
			sess->cipher.direction = ENCRYPT;
			sess->chain_order = CIPHER_HASH;
		} else
			sess->cipher.direction = DECRYPT;

		sess->auth.algo = AES_GMAC;
		if (sess->auth.req_digest_len >
			get_digest_byte_length(AES_GMAC)) {
			IPSEC_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		sess->auth.gen_digest_len = sess->auth.req_digest_len;
		sess->iv.length = xform->auth.iv.length;
		sess->iv.offset = xform->auth.iv.offset;

		switch (xform->auth.key.length) {
		case AES_128_BYTES:
			IMB_AES128_GCM_PRE(mb_mgr, xform->auth.key.data,
				&sess->cipher.gcm_key);
			sess->cipher.key_length_in_bytes = AES_128_BYTES;
			break;
		case AES_192_BYTES:
			IMB_AES192_GCM_PRE(mb_mgr, xform->auth.key.data,
				&sess->cipher.gcm_key);
			sess->cipher.key_length_in_bytes = AES_192_BYTES;
			break;
		case AES_256_BYTES:
			IMB_AES256_GCM_PRE(mb_mgr, xform->auth.key.data,
				&sess->cipher.gcm_key);
			sess->cipher.key_length_in_bytes = AES_256_BYTES;
			break;
		default:
			RTE_LOG(ERR, PMD, "failed to parse test type\n");
			return -EINVAL;
		}

		return 0;
	}

	if (xform->auth.algo == RTE_CRYPTO_AUTH_ZUC_EIA3) {
		sess->auth.algo = IMB_AUTH_ZUC_EIA3_BITLEN;
		uint16_t zuc_eia3_digest_len =
			get_truncated_digest_byte_length(
						IMB_AUTH_ZUC_EIA3_BITLEN);
		if (sess->auth.req_digest_len != zuc_eia3_digest_len) {
			IPSEC_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		sess->auth.gen_digest_len = sess->auth.req_digest_len;

		memcpy(sess->auth.zuc_auth_key, xform->auth.key.data, 16);
		return 0;
	} else if (xform->auth.algo == RTE_CRYPTO_AUTH_SNOW3G_UIA2) {
		sess->auth.algo = IMB_AUTH_SNOW3G_UIA2_BITLEN;
		uint16_t snow3g_uia2_digest_len =
			get_truncated_digest_byte_length(
						IMB_AUTH_SNOW3G_UIA2_BITLEN);
		if (sess->auth.req_digest_len != snow3g_uia2_digest_len) {
			IPSEC_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		sess->auth.gen_digest_len = sess->auth.req_digest_len;

		IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, xform->auth.key.data,
					&sess->auth.pKeySched_snow3g_auth);
		return 0;
	} else if (xform->auth.algo == RTE_CRYPTO_AUTH_KASUMI_F9) {
		sess->auth.algo = IMB_AUTH_KASUMI_UIA1;
		uint16_t kasumi_f9_digest_len =
			get_truncated_digest_byte_length(IMB_AUTH_KASUMI_UIA1);
		if (sess->auth.req_digest_len != kasumi_f9_digest_len) {
			IPSEC_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		sess->auth.gen_digest_len = sess->auth.req_digest_len;

		IMB_KASUMI_INIT_F9_KEY_SCHED(mb_mgr, xform->auth.key.data,
					&sess->auth.pKeySched_kasumi_auth);
		return 0;
	}

	switch (xform->auth.algo) {
	case RTE_CRYPTO_AUTH_MD5_HMAC:
		sess->auth.algo = MD5;
		hash_oneblock_fn = mb_mgr->md5_one_block;
		break;
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		sess->auth.algo = SHA1;
		hash_oneblock_fn = mb_mgr->sha1_one_block;
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA1)) {
			IMB_SHA1(mb_mgr,
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
		break;
	case RTE_CRYPTO_AUTH_SHA1:
		sess->auth.algo = PLAIN_SHA1;
		auth_precompute = 0;
		break;
	case RTE_CRYPTO_AUTH_SHA224_HMAC:
		sess->auth.algo = SHA_224;
		hash_oneblock_fn = mb_mgr->sha224_one_block;
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA_224)) {
			IMB_SHA224(mb_mgr,
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
		break;
	case RTE_CRYPTO_AUTH_SHA224:
		sess->auth.algo = PLAIN_SHA_224;
		auth_precompute = 0;
		break;
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
		sess->auth.algo = SHA_256;
		hash_oneblock_fn = mb_mgr->sha256_one_block;
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA_256)) {
			IMB_SHA256(mb_mgr,
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
		break;
	case RTE_CRYPTO_AUTH_SHA256:
		sess->auth.algo = PLAIN_SHA_256;
		auth_precompute = 0;
		break;
	case RTE_CRYPTO_AUTH_SHA384_HMAC:
		sess->auth.algo = SHA_384;
		hash_oneblock_fn = mb_mgr->sha384_one_block;
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA_384)) {
			IMB_SHA384(mb_mgr,
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
		break;
	case RTE_CRYPTO_AUTH_SHA384:
		sess->auth.algo = PLAIN_SHA_384;
		auth_precompute = 0;
		break;
	case RTE_CRYPTO_AUTH_SHA512_HMAC:
		sess->auth.algo = SHA_512;
		hash_oneblock_fn = mb_mgr->sha512_one_block;
		if (xform->auth.key.length > get_auth_algo_blocksize(SHA_512)) {
			IMB_SHA512(mb_mgr,
				xform->auth.key.data,
				xform->auth.key.length,
				hashed_key);
			key_larger_block_size = 1;
		}
		break;
	case RTE_CRYPTO_AUTH_SHA512:
		sess->auth.algo = PLAIN_SHA_512;
		auth_precompute = 0;
		break;
	default:
		IPSEC_MB_LOG(ERR,
			"Unsupported authentication algorithm selection");
		return -ENOTSUP;
	}
	uint16_t trunc_digest_size =
			get_truncated_digest_byte_length(sess->auth.algo);
	uint16_t full_digest_size =
			get_digest_byte_length(sess->auth.algo);

	if (sess->auth.req_digest_len > full_digest_size ||
			sess->auth.req_digest_len == 0) {
		IPSEC_MB_LOG(ERR, "Invalid digest size\n");
		return -EINVAL;
	}

	if (sess->auth.req_digest_len != trunc_digest_size &&
			sess->auth.req_digest_len != full_digest_size)
		sess->auth.gen_digest_len = full_digest_size;
	else
		sess->auth.gen_digest_len = sess->auth.req_digest_len;

	/* Plain SHA does not require precompute key */
	if (auth_precompute == 0)
		return 0;

	/* Calculate Authentication precomputes */
	if (key_larger_block_size) {
		calculate_auth_precomputes(hash_oneblock_fn,
			sess->auth.pads.inner, sess->auth.pads.outer,
			hashed_key,
			xform->auth.key.length,
			get_auth_algo_blocksize(sess->auth.algo));
	} else {
		calculate_auth_precomputes(hash_oneblock_fn,
			sess->auth.pads.inner, sess->auth.pads.outer,
			xform->auth.key.data,
			xform->auth.key.length,
			get_auth_algo_blocksize(sess->auth.algo));
	}

	return 0;
}

/** Set session cipher parameters */
static int
aesni_mb_set_session_cipher_parameters(const MB_MGR *mb_mgr,
		struct aesni_mb_session *sess,
		const struct rte_crypto_sym_xform *xform)
{
	uint8_t is_aes = 0;
	uint8_t is_3DES = 0;
	uint8_t is_docsis = 0;
	uint8_t is_zuc = 0;
	uint8_t is_snow3g = 0;
	uint8_t is_kasumi = 0;

	if (xform == NULL) {
		sess->cipher.mode = NULL_CIPHER;
		return 0;
	}

	if (xform->type != RTE_CRYPTO_SYM_XFORM_CIPHER) {
		IPSEC_MB_LOG(ERR, "Crypto xform struct not of type cipher");
		return -EINVAL;
	}

	/* Select cipher direction */
	switch (xform->cipher.op) {
	case RTE_CRYPTO_CIPHER_OP_ENCRYPT:
		sess->cipher.direction = ENCRYPT;
		break;
	case RTE_CRYPTO_CIPHER_OP_DECRYPT:
		sess->cipher.direction = DECRYPT;
		break;
	default:
		IPSEC_MB_LOG(ERR, "Invalid cipher operation parameter");
		return -EINVAL;
	}

	/* Select cipher mode */
	switch (xform->cipher.algo) {
	case RTE_CRYPTO_CIPHER_AES_CBC:
		sess->cipher.mode = CBC;
		is_aes = 1;
		break;
	case RTE_CRYPTO_CIPHER_AES_CTR:
		sess->cipher.mode = CNTR;
		is_aes = 1;
		break;
	case RTE_CRYPTO_CIPHER_AES_DOCSISBPI:
		sess->cipher.mode = DOCSIS_SEC_BPI;
		is_docsis = 1;
		break;
	case RTE_CRYPTO_CIPHER_DES_CBC:
		sess->cipher.mode = DES;
		break;
	case RTE_CRYPTO_CIPHER_DES_DOCSISBPI:
		sess->cipher.mode = DOCSIS_DES;
		break;
	case RTE_CRYPTO_CIPHER_3DES_CBC:
		sess->cipher.mode = DES3;
		is_3DES = 1;
		break;
	case RTE_CRYPTO_CIPHER_AES_ECB:
		sess->cipher.mode = ECB;
		is_aes = 1;
		break;
	case RTE_CRYPTO_CIPHER_ZUC_EEA3:
		sess->cipher.mode = IMB_CIPHER_ZUC_EEA3;
		is_zuc = 1;
		break;
	case RTE_CRYPTO_CIPHER_SNOW3G_UEA2:
		sess->cipher.mode = IMB_CIPHER_SNOW3G_UEA2_BITLEN;
		is_snow3g = 1;
		break;
	case RTE_CRYPTO_CIPHER_KASUMI_F8:
		sess->cipher.mode = IMB_CIPHER_KASUMI_UEA1_BITLEN;
		is_kasumi = 1;
		break;
	default:
		IPSEC_MB_LOG(ERR, "Unsupported cipher mode parameter");
		return -ENOTSUP;
	}

	/* Set IV parameters */
	sess->iv.offset = xform->cipher.iv.offset;
	sess->iv.length = xform->cipher.iv.length;

	/* Check key length and choose key expansion function for AES */
	if (is_aes) {
		switch (xform->cipher.key.length) {
		case AES_128_BYTES:
			sess->cipher.key_length_in_bytes = AES_128_BYTES;
			IMB_AES_KEYEXP_128(mb_mgr, xform->cipher.key.data,
					sess->cipher.expanded_aes_keys.encode,
					sess->cipher.expanded_aes_keys.decode);
			break;
		case AES_192_BYTES:
			sess->cipher.key_length_in_bytes = AES_192_BYTES;
			IMB_AES_KEYEXP_192(mb_mgr, xform->cipher.key.data,
					sess->cipher.expanded_aes_keys.encode,
					sess->cipher.expanded_aes_keys.decode);
			break;
		case AES_256_BYTES:
			sess->cipher.key_length_in_bytes = AES_256_BYTES;
			IMB_AES_KEYEXP_256(mb_mgr, xform->cipher.key.data,
					sess->cipher.expanded_aes_keys.encode,
					sess->cipher.expanded_aes_keys.decode);
			break;
		default:
			IPSEC_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}
	} else if (is_docsis) {
		switch (xform->cipher.key.length) {
		case AES_128_BYTES:
			sess->cipher.key_length_in_bytes = AES_128_BYTES;
			IMB_AES_KEYEXP_128(mb_mgr, xform->cipher.key.data,
					sess->cipher.expanded_aes_keys.encode,
					sess->cipher.expanded_aes_keys.decode);
			break;
		case AES_256_BYTES:
			sess->cipher.key_length_in_bytes = AES_256_BYTES;
			IMB_AES_KEYEXP_256(mb_mgr, xform->cipher.key.data,
					sess->cipher.expanded_aes_keys.encode,
					sess->cipher.expanded_aes_keys.decode);
			break;
		default:
			IPSEC_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}
	} else if (is_3DES) {
		uint64_t *keys[3] = {sess->cipher.exp_3des_keys.key[0],
				sess->cipher.exp_3des_keys.key[1],
				sess->cipher.exp_3des_keys.key[2]};

		switch (xform->cipher.key.length) {
		case  24:
			IMB_DES_KEYSCHED(mb_mgr, keys[0],
					xform->cipher.key.data);
			IMB_DES_KEYSCHED(mb_mgr, keys[1],
					xform->cipher.key.data + 8);
			IMB_DES_KEYSCHED(mb_mgr, keys[2],
					xform->cipher.key.data + 16);

			/* Initialize keys - 24 bytes: [K1-K2-K3] */
			sess->cipher.exp_3des_keys.ks_ptr[0] = keys[0];
			sess->cipher.exp_3des_keys.ks_ptr[1] = keys[1];
			sess->cipher.exp_3des_keys.ks_ptr[2] = keys[2];
			break;
		case 16:
			IMB_DES_KEYSCHED(mb_mgr, keys[0],
					xform->cipher.key.data);
			IMB_DES_KEYSCHED(mb_mgr, keys[1],
					xform->cipher.key.data + 8);
			/* Initialize keys - 16 bytes: [K1=K1,K2=K2,K3=K1] */
			sess->cipher.exp_3des_keys.ks_ptr[0] = keys[0];
			sess->cipher.exp_3des_keys.ks_ptr[1] = keys[1];
			sess->cipher.exp_3des_keys.ks_ptr[2] = keys[0];
			break;
		case 8:
			IMB_DES_KEYSCHED(mb_mgr, keys[0],
					xform->cipher.key.data);

			/* Initialize keys - 8 bytes: [K1 = K2 = K3] */
			sess->cipher.exp_3des_keys.ks_ptr[0] = keys[0];
			sess->cipher.exp_3des_keys.ks_ptr[1] = keys[0];
			sess->cipher.exp_3des_keys.ks_ptr[2] = keys[0];
			break;
		default:
			IPSEC_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}

		sess->cipher.key_length_in_bytes = 24;
	} else if (is_zuc) {
		if (xform->cipher.key.length != 16) {
			IPSEC_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}
		sess->cipher.key_length_in_bytes = 16;
		memcpy(sess->cipher.zuc_cipher_key, xform->cipher.key.data,
			16);
	} else if (is_snow3g) {
		if (xform->cipher.key.length != 16) {
			IPSEC_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}
		sess->cipher.key_length_in_bytes = 16;
		IMB_SNOW3G_INIT_KEY_SCHED(mb_mgr, xform->cipher.key.data,
					&sess->cipher.pKeySched_snow3g_cipher);
	} else if (is_kasumi) {
		if (xform->cipher.key.length != 16) {
			IPSEC_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}
		sess->cipher.key_length_in_bytes = 16;
		IMB_KASUMI_INIT_F8_KEY_SCHED(mb_mgr, xform->cipher.key.data,
					&sess->cipher.pKeySched_kasumi_cipher);
	} else {
		if (xform->cipher.key.length != 8) {
			IPSEC_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}
		sess->cipher.key_length_in_bytes = 8;

		IMB_DES_KEYSCHED(mb_mgr,
			(uint64_t *)sess->cipher.expanded_aes_keys.encode,
				xform->cipher.key.data);
		IMB_DES_KEYSCHED(mb_mgr,
			(uint64_t *)sess->cipher.expanded_aes_keys.decode,
				xform->cipher.key.data);
	}

	return 0;
}

static int
aesni_mb_set_session_aead_parameters(const MB_MGR *mb_mgr,
		struct aesni_mb_session *sess,
		const struct rte_crypto_sym_xform *xform)
{
	switch (xform->aead.op) {
	case RTE_CRYPTO_AEAD_OP_ENCRYPT:
		sess->cipher.direction = ENCRYPT;
		sess->auth.operation = RTE_CRYPTO_AUTH_OP_GENERATE;
		break;
	case RTE_CRYPTO_AEAD_OP_DECRYPT:
		sess->cipher.direction = DECRYPT;
		sess->auth.operation = RTE_CRYPTO_AUTH_OP_VERIFY;
		break;
	default:
		IPSEC_MB_LOG(ERR, "Invalid aead operation parameter");
		return -EINVAL;
	}

	/* Set IV parameters */
	sess->iv.offset = xform->aead.iv.offset;
	sess->iv.length = xform->aead.iv.length;

	/* Set digest sizes */
	sess->auth.req_digest_len = xform->aead.digest_length;
	sess->auth.gen_digest_len = sess->auth.req_digest_len;

	switch (xform->aead.algo) {
	case RTE_CRYPTO_AEAD_AES_CCM:
		sess->cipher.mode = CCM;
		sess->auth.algo = AES_CCM;

		/* Check key length and choose key expansion function for AES */
		switch (xform->aead.key.length) {
		case AES_128_BYTES:
			sess->cipher.key_length_in_bytes = AES_128_BYTES;
			IMB_AES_KEYEXP_128(mb_mgr, xform->aead.key.data,
					sess->cipher.expanded_aes_keys.encode,
					sess->cipher.expanded_aes_keys.decode);
			break;
		case AES_256_BYTES:
			sess->cipher.key_length_in_bytes = AES_256_BYTES;
			IMB_AES_KEYEXP_256(mb_mgr, xform->aead.key.data,
					sess->cipher.expanded_aes_keys.encode,
					sess->cipher.expanded_aes_keys.decode);
			break;
		default:
			IPSEC_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}

		/* CCM digests must be between 4 and 16 and an even number */
		if (sess->auth.req_digest_len < AES_CCM_DIGEST_MIN_LEN ||
			sess->auth.req_digest_len > AES_CCM_DIGEST_MAX_LEN ||
			(sess->auth.req_digest_len & 1) == 1) {
			IPSEC_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		break;

	case RTE_CRYPTO_AEAD_AES_GCM:
		sess->cipher.mode = GCM;
		sess->auth.algo = AES_GMAC;

		switch (xform->aead.key.length) {
		case AES_128_BYTES:
			sess->cipher.key_length_in_bytes = AES_128_BYTES;
			IMB_AES128_GCM_PRE(mb_mgr, xform->aead.key.data,
				&sess->cipher.gcm_key);
			break;
		case AES_192_BYTES:
			sess->cipher.key_length_in_bytes = AES_192_BYTES;
			IMB_AES192_GCM_PRE(mb_mgr, xform->aead.key.data,
				&sess->cipher.gcm_key);
			break;
		case AES_256_BYTES:
			sess->cipher.key_length_in_bytes = AES_256_BYTES;
			IMB_AES256_GCM_PRE(mb_mgr, xform->aead.key.data,
				&sess->cipher.gcm_key);
			break;
		default:
			IPSEC_MB_LOG(ERR, "Invalid cipher key length");
			return -EINVAL;
		}

		/* GCM digest size must be between 1 and 16 */
		if (sess->auth.req_digest_len == 0 ||
				sess->auth.req_digest_len > 16) {
			IPSEC_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		break;

	case RTE_CRYPTO_AEAD_CHACHA20_POLY1305:
		sess->cipher.mode = IMB_CIPHER_CHACHA20_POLY1305;
		sess->auth.algo = IMB_AUTH_CHACHA20_POLY1305;

		if (xform->aead.key.length != 32) {
			IPSEC_MB_LOG(ERR, "Invalid key length");
			return -EINVAL;
		}
		sess->cipher.key_length_in_bytes = 32;
		memcpy(sess->cipher.expanded_aes_keys.encode,
			xform->aead.key.data, 32);
		if (sess->auth.req_digest_len != 16) {
			IPSEC_MB_LOG(ERR, "Invalid digest size\n");
			return -EINVAL;
		}
		break;
	default:
		IPSEC_MB_LOG(ERR, "Unsupported aead mode parameter");
		return -ENOTSUP;
	}

	return 0;
}

/** Configure a aesni multi-buffer session from a crypto xform chain */
static int
aesni_mb_session_configure(MB_MGR *mb_mgr,
		void *priv_sess,
		const struct rte_crypto_sym_xform *xform)
{
	const struct rte_crypto_sym_xform *auth_xform = NULL;
	const struct rte_crypto_sym_xform *cipher_xform = NULL;
	const struct rte_crypto_sym_xform *aead_xform = NULL;
	enum ipsec_mb_operation mode;
	struct aesni_mb_session *sess = (struct aesni_mb_session *) priv_sess;
	int ret;

	ret = ipsec_mb_parse_xform(xform, &mode, &auth_xform,
				&cipher_xform, &aead_xform);
	if (ret)
		return ret;

	/* Select Crypto operation - hash then cipher / cipher then hash */
	switch (mode) {
	case IPSEC_MB_OP_HASH_VERIFY_THEN_DECRYPT:
		sess->chain_order = HASH_CIPHER;
		break;
	case IPSEC_MB_OP_ENCRYPT_THEN_HASH_GEN:
	case IPSEC_MB_OP_DECRYPT_THEN_HASH_VERIFY:
		sess->chain_order = CIPHER_HASH;
		break;
	case IPSEC_MB_OP_HASH_GEN_ONLY:
	case IPSEC_MB_OP_HASH_VERIFY_ONLY:
	case IPSEC_MB_OP_HASH_GEN_THEN_ENCRYPT:
		sess->chain_order = HASH_CIPHER;
		break;
	/*
	 * Multi buffer library operates only at two modes,
	 * CIPHER_HASH and HASH_CIPHER. When doing ciphering only,
	 * chain order depends on cipher operation: encryption is always
	 * the first operation and decryption the last one.
	 */
	case IPSEC_MB_OP_ENCRYPT_ONLY:
		sess->chain_order = CIPHER_HASH;
		break;
	case IPSEC_MB_OP_DECRYPT_ONLY:
		sess->chain_order = HASH_CIPHER;
		break;
	case IPSEC_MB_OP_AEAD_AUTHENTICATED_ENCRYPT:
		sess->chain_order = CIPHER_HASH;
		sess->aead.aad_len = xform->aead.aad_length;
		break;
	case IPSEC_MB_OP_AEAD_AUTHENTICATED_DECRYPT:
		sess->chain_order = HASH_CIPHER;
		sess->aead.aad_len = xform->aead.aad_length;
		break;
	case IPSEC_MB_OP_NOT_SUPPORTED:
	default:
		IPSEC_MB_LOG(ERR,
			"Unsupported operation chain order parameter");
		return -ENOTSUP;
	}

	/* Default IV length = 0 */
	sess->iv.length = 0;
	sess->auth_iv.length = 0;

	ret = aesni_mb_set_session_auth_parameters(mb_mgr, sess, auth_xform);
	if (ret != 0) {
		IPSEC_MB_LOG(ERR,
			"Invalid/unsupported authentication parameters");
		return ret;
	}

	ret = aesni_mb_set_session_cipher_parameters(mb_mgr, sess,
			cipher_xform);
	if (ret != 0) {
		IPSEC_MB_LOG(ERR, "Invalid/unsupported cipher parameters");
		return ret;
	}

	if (aead_xform) {
		ret = aesni_mb_set_session_aead_parameters(mb_mgr, sess,
				aead_xform);
		if (ret != 0) {
			IPSEC_MB_LOG(ERR,
				"Invalid/unsupported aead parameters");
			return ret;
		}
	}

	return 0;
}

#ifdef AESNI_MB_DOCSIS_SEC_ENABLED
/** Check DOCSIS security session configuration is valid */
static int
check_docsis_sec_session(struct rte_security_session_conf *conf)
{
	struct rte_crypto_sym_xform *crypto_sym = conf->crypto_xform;
	struct rte_security_docsis_xform *docsis = &conf->docsis;

	/* Downlink: CRC generate -> Cipher encrypt */
	if (docsis->direction == RTE_SECURITY_DOCSIS_DOWNLINK) {

		if (crypto_sym != NULL &&
		    crypto_sym->type ==	RTE_CRYPTO_SYM_XFORM_CIPHER &&
		    crypto_sym->cipher.op == RTE_CRYPTO_CIPHER_OP_ENCRYPT &&
		    crypto_sym->cipher.algo ==
					RTE_CRYPTO_CIPHER_AES_DOCSISBPI &&
		    (crypto_sym->cipher.key.length == IMB_KEY_AES_128_BYTES ||
		     crypto_sym->cipher.key.length == IMB_KEY_AES_256_BYTES) &&
		    crypto_sym->cipher.iv.length == AES_BLOCK_SIZE &&
		    crypto_sym->next == NULL) {
			return 0;
		}
	/* Uplink: Cipher decrypt -> CRC verify */
	} else if (docsis->direction == RTE_SECURITY_DOCSIS_UPLINK) {

		if (crypto_sym != NULL &&
		    crypto_sym->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
		    crypto_sym->cipher.op == RTE_CRYPTO_CIPHER_OP_DECRYPT &&
		    crypto_sym->cipher.algo ==
					RTE_CRYPTO_CIPHER_AES_DOCSISBPI &&
		    (crypto_sym->cipher.key.length == IMB_KEY_AES_128_BYTES ||
		     crypto_sym->cipher.key.length == IMB_KEY_AES_256_BYTES) &&
		    crypto_sym->cipher.iv.length == AES_BLOCK_SIZE &&
		    crypto_sym->next == NULL) {
			return 0;
		}
	}

	return -EINVAL;
}

/** Set DOCSIS security session auth (CRC) parameters */
static int
aesni_mb_set_docsis_sec_session_auth_parameters(struct aesni_mb_session *sess,
		struct rte_security_docsis_xform *xform)
{
	if (xform == NULL) {
		IPSEC_MB_LOG(ERR, "Invalid DOCSIS xform");
		return -EINVAL;
	}

	/* Select CRC generate/verify */
	if (xform->direction == RTE_SECURITY_DOCSIS_UPLINK) {
		sess->auth.algo = IMB_AUTH_DOCSIS_CRC32;
		sess->auth.operation = RTE_CRYPTO_AUTH_OP_VERIFY;
	} else if (xform->direction == RTE_SECURITY_DOCSIS_DOWNLINK) {
		sess->auth.algo = IMB_AUTH_DOCSIS_CRC32;
		sess->auth.operation = RTE_CRYPTO_AUTH_OP_GENERATE;
	} else {
		IPSEC_MB_LOG(ERR, "Unsupported DOCSIS direction");
		return -ENOTSUP;
	}

	sess->auth.req_digest_len = RTE_ETHER_CRC_LEN;
	sess->auth.gen_digest_len = RTE_ETHER_CRC_LEN;

	return 0;
}

/**
 * Parse DOCSIS security session configuration and set private session
 * parameters
 */
static int
aesni_mb_set_docsis_sec_session_parameters(
		__rte_unused struct rte_cryptodev *dev,
		struct rte_security_session_conf *conf,
		void *sess)
{
	MB_MGR  *mb_mgr = alloc_init_mb_mgr();
	struct rte_security_docsis_xform *docsis_xform;
	struct rte_crypto_sym_xform *cipher_xform;
	struct aesni_mb_session *ipsec_sess = sess;
	int ret = 0;

	if (!mb_mgr)
		return -ENOMEM;

	ret = check_docsis_sec_session(conf);
	if (ret) {
		IPSEC_MB_LOG(ERR, "Unsupported DOCSIS security configuration");
		goto error_exit;
	}

	switch (conf->docsis.direction) {
	case RTE_SECURITY_DOCSIS_UPLINK:
		ipsec_sess->chain_order = IMB_ORDER_CIPHER_HASH;
		docsis_xform = &conf->docsis;
		cipher_xform = conf->crypto_xform;
		break;
	case RTE_SECURITY_DOCSIS_DOWNLINK:
		ipsec_sess->chain_order = IMB_ORDER_HASH_CIPHER;
		cipher_xform = conf->crypto_xform;
		docsis_xform = &conf->docsis;
		break;
	default:
		IPSEC_MB_LOG(ERR, "Unsupported DOCSIS security configuration");
		ret = -EINVAL;
		goto error_exit;
	}

	/* Default IV length = 0 */
	ipsec_sess->iv.length = 0;

	ret = aesni_mb_set_docsis_sec_session_auth_parameters(ipsec_sess,
			docsis_xform);
	if (ret != 0) {
		IPSEC_MB_LOG(ERR, "Invalid/unsupported DOCSIS parameters");
		goto error_exit;
	}

	ret = aesni_mb_set_session_cipher_parameters(mb_mgr,
			ipsec_sess, cipher_xform);

	if (ret != 0) {
		IPSEC_MB_LOG(ERR, "Invalid/unsupported cipher parameters");
		goto error_exit;
	}

error_exit:
	free_mb_mgr(mb_mgr);
	return ret;
}
#endif

static inline uint64_t
auth_start_offset(struct rte_crypto_op *op, struct aesni_mb_session *session,
		uint32_t oop)
{
	struct rte_mbuf *m_src, *m_dst;
	uint8_t *p_src, *p_dst;
	uintptr_t u_src, u_dst;
	uint32_t cipher_end, auth_end;

	/* Only cipher then hash needs special calculation. */
	if (!oop || session->chain_order != CIPHER_HASH)
		return op->sym->auth.data.offset;

	m_src = op->sym->m_src;
	m_dst = op->sym->m_dst;

	p_src = rte_pktmbuf_mtod(m_src, uint8_t *);
	p_dst = rte_pktmbuf_mtod(m_dst, uint8_t *);
	u_src = (uintptr_t)p_src;
	u_dst = (uintptr_t)p_dst + op->sym->auth.data.offset;

	/**
	 * Copy the content between cipher offset and auth offset for generating
	 * correct digest.
	 */
	if (op->sym->cipher.data.offset > op->sym->auth.data.offset)
		memcpy(p_dst + op->sym->auth.data.offset,
				p_src + op->sym->auth.data.offset,
				op->sym->cipher.data.offset -
				op->sym->auth.data.offset);

	/**
	 * Copy the content between (cipher offset + length) and (auth offset +
	 * length) for generating correct digest
	 */
	cipher_end = op->sym->cipher.data.offset + op->sym->cipher.data.length;
	auth_end = op->sym->auth.data.offset + op->sym->auth.data.length;
	if (cipher_end < auth_end)
		memcpy(p_dst + cipher_end, p_src + cipher_end,
				auth_end - cipher_end);

	/**
	 * Since intel-ipsec-mb only supports positive values,
	 * we need to deduct the correct offset between src and dst.
	 */

	return u_src < u_dst ? (u_dst - u_src) :
			(UINT64_MAX - u_src + u_dst + 1);
}

static inline void
set_cpu_mb_job_params(JOB_AES_HMAC *job, struct aesni_mb_session *session,
		union rte_crypto_sym_ofs sofs, void *buf, uint32_t len,
		struct rte_crypto_va_iova_ptr *iv,
		struct rte_crypto_va_iova_ptr *aad, void *digest, void *udata)
{
	/* Set crypto operation */
	job->chain_order = session->chain_order;

	/* Set cipher parameters */
	job->cipher_direction = session->cipher.direction;
	job->cipher_mode = session->cipher.mode;

	job->aes_key_len_in_bytes = session->cipher.key_length_in_bytes;

	/* Set authentication parameters */
	job->hash_alg = session->auth.algo;
	job->iv = iv->va;

	switch (job->hash_alg) {
	case AES_XCBC:
		job->u.XCBC._k1_expanded = session->auth.xcbc.k1_expanded;
		job->u.XCBC._k2 = session->auth.xcbc.k2;
		job->u.XCBC._k3 = session->auth.xcbc.k3;

		job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		break;

	case AES_CCM:
		job->u.CCM.aad = (uint8_t *)aad->va + 18;
		job->u.CCM.aad_len_in_bytes = session->aead.aad_len;
		job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		job->iv++;
		break;

	case AES_CMAC:
		job->u.CMAC._key_expanded = session->auth.cmac.expkey;
		job->u.CMAC._skey1 = session->auth.cmac.skey1;
		job->u.CMAC._skey2 = session->auth.cmac.skey2;
		job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		break;

	case AES_GMAC:
		if (session->cipher.mode == GCM) {
			job->u.GCM.aad = aad->va;
			job->u.GCM.aad_len_in_bytes = session->aead.aad_len;
		} else {
			/* For GMAC */
			job->u.GCM.aad = buf;
			job->u.GCM.aad_len_in_bytes = len;
			job->cipher_mode = GCM;
		}
		job->aes_enc_key_expanded = &session->cipher.gcm_key;
		job->aes_dec_key_expanded = &session->cipher.gcm_key;
		break;

	case IMB_AUTH_CHACHA20_POLY1305:
		job->u.CHACHA20_POLY1305.aad = aad->va;
		job->u.CHACHA20_POLY1305.aad_len_in_bytes =
			session->aead.aad_len;
		job->aes_enc_key_expanded =
			session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
			session->cipher.expanded_aes_keys.encode;
		break;
	default:
		job->u.HMAC._hashed_auth_key_xor_ipad =
				session->auth.pads.inner;
		job->u.HMAC._hashed_auth_key_xor_opad =
				session->auth.pads.outer;

		if (job->cipher_mode == DES3) {
			job->aes_enc_key_expanded =
				session->cipher.exp_3des_keys.ks_ptr;
			job->aes_dec_key_expanded =
				session->cipher.exp_3des_keys.ks_ptr;
		} else {
			job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
			job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		}
	}

	/*
	 * Multi-buffer library current only support returning a truncated
	 * digest length as specified in the relevant IPsec RFCs
	 */

	/* Set digest location and length */
	job->auth_tag_output = digest;
	job->auth_tag_output_len_in_bytes = session->auth.gen_digest_len;

	/* Set IV parameters */
	job->iv_len_in_bytes = session->iv.length;

	/* Data Parameters */
	job->src = buf;
	job->dst = (uint8_t *)buf + sofs.ofs.cipher.head;
	job->cipher_start_src_offset_in_bytes = sofs.ofs.cipher.head;
	job->hash_start_src_offset_in_bytes = sofs.ofs.auth.head;
	if (job->hash_alg == AES_GMAC && session->cipher.mode != GCM) {
		job->msg_len_to_hash_in_bytes = 0;
		job->msg_len_to_cipher_in_bytes = 0;
	} else {
		job->msg_len_to_hash_in_bytes = len - sofs.ofs.auth.head -
			sofs.ofs.auth.tail;
		job->msg_len_to_cipher_in_bytes = len - sofs.ofs.cipher.head -
			sofs.ofs.cipher.tail;
	}

	job->user_data = udata;
}

/**
 * Process a crypto operation and complete a JOB_AES_HMAC job structure for
 * submission to the multi buffer library for processing.
 *
 * @param	qp	queue pair
 * @param	job	JOB_AES_HMAC structure to fill
 * @param	m	mbuf to process
 *
 * @return
 * - Completed JOB_AES_HMAC structure pointer on success
 * - NULL pointer if completion of JOB_AES_HMAC structure isn't possible
 */
static inline int
set_mb_job_params(JOB_AES_HMAC *job, struct ipsec_mb_qp *qp,
		struct rte_crypto_op *op, uint8_t *digest_idx)
{
	struct rte_mbuf *m_src = op->sym->m_src, *m_dst;
	struct aesni_mb_qp_data *qp_data = ipsec_mb_get_qp_private_data(qp);
	struct aesni_mb_session *session;
	uint32_t m_offset, oop;

	session = ipsec_mb_get_session_private(qp, op);
	if (session == NULL) {
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_SESSION;
		return -1;
	}

	/* Set crypto operation */
	job->chain_order = session->chain_order;

	/* Set cipher parameters */
	job->cipher_direction = session->cipher.direction;
	job->cipher_mode = session->cipher.mode;

	job->aes_key_len_in_bytes = session->cipher.key_length_in_bytes;

	/* Set authentication parameters */
	job->hash_alg = session->auth.algo;

	const int aead = is_aead_algo(job->hash_alg, job->cipher_mode);

	switch (job->hash_alg) {
	case AES_XCBC:
		job->u.XCBC._k1_expanded = session->auth.xcbc.k1_expanded;
		job->u.XCBC._k2 = session->auth.xcbc.k2;
		job->u.XCBC._k3 = session->auth.xcbc.k3;

		job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		break;

	case AES_CCM:
		job->u.CCM.aad = op->sym->aead.aad.data + 18;
		job->u.CCM.aad_len_in_bytes = session->aead.aad_len;
		job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		break;

	case AES_CMAC:
		job->u.CMAC._key_expanded = session->auth.cmac.expkey;
		job->u.CMAC._skey1 = session->auth.cmac.skey1;
		job->u.CMAC._skey2 = session->auth.cmac.skey2;
		job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		break;

	case AES_GMAC:
		if (session->cipher.mode == GCM) {
			job->u.GCM.aad = op->sym->aead.aad.data;
			job->u.GCM.aad_len_in_bytes = session->aead.aad_len;
		} else {
			/* For GMAC */
			job->u.GCM.aad = rte_pktmbuf_mtod_offset(m_src,
					uint8_t *, op->sym->auth.data.offset);
			job->u.GCM.aad_len_in_bytes = op->sym->auth.data.length;
			job->cipher_mode = GCM;
		}
		job->aes_enc_key_expanded = &session->cipher.gcm_key;
		job->aes_dec_key_expanded = &session->cipher.gcm_key;
		break;
	case IMB_AUTH_ZUC_EIA3_BITLEN:
		job->u.ZUC_EIA3._key = session->auth.zuc_auth_key;
		job->u.ZUC_EIA3._iv = rte_crypto_op_ctod_offset(op, uint8_t *,
						session->auth_iv.offset);
		break;
	case IMB_AUTH_SNOW3G_UIA2_BITLEN:
		job->u.SNOW3G_UIA2._key = (void *)
			&session->auth.pKeySched_snow3g_auth;
		job->u.SNOW3G_UIA2._iv =
			rte_crypto_op_ctod_offset(op, uint8_t *,
						session->auth_iv.offset);
		break;
	case IMB_AUTH_KASUMI_UIA1:
		job->u.KASUMI_UIA1._key = (void *)
			&session->auth.pKeySched_kasumi_auth;
		break;
	case IMB_AUTH_CHACHA20_POLY1305:
		job->u.CHACHA20_POLY1305.aad = op->sym->aead.aad.data;
		job->u.CHACHA20_POLY1305.aad_len_in_bytes =
			session->aead.aad_len;
		job->aes_enc_key_expanded =
			session->cipher.expanded_aes_keys.encode;
		job->aes_dec_key_expanded =
			session->cipher.expanded_aes_keys.encode;
		break;
	default:
		job->u.HMAC._hashed_auth_key_xor_ipad =
			session->auth.pads.inner;
		job->u.HMAC._hashed_auth_key_xor_opad =
			session->auth.pads.outer;

		if (job->cipher_mode == DES3) {
			job->aes_enc_key_expanded =
				session->cipher.exp_3des_keys.ks_ptr;
			job->aes_dec_key_expanded =
				session->cipher.exp_3des_keys.ks_ptr;
		} else {
			job->aes_enc_key_expanded =
				session->cipher.expanded_aes_keys.encode;
			job->aes_dec_key_expanded =
				session->cipher.expanded_aes_keys.decode;
		}
	}

	if (aead)
		m_offset = op->sym->aead.data.offset;
	else
		m_offset = op->sym->cipher.data.offset;

	if (job->cipher_mode == IMB_CIPHER_ZUC_EEA3) {
		job->aes_enc_key_expanded = session->cipher.zuc_cipher_key;
		job->aes_dec_key_expanded = session->cipher.zuc_cipher_key;
	} else if (job->cipher_mode == IMB_CIPHER_SNOW3G_UEA2_BITLEN) {
		job->enc_keys = &session->cipher.pKeySched_snow3g_cipher;
		m_offset = 0;
	} else if (job->cipher_mode == IMB_CIPHER_KASUMI_UEA1_BITLEN) {
		job->enc_keys = &session->cipher.pKeySched_kasumi_cipher;
		m_offset = 0;
	}

	if (!op->sym->m_dst) {
		/* in-place operation */
		m_dst = m_src;
		oop = 0;
	} else if (op->sym->m_dst == op->sym->m_src) {
		/* in-place operation */
		m_dst = m_src;
		oop = 0;
	} else {
		/* out-of-place operation */
		m_dst = op->sym->m_dst;
		oop = 1;
	}

	/* Set digest output location */
	if (job->hash_alg != NULL_HASH &&
			session->auth.operation == RTE_CRYPTO_AUTH_OP_VERIFY) {
		job->auth_tag_output = qp_data->temp_digests[*digest_idx];
		*digest_idx = (*digest_idx + 1) % MAX_JOBS;
	} else {
		if (aead)
			job->auth_tag_output = op->sym->aead.digest.data;
		else
			job->auth_tag_output = op->sym->auth.digest.data;

		if (session->auth.req_digest_len !=
				session->auth.gen_digest_len) {
			job->auth_tag_output =
				qp_data->temp_digests[*digest_idx];
			*digest_idx = (*digest_idx + 1) % MAX_JOBS;
		}
	}
	/*
	 * Multi-buffer library current only support returning a truncated
	 * digest length as specified in the relevant IPsec RFCs
	 */

	/* Set digest length */
	job->auth_tag_output_len_in_bytes = session->auth.gen_digest_len;

	/* Set IV parameters */
	job->iv_len_in_bytes = session->iv.length;

	/* Data Parameters */
	job->src = rte_pktmbuf_mtod(m_src, uint8_t *);
	job->dst = rte_pktmbuf_mtod_offset(m_dst, uint8_t *, m_offset);

	switch (job->hash_alg) {
	case AES_CCM:
		job->cipher_start_src_offset_in_bytes =
				op->sym->aead.data.offset;
		job->msg_len_to_cipher_in_bytes = op->sym->aead.data.length;
		job->hash_start_src_offset_in_bytes = op->sym->aead.data.offset;
		job->msg_len_to_hash_in_bytes = op->sym->aead.data.length;

		job->iv = rte_crypto_op_ctod_offset(op, uint8_t *,
			session->iv.offset + 1);
		break;

	case AES_GMAC:
		if (session->cipher.mode == GCM) {
			job->cipher_start_src_offset_in_bytes =
					op->sym->aead.data.offset;
			job->hash_start_src_offset_in_bytes =
					op->sym->aead.data.offset;
			job->msg_len_to_cipher_in_bytes =
					op->sym->aead.data.length;
			job->msg_len_to_hash_in_bytes =
					op->sym->aead.data.length;
		} else {
			job->cipher_start_src_offset_in_bytes =
					op->sym->auth.data.offset;
			job->hash_start_src_offset_in_bytes =
					op->sym->auth.data.offset;
			job->msg_len_to_cipher_in_bytes = 0;
			job->msg_len_to_hash_in_bytes = 0;
		}

		job->iv = rte_crypto_op_ctod_offset(op, uint8_t *,
				session->iv.offset);
		break;

	case IMB_AUTH_CHACHA20_POLY1305:
		job->cipher_start_src_offset_in_bytes =
			op->sym->aead.data.offset;
		job->hash_start_src_offset_in_bytes =
			op->sym->aead.data.offset;
		job->msg_len_to_cipher_in_bytes =
				op->sym->aead.data.length;
		job->msg_len_to_hash_in_bytes =
					op->sym->aead.data.length;

		job->iv = rte_crypto_op_ctod_offset(op, uint8_t *,
				session->iv.offset);
		break;
	default:
		/* For SNOW3G, length and offsets are already in bits */
		job->cipher_start_src_offset_in_bytes =
				op->sym->cipher.data.offset;
		job->msg_len_to_cipher_in_bytes = op->sym->cipher.data.length;

		job->hash_start_src_offset_in_bytes = auth_start_offset(op,
				session, oop);
		job->msg_len_to_hash_in_bytes = op->sym->auth.data.length;

		job->iv = rte_crypto_op_ctod_offset(op, uint8_t *,
			session->iv.offset);
	}

	if (job->cipher_mode == IMB_CIPHER_ZUC_EEA3)
		job->msg_len_to_cipher_in_bytes >>= 3;
	else if (job->hash_alg == IMB_AUTH_KASUMI_UIA1)
		job->msg_len_to_hash_in_bytes >>= 3;

	/* Set user data to be crypto operation data struct */
	job->user_data = op;

	return 0;
}

#ifdef AESNI_MB_DOCSIS_SEC_ENABLED
/**
 * Process a crypto operation containing a security op and complete a
 * JOB_AES_HMAC job structure for submission to the multi buffer library for
 * processing.
 */
static inline int
set_sec_mb_job_params(JOB_AES_HMAC *job, struct ipsec_mb_qp *qp,
			struct rte_crypto_op *op, uint8_t *digest_idx)
{
	struct aesni_mb_qp_data *qp_data = ipsec_mb_get_qp_private_data(qp);
	struct rte_mbuf *m_src, *m_dst;
	struct rte_crypto_sym_op *sym;
	struct aesni_mb_session *session = NULL;

	if (unlikely(op->sess_type != RTE_CRYPTO_OP_SECURITY_SESSION)) {
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_SESSION;
		return -1;
	}
	session = (struct aesni_mb_session *)
		get_sec_session_private_data(op->sym->sec_session);

	if (unlikely(session == NULL)) {
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_SESSION;
		return -1;
	}
	/* Only DOCSIS protocol operations supported now */
	if (session->cipher.mode != IMB_CIPHER_DOCSIS_SEC_BPI ||
			session->auth.algo != IMB_AUTH_DOCSIS_CRC32) {
		op->status = RTE_CRYPTO_OP_STATUS_ERROR;
		return -1;
	}

	sym = op->sym;
	m_src = sym->m_src;

	if (likely(sym->m_dst == NULL || sym->m_dst == m_src)) {
		/* in-place operation */
		m_dst = m_src;
	} else {
		/* out-of-place operation not supported */
		op->status = RTE_CRYPTO_OP_STATUS_ERROR;
		return -ENOTSUP;
	}

	/* Set crypto operation */
	job->chain_order = session->chain_order;

	/* Set cipher parameters */
	job->cipher_direction = session->cipher.direction;
	job->cipher_mode = session->cipher.mode;

	job->aes_key_len_in_bytes = session->cipher.key_length_in_bytes;
	job->aes_enc_key_expanded = session->cipher.expanded_aes_keys.encode;
	job->aes_dec_key_expanded = session->cipher.expanded_aes_keys.decode;

	/* Set IV parameters */
	job->iv_len_in_bytes = session->iv.length;
	job->iv = (uint8_t *)op + session->iv.offset;

	/* Set authentication parameters */
	job->hash_alg = session->auth.algo;

	/* Set digest output location */
	job->auth_tag_output = qp_data->temp_digests[*digest_idx];
	*digest_idx = (*digest_idx + 1) % MAX_JOBS;

	/* Set digest length */
	job->auth_tag_output_len_in_bytes = session->auth.gen_digest_len;

	/* Set data parameters */
	job->src = rte_pktmbuf_mtod(m_src, uint8_t *);
	job->dst = rte_pktmbuf_mtod_offset(m_dst, uint8_t *,
						sym->cipher.data.offset);

	job->cipher_start_src_offset_in_bytes = sym->cipher.data.offset;
	job->msg_len_to_cipher_in_bytes = sym->cipher.data.length;

	job->hash_start_src_offset_in_bytes = sym->auth.data.offset;
	job->msg_len_to_hash_in_bytes = sym->auth.data.length;

	job->user_data = op;

	return 0;
}

static inline void
verify_docsis_sec_crc(JOB_AES_HMAC *job, uint8_t *status)
{
	uint16_t crc_offset;
	uint8_t *crc;

	if (!job->msg_len_to_hash_in_bytes)
		return;

	crc_offset = job->hash_start_src_offset_in_bytes +
			job->msg_len_to_hash_in_bytes -
			job->cipher_start_src_offset_in_bytes;
	crc = job->dst + crc_offset;

	/* Verify CRC (at the end of the message) */
	if (memcmp(job->auth_tag_output, crc, RTE_ETHER_CRC_LEN) != 0)
		*status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
}
#endif

static inline void
verify_digest(JOB_AES_HMAC *job, void *digest, uint16_t len, uint8_t *status)
{
	/* Verify digest if required */
	if (memcmp(job->auth_tag_output, digest, len) != 0)
		*status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
}

static inline void
generate_digest(JOB_AES_HMAC *job, struct rte_crypto_op *op,
		struct aesni_mb_session *sess)
{
	/* No extra copy needed */
	if (likely(sess->auth.req_digest_len == sess->auth.gen_digest_len))
		return;

	/*
	 * This can only happen for HMAC, so only digest
	 * for authentication algos is required
	 */
	memcpy(op->sym->auth.digest.data, job->auth_tag_output,
			sess->auth.req_digest_len);
}

/**
 * Process a completed job and return rte_mbuf which job processed
 *
 * @param qp		Queue Pair to process
 * @param job	JOB_AES_HMAC job to process
 *
 * @return
 * - Returns processed crypto operation.
 * - Returns NULL on invalid job
 */
static inline struct rte_crypto_op *
post_process_mb_job(struct ipsec_mb_qp *qp, JOB_AES_HMAC *job)
{
	struct rte_crypto_op *op = (struct rte_crypto_op *)job->user_data;
	struct aesni_mb_session *sess = NULL;
	uint32_t driver_id = ipsec_mb_get_driver_id(
						IPSEC_MB_PMD_TYPE_AESNI_MB);

#ifdef AESNI_MB_DOCSIS_SEC_ENABLED
	uint8_t is_docsis_sec = 0;

	if (op->sess_type == RTE_CRYPTO_OP_SECURITY_SESSION) {
		/*
		 * Assuming at this point that if it's a security type op, that
		 * this is for DOCSIS
		 */
		is_docsis_sec = 1;
		sess = get_sec_session_private_data(op->sym->sec_session);
	} else
#endif
	{
		sess = get_sym_session_private_data(op->sym->session,
						driver_id);
	}

	if (unlikely(sess == NULL)) {
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_SESSION;
		return op;
	}

	if (likely(op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED)) {
		switch (job->status) {
		case STS_COMPLETED:
			op->status = RTE_CRYPTO_OP_STATUS_SUCCESS;

			if (job->hash_alg == NULL_HASH)
				break;

			if (sess->auth.operation == RTE_CRYPTO_AUTH_OP_VERIFY) {
				if (is_aead_algo(job->hash_alg,
						sess->cipher.mode))
					verify_digest(job,
						op->sym->aead.digest.data,
						sess->auth.req_digest_len,
						&op->status);
#ifdef AESNI_MB_DOCSIS_SEC_ENABLED
				else if (is_docsis_sec)
					verify_docsis_sec_crc(job,
						&op->status);
#endif
				else
					verify_digest(job,
						op->sym->auth.digest.data,
						sess->auth.req_digest_len,
						&op->status);
			} else
				generate_digest(job, op, sess);
			break;
		default:
			op->status = RTE_CRYPTO_OP_STATUS_ERROR;
		}
	}

	/* Free session if a session-less crypto op */
	if (op->sess_type == RTE_CRYPTO_OP_SESSIONLESS) {
		memset(sess, 0, sizeof(struct aesni_mb_session));
		memset(op->sym->session, 0,
			rte_cryptodev_sym_get_existing_header_session_size(
				op->sym->session));
		rte_mempool_put(qp->sess_mp_priv, sess);
		rte_mempool_put(qp->sess_mp, op->sym->session);
		op->sym->session = NULL;
	}

	return op;
}

static inline void
post_process_mb_sync_job(JOB_AES_HMAC *job)
{
	uint32_t *st;

	st = job->user_data;
	st[0] = (job->status == STS_COMPLETED) ? 0 : EBADMSG;
}

/**
 * Process a completed JOB_AES_HMAC job and keep processing jobs until
 * get_completed_job return NULL
 *
 * @param qp		Queue Pair to process
 * @param job		JOB_AES_HMAC job
 *
 * @return
 * - Number of processed jobs
 */
static unsigned
handle_completed_jobs(struct ipsec_mb_qp *qp, MB_MGR *mb_mgr,
		JOB_AES_HMAC *job, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	struct rte_crypto_op *op = NULL;
	uint16_t processed_jobs = 0;

	while (job != NULL) {
		op = post_process_mb_job(qp, job);

		if (op) {
			ops[processed_jobs++] = op;
			qp->stats.dequeued_count++;
		} else {
			qp->stats.dequeue_err_count++;
			break;
		}
		if (processed_jobs == nb_ops)
			break;

		job = IMB_GET_COMPLETED_JOB(mb_mgr);
	}

	return processed_jobs;
}

static inline uint32_t
handle_completed_sync_jobs(JOB_AES_HMAC *job, MB_MGR *mb_mgr)
{
	uint32_t i;

	for (i = 0; job != NULL; i++, job = IMB_GET_COMPLETED_JOB(mb_mgr))
		post_process_mb_sync_job(job);

	return i;
}

static inline uint32_t
flush_mb_sync_mgr(MB_MGR *mb_mgr)
{
	JOB_AES_HMAC *job;

	job = IMB_FLUSH_JOB(mb_mgr);
	return handle_completed_sync_jobs(job, mb_mgr);
}

static inline uint16_t
flush_mb_mgr(struct ipsec_mb_qp *qp, MB_MGR *mb_mgr,
		struct rte_crypto_op **ops, uint16_t nb_ops)
{
	int processed_ops = 0;

	/* Flush the remaining jobs */
	JOB_AES_HMAC *job = IMB_FLUSH_JOB(mb_mgr);

	if (job)
		processed_ops += handle_completed_jobs(qp, mb_mgr, job,
				&ops[processed_ops], nb_ops - processed_ops);

	return processed_ops;
}

static inline JOB_AES_HMAC *
set_job_null_op(JOB_AES_HMAC *job, struct rte_crypto_op *op)
{
	job->chain_order = HASH_CIPHER;
	job->cipher_mode = NULL_CIPHER;
	job->hash_alg = NULL_HASH;
	job->cipher_direction = DECRYPT;

	/* Set user data to be crypto operation data struct */
	job->user_data = op;

	return job;
}

static uint16_t
aesni_mb_dequeue_burst(void *queue_pair, struct rte_crypto_op **ops,
		uint16_t nb_ops)
{
	struct ipsec_mb_qp *qp = queue_pair;
	MB_MGR *mb_mgr = qp->mb_mgr;
	struct rte_crypto_op *op;
	JOB_AES_HMAC *job;
	int retval, processed_jobs = 0;

	if (unlikely(nb_ops == 0 || mb_mgr == NULL))
		return 0;

	uint8_t digest_idx = qp->digest_idx;

	do {
		/* Get next free mb job struct from mb manager */
		job = IMB_GET_NEXT_JOB(mb_mgr);
		if (unlikely(job == NULL)) {
			/* if no free mb job structs we need to flush mb_mgr */
			processed_jobs += flush_mb_mgr(qp, mb_mgr,
					&ops[processed_jobs],
					nb_ops - processed_jobs);

			if (nb_ops == processed_jobs)
				break;

			job = IMB_GET_NEXT_JOB(mb_mgr);
		}

		/*
		 * Get next operation to process from ingress queue.
		 * There is no need to return the job to the MB_MGR
		 * if there are no more operations to process, since the MB_MGR
		 * can use that pointer again in next get_next calls.
		 */
		retval = rte_ring_dequeue(qp->ingress_queue, (void **)&op);
		if (retval < 0)
			break;

#ifdef AESNI_MB_DOCSIS_SEC_ENABLED
		if (op->sess_type == RTE_CRYPTO_OP_SECURITY_SESSION)
			retval = set_sec_mb_job_params(job, qp, op,
						&digest_idx);
		else
#endif
			retval = set_mb_job_params(job, qp, op,
				&digest_idx);

		if (unlikely(retval != 0)) {
			qp->stats.dequeue_err_count++;
			set_job_null_op(job, op);
		}

		/* Submit job to multi-buffer for processing */
#ifdef RTE_LIBRTE_PMD_AESNI_MB_DEBUG
		job = IMB_SUBMIT_JOB(mb_mgr);
#else
		job = IMB_SUBMIT_JOB_NOCHECK(mb_mgr);
#endif
		/*
		 * If submit returns a processed job then handle it,
		 * before submitting subsequent jobs
		 */
		if (job)
			processed_jobs += handle_completed_jobs(qp, mb_mgr,
					job, &ops[processed_jobs],
					nb_ops - processed_jobs);

	} while (processed_jobs < nb_ops);

	qp->digest_idx = digest_idx;

	if (processed_jobs < 1)
		processed_jobs += flush_mb_mgr(qp, mb_mgr,
				&ops[processed_jobs],
				nb_ops - processed_jobs);

	return processed_jobs;
}


static inline void
ipsec_mb_fill_error_code(struct rte_crypto_sym_vec *vec, int32_t err)
{
	uint32_t i;

	for (i = 0; i != vec->num; ++i)
		vec->status[i] = err;
}

static inline int
check_crypto_sgl(union rte_crypto_sym_ofs so, const struct rte_crypto_sgl *sgl)
{
	/* no multi-seg support with current AESNI-MB PMD */
	if (sgl->num != 1)
		return -ENOTSUP;
	else if (so.ofs.cipher.head + so.ofs.cipher.tail > sgl->vec[0].len)
		return -EINVAL;
	return 0;
}

static inline JOB_AES_HMAC *
submit_sync_job(MB_MGR *mb_mgr)
{
#ifdef RTE_LIBRTE_PMD_AESNI_MB_DEBUG
	return IMB_SUBMIT_JOB(mb_mgr);
#else
	return IMB_SUBMIT_JOB_NOCHECK(mb_mgr);
#endif
}

static inline uint32_t
generate_sync_dgst(struct rte_crypto_sym_vec *vec,
	const uint8_t dgst[][DIGEST_LENGTH_MAX], uint32_t len)
{
	uint32_t i, k;

	for (i = 0, k = 0; i != vec->num; i++) {
		if (vec->status[i] == 0) {
			memcpy(vec->digest[i].va, dgst[i], len);
			k++;
		}
	}

	return k;
}

static inline uint32_t
verify_sync_dgst(struct rte_crypto_sym_vec *vec,
	const uint8_t dgst[][DIGEST_LENGTH_MAX], uint32_t len)
{
	uint32_t i, k;

	for (i = 0, k = 0; i != vec->num; i++) {
		if (vec->status[i] == 0) {
			if (memcmp(vec->digest[i].va, dgst[i], len) != 0)
				vec->status[i] = EBADMSG;
			else
				k++;
		}
	}

	return k;
}

static uint32_t
aesni_mb_process_bulk(struct rte_cryptodev *dev,
	struct rte_cryptodev_sym_session *sess, union rte_crypto_sym_ofs sofs,
	struct rte_crypto_sym_vec *vec)
{
	int32_t ret;
	uint32_t i, j, k, len;
	void *buf;
	JOB_AES_HMAC *job;
	MB_MGR *mb_mgr;
	struct aesni_mb_session *s;
	uint8_t tmp_dgst[vec->num][DIGEST_LENGTH_MAX];

	s = get_sym_session_private_data(sess, dev->driver_id);
	if (s == NULL) {
		ipsec_mb_fill_error_code(vec, EINVAL);
		return 0;
	}

	/* get per-thread MB MGR, create one if needed */
	mb_mgr = get_per_thread_mb_mgr();
	if (unlikely(mb_mgr == NULL))
		return 0;

	for (i = 0, j = 0, k = 0; i != vec->num; i++) {
		ret = check_crypto_sgl(sofs, vec->sgl + i);
		if (ret != 0) {
			vec->status[i] = ret;
			continue;
		}

		buf = vec->sgl[i].vec[0].base;
		len = vec->sgl[i].vec[0].len;

		job = IMB_GET_NEXT_JOB(mb_mgr);
		if (job == NULL) {
			k += flush_mb_sync_mgr(mb_mgr);
			job = IMB_GET_NEXT_JOB(mb_mgr);
			RTE_ASSERT(job != NULL);
		}

		/* Submit job for processing */
		set_cpu_mb_job_params(job, s, sofs, buf, len, &vec->iv[i],
			&vec->aad[i], tmp_dgst[i], &vec->status[i]);
		job = submit_sync_job(mb_mgr);
		j++;

		/* handle completed jobs */
		k += handle_completed_sync_jobs(job, mb_mgr);
	}

	/* flush remaining jobs */
	while (k != j)
		k += flush_mb_sync_mgr(mb_mgr);

	/* finish processing for successful jobs: check/update digest */
	if (k != 0) {
		if (s->auth.operation == RTE_CRYPTO_AUTH_OP_VERIFY)
			k = verify_sync_dgst(vec,
				(const uint8_t (*)[DIGEST_LENGTH_MAX])tmp_dgst,
				s->auth.req_digest_len);
		else
			k = generate_sync_dgst(vec,
				(const uint8_t (*)[DIGEST_LENGTH_MAX])tmp_dgst,
				s->auth.req_digest_len);
	}

	return k;
}

struct rte_cryptodev_ops aes_mb_pmd_ops = {
	.dev_configure = ipsec_mb_pmd_config,
	.dev_start = ipsec_mb_pmd_start,
	.dev_stop = ipsec_mb_pmd_stop,
	.dev_close = ipsec_mb_pmd_close,

	.stats_get = ipsec_mb_pmd_stats_get,
	.stats_reset = ipsec_mb_pmd_stats_reset,

	.dev_infos_get = ipsec_mb_pmd_info_get,

	.queue_pair_setup = ipsec_mb_pmd_qp_setup,
	.queue_pair_release = ipsec_mb_pmd_qp_release,

	.sym_cpu_process = aesni_mb_process_bulk,

	.sym_session_get_size = ipsec_mb_pmd_sym_session_get_size,
	.sym_session_configure = ipsec_mb_pmd_sym_session_configure,
	.sym_session_clear = ipsec_mb_pmd_sym_session_clear
};

#ifdef AESNI_MB_DOCSIS_SEC_ENABLED
/**
 * Configure a aesni multi-buffer session from a security session
 * configuration
 */
static int
aesni_mb_pmd_sec_sess_create(void *dev, struct rte_security_session_conf *conf,
		struct rte_security_session *sess,
		struct rte_mempool *mempool)
{
	void *sess_private_data;
	struct rte_cryptodev *cdev = (struct rte_cryptodev *)dev;
	int ret;

	if (conf->action_type != RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL ||
			conf->protocol != RTE_SECURITY_PROTOCOL_DOCSIS) {
		IPSEC_MB_LOG(ERR, "Invalid security protocol");
		return -EINVAL;
	}

	if (rte_mempool_get(mempool, &sess_private_data)) {
		IPSEC_MB_LOG(ERR, "Couldn't get object from session mempool");
		return -ENOMEM;
	}

	ret = aesni_mb_set_docsis_sec_session_parameters(cdev, conf,
			sess_private_data);

	if (ret != 0) {
		IPSEC_MB_LOG(ERR, "Failed to configure session parameters");

		/* Return session to mempool */
		rte_mempool_put(mempool, sess_private_data);
		return ret;
	}

	set_sec_session_private_data(sess, sess_private_data);

	return ret;
}

/** Clear the memory of session so it does not leave key material behind */
static int
aesni_mb_pmd_sec_sess_destroy(void *dev __rte_unused,
		struct rte_security_session *sess)
{
	void *sess_priv = get_sec_session_private_data(sess);

	if (sess_priv) {
		struct rte_mempool *sess_mp = rte_mempool_from_obj(sess_priv);

		memset(sess_priv, 0, sizeof(struct aesni_mb_session));
		set_sec_session_private_data(sess, NULL);
		rte_mempool_put(sess_mp, sess_priv);
	}
	return 0;
}

static const struct rte_cryptodev_capabilities
					aesni_mb_pmd_security_crypto_cap[] = {
	{	/* AES DOCSIS BPI */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_DOCSISBPI,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 16
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}, }
		}, }
	},

	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

static const struct rte_security_capability aesni_mb_pmd_security_cap[] = {
	{	/* DOCSIS Uplink */
		.action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
		.protocol = RTE_SECURITY_PROTOCOL_DOCSIS,
		.docsis = {
			.direction = RTE_SECURITY_DOCSIS_UPLINK
		},
		.crypto_capabilities = aesni_mb_pmd_security_crypto_cap
	},
	{	/* DOCSIS Downlink */
		.action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
		.protocol = RTE_SECURITY_PROTOCOL_DOCSIS,
		.docsis = {
			.direction = RTE_SECURITY_DOCSIS_DOWNLINK
		},
		.crypto_capabilities = aesni_mb_pmd_security_crypto_cap
	},
	{
		.action = RTE_SECURITY_ACTION_TYPE_NONE
	}
};

/** Get security capabilities for aesni multi-buffer */
static const struct rte_security_capability *
aesni_mb_pmd_sec_capa_get(void *device __rte_unused)
{
	return aesni_mb_pmd_security_cap;
}

static struct rte_security_ops aesni_mb_pmd_sec_ops = {
		.session_create = aesni_mb_pmd_sec_sess_create,
		.session_update = NULL,
		.session_stats_get = NULL,
		.session_destroy = aesni_mb_pmd_sec_sess_destroy,
		.set_pkt_metadata = NULL,
		.capabilities_get = aesni_mb_pmd_sec_capa_get
};

struct rte_security_ops *rte_aesni_mb_pmd_sec_ops = &aesni_mb_pmd_sec_ops;

static int
aesni_mb_configure_dev(struct rte_cryptodev *dev)
{
	struct rte_security_ctx *security_instance;

	security_instance = rte_malloc("aesni_mb_sec",
				sizeof(struct rte_security_ctx),
				RTE_CACHE_LINE_SIZE);
	if (security_instance != NULL) {
		security_instance->device = (void *)dev;
		security_instance->ops = rte_aesni_mb_pmd_sec_ops;
		security_instance->sess_cnt = 0;
		dev->security_ctx = security_instance;

		return 0;
	}

	return -ENOMEM;
}

#endif

static int
cryptodev_aesni_mb_probe(struct rte_vdev_device *vdev)
{
	return cryptodev_ipsec_mb_create(vdev, IPSEC_MB_PMD_TYPE_AESNI_MB);
}

static struct rte_vdev_driver cryptodev_aesni_mb_pmd_drv = {
	.probe = cryptodev_aesni_mb_probe,
	.remove = cryptodev_ipsec_mb_remove
};

static struct cryptodev_driver aesni_mb_crypto_drv;

RTE_PMD_REGISTER_VDEV(CRYPTODEV_NAME_AESNI_MB_PMD,
	cryptodev_aesni_mb_pmd_drv);
RTE_PMD_REGISTER_ALIAS(CRYPTODEV_NAME_AESNI_MB_PMD, cryptodev_aesni_mb_pmd);
RTE_PMD_REGISTER_PARAM_STRING(CRYPTODEV_NAME_AESNI_MB_PMD,
			"max_nb_queue_pairs=<int> socket_id=<int>");
RTE_PMD_REGISTER_CRYPTO_DRIVER(
	aesni_mb_crypto_drv,
	cryptodev_aesni_mb_pmd_drv.driver,
	pmd_driver_id_aesni_mb);

/* Constructor function to register aesni-mb PMD */
RTE_INIT(ipsec_mb_register_aesni_mb)
{
	struct ipsec_mb_pmd_data *aesni_mb_data =
		&ipsec_mb_pmds[IPSEC_MB_PMD_TYPE_AESNI_MB];

	aesni_mb_data->caps = aesni_mb_capabilities;
	aesni_mb_data->dequeue_burst = aesni_mb_dequeue_burst;
	aesni_mb_data->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
			RTE_CRYPTODEV_FF_OOP_LB_IN_LB_OUT |
			RTE_CRYPTODEV_FF_SYM_CPU_CRYPTO |
			RTE_CRYPTODEV_FF_NON_BYTE_ALIGNED_DATA |
			RTE_CRYPTODEV_FF_SYM_SESSIONLESS;

	aesni_mb_data->internals_priv_size = 0;
	aesni_mb_data->ops = &aes_mb_pmd_ops;
	aesni_mb_data->qp_priv_size = sizeof(struct aesni_mb_qp_data);
	aesni_mb_data->queue_pair_configure = NULL;
#ifdef AESNI_MB_DOCSIS_SEC_ENABLED
	aesni_mb_data->security_ops = &aesni_mb_pmd_sec_ops;
	aesni_mb_data->dev_config = aesni_mb_configure_dev;
	aesni_mb_data->feature_flags |= RTE_CRYPTODEV_FF_SECURITY;
#endif
	aesni_mb_data->session_configure = aesni_mb_session_configure;
	aesni_mb_data->session_priv_size = sizeof(struct aesni_mb_session);
}

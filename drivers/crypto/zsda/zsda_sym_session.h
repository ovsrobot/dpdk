/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_SYM_SESSION_H_
#define _ZSDA_SYM_SESSION_H_

#include "zsda_sym_pmd.h"

#define ZSDA_SYM_XTS_IV_SLBA_OFF  (8)
#define ZSDA_SYM_XTS_256_SKEY_LEN (16)
#define ZSDA_SYM_XTS_512_SKEY_LEN (32)
#define ZSDA_SYM_XTS_256_KEY2_OFF (16)
#define ZSDA_SYM_XTS_256_KEY1_OFF (48)
#define ZSDA_SYM_XTS_512_KEY1_OFF (32)
#define ZSDA_SYM_MIN_SRC_LEN_HASH (16)

#define ZSDA_AES256_ROUND_NUM	    (10)
#define ZSDA_AES512_ROUND_NUM	    (14)
#define ZSDA_AES_MAX_EXP_BYTE_SIZE  (240)
#define ZSDA_AES_MAX_KEY_BYTE_LEN   (32)
#define ZSDA_SM4_MAX_EXP_DWORD_SIZE (32)

#define ZSDA_AES_LBADS_0	  (0)
#define ZSDA_AES_LBADS_512	  (512)
#define ZSDA_AES_LBADS_4096	  (4096)
#define ZSDA_AES_LBADS_8192	  (8192)

#define ZSDA_AES_LBADS_INDICATE_0       (0x0)
#define ZSDA_AES_LBADS_INDICATE_512     (0x9)
#define ZSDA_AES_LBADS_INDICATE_4096    (0xC)
#define ZSDA_AES_LBADS_INDICATE_8192    (0xD)
#define ZSDA_AES_LBADS_INDICATE_INVALID (0xff)


void zsda_reverse_memcpy(uint8_t *dst, const uint8_t *src, size_t n);

int zsda_crypto_set_session_parameters(void *sess_priv,
				       struct rte_crypto_sym_xform *xform);

#endif /* _ZSDA_SYM_SESSION_H_ */

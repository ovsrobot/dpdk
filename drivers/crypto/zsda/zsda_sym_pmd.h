/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_SYM_PMD_H_
#define _ZSDA_SYM_PMD_H_

#include "cryptodev_pmd.h"

#include "zsda_logs.h"
#include "zsda_common.h"
#include "zsda_device.h"
#include "zsda_qp.h"

/** ZSDA Symmetric Crypto PMD driver name */
#define CRYPTODEV_NAME_ZSDA_SYM_PMD crypto_zsda
#define ZSDA_CIPHER_KEY_MAX_LEN 64

extern uint8_t zsda_sym_driver_id;

/** private data structure for a ZSDA device.
 * This ZSDA device is a device offering only symmetric crypto service,
 * there can be one of these on each zsda_pci_device (VF).
 */
struct zsda_sym_dev_private {
	struct zsda_pci_device *zsda_pci_dev;
	/**< The zsda pci device hosting the service */

	const struct rte_cryptodev_capabilities *zsda_dev_capabilities;
	/* ZSDA device symmetric crypto capabilities */
	const struct rte_memzone *capa_mz;
	/* Shared memzone for storing capabilities */
};

enum zsda_sym_chain_order {
	ZSDA_SYM_CHAIN_ONLY_CIPHER,
	ZSDA_SYM_CHAIN_ONLY_AUTH,
	ZSDA_SYM_CHAIN_CIPHER_AUTH,
	ZSDA_SYM_CHAIN_AUTH_CIPHER,
	ZSDA_SYM_CHAIN_NOT_SUPPORTED
};
struct zsda_sym_session {
	enum zsda_sym_chain_order chain_order;

	/* Cipher Parameters */
	struct {
		enum rte_crypto_cipher_operation op;
		enum rte_crypto_cipher_algorithm algo;
		struct {
			uint8_t data[ZSDA_CIPHER_KEY_MAX_LEN];
			size_t length;
		} key_encry;
		struct {
			uint8_t data[ZSDA_CIPHER_KEY_MAX_LEN];
			size_t length;
		} key_decry;
		struct {
			uint32_t offset;
			size_t length;
		} iv;

		uint32_t dataunit_len;
		uint8_t lbads;
	} cipher;

	struct {
		enum rte_crypto_auth_operation op;
		/* Auth operation */
		enum rte_crypto_auth_algorithm algo;
		/* Auth algorithm */
		uint16_t digest_length;
	} auth;

	bool cipher_first;
};

__rte_weak int
zsda_encry_match(const void *op_in);

__rte_weak int
zsda_decry_match(const void *op_in);

__rte_weak int
zsda_hash_match(const void *op_in);

__rte_weak int
zsda_build_cipher_request(void *op_in, const struct zsda_queue *queue,
			 void **op_cookies, const uint16_t new_tail);

__rte_weak int
zsda_build_hash_request(void *op_in, const struct zsda_queue *queue,
		       void **op_cookies, const uint16_t new_tail);

__rte_weak int
zsda_crypto_callback(void *cookie_in, struct zsda_cqe *cqe);

__rte_weak int
zsda_crypto_set_session_parameters(void *sess_priv,
				struct rte_crypto_sym_xform *xform);

int zsda_sym_dev_create(struct zsda_pci_device *zsda_pci_dev);

int zsda_sym_dev_destroy(struct zsda_pci_device *zsda_pci_dev);

#endif /* _ZSDA_SYM_PMD_H_ */

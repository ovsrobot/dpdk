/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Roman Khromenok
 */

#ifndef RTE_TRANSCEIVER_H
#define RTE_TRANSCEIVER_H

/**
 * @file
 *
 * Pluggable transceiver module EEPROM decoding.
 *
 * Decode the EEPROM of pluggable transceiver modules (SFP, QSFP)
 * according to the SFF specifications.
 * The decoding does not depend on any device or driver:
 * the EEPROM data may be read with rte_eth_dev_get_module_eeprom()
 * or from any other source using the same layout,
 * for example the Linux ethtool ioctls ETHTOOL_GMODULEINFO
 * and ETHTOOL_GMODULEEEPROM.
 */

#include <stdint.h>

#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Module EEPROM layouts.
 * The values are the same as the RTE_ETH_MODULE_SFF_* values
 * reported by rte_eth_dev_get_module_info().
 */
#define RTE_TRANSCEIVER_SFF_8079		0x1 /**< SFF-8079 (SFP), page A0h */
#define RTE_TRANSCEIVER_SFF_8079_LEN		256 /**< SFF-8079 EEPROM length */
#define RTE_TRANSCEIVER_SFF_8472		0x2 /**< SFF-8472 (SFP), pages A0h and A2h */
#define RTE_TRANSCEIVER_SFF_8472_LEN		512 /**< SFF-8472 EEPROM length */
#define RTE_TRANSCEIVER_SFF_8636		0x3 /**< SFF-8636 (QSFP28) */
#define RTE_TRANSCEIVER_SFF_8636_LEN		256 /**< SFF-8636 lower and page 00h length */
#define RTE_TRANSCEIVER_SFF_8636_MAX_LEN	640 /**< SFF-8636 length with page 03h */
#define RTE_TRANSCEIVER_SFF_8436		0x4 /**< SFF-8436 (QSFP+) */
#define RTE_TRANSCEIVER_SFF_8436_LEN		256 /**< SFF-8436 lower and page 00h length */
#define RTE_TRANSCEIVER_SFF_8436_MAX_LEN	640 /**< SFF-8436 length with page 03h */

/**
 * Callback invoked by rte_transceiver_decode() for each decoded field.
 *
 * @param name
 *   Field name, for example "Vendor name" or "Laser bias current".
 *   The same name may be reported more than once,
 *   for example when a module complies with several transceiver types.
 * @param value
 *   Field value as a human readable string, including the unit if any.
 * @param arg
 *   The opaque argument passed to rte_transceiver_decode().
 *
 * @note The field names and the value formats are intended for display.
 *   They follow the ethtool output and may change in future releases,
 *   so they should not be parsed or matched by applications.
 */
typedef void (*rte_transceiver_field_cb)(const char *name, const char *value,
		void *arg);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Decode pluggable module EEPROM data according to the SFF specifications.
 *
 * The function does not access any device
 * and can be called without EAL initialization.
 *
 * @param type
 *   Module EEPROM layout, one of RTE_TRANSCEIVER_SFF_*.
 * @param data
 *   Module EEPROM data starting at offset 0.
 * @param length
 *   Length of the data in bytes.
 *   SFF-8472 diagnostics are decoded only if at least
 *   RTE_TRANSCEIVER_SFF_8472_LEN bytes are provided.
 *   SFF-8436 and SFF-8636 thresholds and alarm flags are decoded
 *   only if at least RTE_TRANSCEIVER_SFF_8636_MAX_LEN bytes are provided.
 * @param cb
 *   Callback invoked for each decoded field.
 * @param arg
 *   Opaque argument passed to the callback.
 * @return
 *   - (0) if successful.
 *   - (-EINVAL) if bad parameter or data is too short for the module type.
 *   - (-ENOTSUP) if the module type is not supported.
 */
__rte_experimental
int
rte_transceiver_decode(uint32_t type, const uint8_t *data, uint32_t length,
		rte_transceiver_field_cb cb, void *arg);

#ifdef __cplusplus
}
#endif

#endif /* RTE_TRANSCEIVER_H */

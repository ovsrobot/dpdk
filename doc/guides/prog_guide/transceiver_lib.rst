..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Roman Khromenok

Transceiver Library
===================

The transceiver library decodes the EEPROM of pluggable transceiver modules
(SFP, QSFP) according to the SFF specifications,
for example the vendor, the transceiver type and the digital diagnostics.

The decoding does not depend on any device or driver,
and the library does not need EAL to be initialized.
The EEPROM data may come from different sources:

ethdev ports
   ``rte_eth_dev_get_module_info()`` gives the module type and EEPROM length,
   and ``rte_eth_dev_get_module_eeprom()`` reads the EEPROM.

Kernel ports
   The Linux ethtool ioctls ``ETHTOOL_GMODULEINFO`` and ``ETHTOOL_GMODULEEEPROM``
   give the same module types and EEPROM layout.


Supported Specifications
------------------------

The module type is one of the ``RTE_TRANSCEIVER_SFF_*`` values,
which are the same as the ``RTE_ETH_MODULE_SFF_*`` values of ethdev.

``RTE_TRANSCEIVER_SFF_8079``
   SFP identification, page A0h (256 bytes).

``RTE_TRANSCEIVER_SFF_8472``
   SFP identification and digital diagnostics, pages A0h and A2h (512 bytes).
   With external calibration, the calibrated values are reported.
   The Rx loss of signal and Tx fault state are reported
   if the module advertises them.

``RTE_TRANSCEIVER_SFF_8436`` and ``RTE_TRANSCEIVER_SFF_8636``
   QSFP+ and QSFP28 identification, diagnostics and per-lane status flags,
   lower page and page 00h (256 bytes).
   The thresholds and the alarm and warning flags are reported
   if page 03h is also provided (640 bytes).
   The channel status flags are latched and cleared on read by the module,
   so they report the events since the previous read of the module.


Usage
-----

``rte_transceiver_decode()`` calls a callback for each decoded field,
with the field name and the value as human readable strings.
The same name may be reported more than once,
for example when a module complies with several transceiver types.

The names and value formats follow the output of ethtool and are intended for display,
so applications should not parse them.

.. code-block:: c

   static void
   print_field(const char *name, const char *value, void *arg)
   {
           RTE_SET_USED(arg);
           printf("%-41s : %s\n", name, value);
   }

   struct rte_eth_dev_module_info info;
   struct rte_dev_eeprom_info eeprom = { 0 };
   uint8_t data[RTE_TRANSCEIVER_SFF_8636_MAX_LEN];

   if (rte_eth_dev_get_module_info(port_id, &info) == 0 &&
           info.eeprom_len <= sizeof(data)) {
           eeprom.length = info.eeprom_len;
           eeprom.data = data;
           if (rte_eth_dev_get_module_eeprom(port_id, &eeprom) == 0)
                   rte_transceiver_decode(info.type, data, eeprom.length,
                                   print_field, NULL);
   }

The decoded module EEPROM of an ethdev port is also available
with the telemetry command ``/ethdev/module_eeprom``
and the testpmd command ``show port (port_id) module_eeprom decode``.

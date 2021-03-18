..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018-2020.

NGBE Poll Mode Driver
======================

The NGBE PMD (librte_pmd_ngbe) provides poll mode driver support
for Wangxun 1 Gigabit Ethernet NICs.

Prerequisites
-------------

- Learning about Wangxun 10 Gigabit Ethernet NICs using
  `<https://www.net-swift.com/a/386.html>`_.

- Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup the basic DPDK environment.

Pre-Installation Configuration
------------------------------

Build Options
~~~~~~~~~~~~~

The following build-time options may be enabled on build time using.

``-Dc_args=`` meson argument (e.g. ``-Dc_args=-DRTE_LIBRTE_NGBE_DEBUG_RX``).

Please note that enabling debugging options may affect system performance.

- ``RTE_LIBRTE_NGBE_DEBUG_RX`` (undefined by default)

  Toggle display of receive fast path run-time messages.

- ``RTE_LIBRTE_NGBE_DEBUG_TX`` (undefined by default)

  Toggle display of transmit fast path run-time messages.

- ``RTE_LIBRTE_NGBE_DEBUG_TX_FREE`` (undefined by default)

  Toggle display of transmit descriptor clean messages.

Dynamic Logging Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~

One may leverage EAL option "--log-level" to change default levels
for the log types supported by the driver. The option is used with
an argument typically consisting of two parts separated by a colon.

NGBE PMD provides the following log types available for control:

- ``pmd.net.ngbe.driver`` (default level is **notice**)

  Affects driver-wide messages unrelated to any particular devices.

- ``pmd.net.ngbe.init`` (default level is **notice**)

  Extra logging of the messages during PMD initialization.

Driver compilation and testing
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.

Limitations or Known issues
---------------------------

Build with ICC is not supported yet.
Power8, ARMv7 and BSD are not supported yet.

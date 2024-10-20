..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (C), 2022, Linkdata Technology Co., Ltd.

SXE Poll Mode Driver
======================

The SXE PMD (librte_pmd_sxe) provides poll mode driver support
for Linkdata 1160-2X 10GE Ethernet Adapter.


Configuration
-------------

Dynamic Logging Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~

One may leverage EAL option "--log-level" to change default levels
for the log types supported by the driver. The option is used with
an argument typically consisting of two parts separated by a colon.

SXE PMD provides the following log types available for control:

- ``pmd.net.sxe.drv`` (default level is **DEBUG**)

  Affects driver-wide messages unrelated to any particular devices.

- ``pmd.net.sxe.init`` (default level is **DEBUG**)

  Extra logging of the messages during PMD initialization.

- ``pmd.net.sxe.rx`` (default level is **DEBUG**)

  Affects rx-wide messages.
- ``pmd.net.sxe.tx`` (default level is **DEBUG**)

  Affects tx-wide messages.
------------------------------

Refer to the document :ref:`compiling and testing a PMD for a NIC <pmd_build_and_test>`
for details.


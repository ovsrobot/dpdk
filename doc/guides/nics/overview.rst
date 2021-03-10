..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2016 6WIND S.A.

Overview of Networking Drivers
==============================

The networking drivers may be classified in two categories:

- physical for real devices
- virtual for emulated devices

Some physical devices may be shaped through a virtual layer as for
SR-IOV.
The interface seen in the virtual environment is a VF (Virtual Function).

The ethdev layer exposes an API to use the networking functions
of these devices.
The bottom half part of ethdev is implemented by the drivers.
Thus some features may not be implemented.

There are more differences between drivers regarding some internal properties,
portability or even documentation availability.
Most of these differences are summarized below.

More details about features can be found in :doc:`features`.

.. _table_net_pmd_features:

.. include:: overview_table.txt

.. Note::

   Features marked with "P" are partially supported. Refer to the appropriate
   NIC guide in the following sections for details.

The ethdev layer support below compile options for debug purpose:

- ``RTE_LIBRTE_ETHDEV_DEBUG`` (default **disabled**)

  Compile with debug code on data path.

- ``RTE_LIBRTE_ETHDEV_DEBUG_RX`` (default **disabled**)

  Compile with debug code on Rx data path.

- ``RTE_LIBRTE_ETHDEV_DEBUG_TX`` (default **disabled**)

  Compile with debug code on Tx data path.

.. Note::

   The lib_ethdev use above options to wrap debug code to trace invalid parameters on
   data path APIs, so performance downgrade is expected when enable those options.
   Each PMD can decide to reuse them to wrap their own debug code in the Rx/Tx path.

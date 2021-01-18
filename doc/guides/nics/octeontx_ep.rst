..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(C) 2020 Marvell.

OCTEON TX EP Poll Mode driver
===========================

The OCTEON TX EP ETHDEV PMD (**librte_pmd_octeontx_ep**) provides poll mode
ethdev driver support for the virtual functions (VF) of **Marvell OCTEON TX2**
and **Cavium OCTEON TX** families of adapters in SR-IOV context.

More information can be found at `Marvell Official Website
<https://www.marvell.com/embedded-processors/infrastructure-processors>`_.

Features
--------

Features of the OCTEON TX EP Ethdev PMD are:


Prerequisites
-------------

See :doc:`../platform/octeontx2` and `../platform/octeontx` for setup information.

Compile time Config Options
---------------------------

The following options may be modified in the ``config`` file.

- ``CONFIG_RTE_LIBRTE_OCTEONTX_EP_PMD`` (default ``y``)

  Toggle compilation of the ``librte_pmd_octeontx_ep`` driver.

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2017 Cavium, Inc

OCTEON TX FPAVF Mempool Driver
==============================

The OCTEON TX FPAVF PMD (**librte_mempool_octeontx**) is a mempool
driver for offload mempool device found in **Cavium OCTEON TX** SoC
family.

More information can be found at `Cavium, Inc Official Website
<http://www.cavium.com/OCTEON-TX_ARM_Processors.html>`_.

Features
--------

Features of the OCTEON TX FPAVF PMD are:

- 32 SR-IOV Virtual functions
- 32 Pools
- HW mempool manager

Supported OCTEON TX SoCs
------------------------

- CN83xx

Prerequisites
-------------

See :doc: `../platform/octeontx.rst` for setup information.


Driver Compilation
------------------

See :doc:`../linux_gsg/build_dpdk` for more information on compiling DPDK.


Initialization
--------------

The OCTEON TX fpavf mempool initialization similar to other mempool
drivers like ring. However user need to pass --base-virtaddr as
command line input to application example test_mempool.c application.

Example:

.. code-block:: console

    ./<build_dir>/app/test/dpdk-test -c 0xf --base-virtaddr=0x100000000000 \
                        --mbuf-pool-ops-name="octeontx_fpavf"

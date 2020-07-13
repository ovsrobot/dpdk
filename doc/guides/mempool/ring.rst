..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Intel Corporation.

Ring Mempool Driver
==============================

**rte_mempool_ring** is a pure SW mempool driver based on ``rte_ring``
DPDK library. This is a default mempool driver.
Following modes of operation are available for ``ring`` mempool driver
and can be selected via mempool ops API:

- ``ring_mp_mc``

  Underlying **rte_ring** operates in multi-thread producer,
  multi-thread consumer sync mode.

- ``ring_sp_sc``

  Underlying **rte_ring** operates in single-thread producer,
  single-thread consumer sync mode.

- ``ring_sp_mc``

  Underlying **rte_ring** operates in single-thread producer,
  multi-thread consumer sync mode.

- ``ring_mp_sc``

  Underlying **rte_ring** operates in multi-thread producer,
  single-thread consumer sync mode.


For more information about ``rte_ring`` structure, behaviour and available
synchronisation modes please refer to: :doc:`../prog_guide/ring_lib`.

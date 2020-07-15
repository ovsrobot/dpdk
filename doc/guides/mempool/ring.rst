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
  multi-thread consumer sync mode. For more information please refer to:
  :ref:`Ring_Library_MPMC_Mode`.

- ``ring_sp_sc``

  Underlying **rte_ring** operates in single-thread producer,
  single-thread consumer sync mode. For more information please refer to:
  :ref:`Ring_Library_SPSC_Mode`.

- ``ring_sp_mc``

  Underlying **rte_ring** operates in single-thread producer,
  multi-thread consumer sync mode.

- ``ring_mp_sc``

  Underlying **rte_ring** operates in multi-thread producer,
  single-thread consumer sync mode.

- ``ring_mt_rts``

  For underlying **rte_ring** both producer and consumer operate in
  multi-thread Relaxed Tail Sync (RTS) mode. For more information please
  refer to: :ref:`Ring_Library_MT_RTS_Mode`.

- ``ring_mt_hts``

  For underlying **rte_ring** both producer and consumer operate in
  multi-thread Head-Tail Sync (HTS) mode. For more information please
  refer to: :ref:`Ring_Library_MT_HTS_Mode`.


For 'classic' DPDK deployments (with one thread per core) ``ring_mp_mc``
mode is usually the most suitable and the fastest one. For overcommitted
scenarios (multiple threads share same set of cores) ``ring_mt_rts`` or
``ring_mt_hts`` usually provide a better alternative.
For more information about ``rte_ring`` structure, behaviour and available
synchronisation modes please refer to: :doc:`../prog_guide/ring_lib`.

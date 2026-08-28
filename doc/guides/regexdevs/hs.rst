..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Intel Corporation

Hyperscan RegEx PMD
===================

The Hyperscan RegEx PMD (**librte_regex_hs**) provides a poll mode
regexdev driver backed by Intel's
`Hyperscan <https://github.com/intel/hyperscan>`_ regular expression
library. It is a software-only virtual device (vdev) PMD that
implements the ``rte_regexdev`` API using Hyperscan block mode scanning.

Features
--------

- Software-only virtual device (no hardware dependency)
- Runtime pattern compilation via ``hs_compile_ext_multi()``
- Serialized database import/export
- Per-queue-pair scratch space for lock-free parallel scanning
- Up to 64 queue pairs, each with up to 32768 descriptors
- Up to 1,000,000 rules per device, with O(1) duplicate rule_id
  detection backed by ``rte_hash``
- Up to 65,535 matches per scan operation (API field width limit);
  cumulative totals are tracked via per-queue-pair xstats
- Per-rule extended match parameters (minimum/maximum start offset)
- Hyperscan block-mode engine supports scan buffers up to 4 GB
  (library capability)
- Through the current ``rte_regexdev`` API, this PMD advertises
  ``max_payload_size = 65,535`` bytes (``uint16_t`` field width), so
  ``dpdk-test-regex`` validation is limited to about 64 KB per op
- Hyperscan uses x86 vectorized instructions (SSSE3/AVX2/AVX-512)
  for high throughput
- Per-queue-pair statistics via xstats

In the RegEx driver feature matrix, this PMD reports:

- ``Run time compilation``
- ``x86``

Supported Regex Rule Flags (Hyperscan Mapping)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Standard DPDK flags (advertised via ``info->rule_flags``):

- ``RTE_REGEX_PCRE_RULE_ALLOW_EMPTY_F`` (maps to ``HS_FLAG_ALLOWEMPTY``)
- ``RTE_REGEX_PCRE_RULE_CASELESS_F``    (maps to ``HS_FLAG_CASELESS``)
- ``RTE_REGEX_PCRE_RULE_DOTALL_F``      (maps to ``HS_FLAG_DOTALL``)
- ``RTE_REGEX_PCRE_RULE_MULTILINE_F``   (maps to ``HS_FLAG_MULTILINE``)
- ``RTE_REGEX_PCRE_RULE_UCP_F``         (maps to ``HS_FLAG_UCP``)
- ``RTE_REGEX_PCRE_RULE_UTF_F``         (maps to ``HS_FLAG_UTF8``)

PMD-private flags (accepted in ``rule_flags`` but not advertised;
defined in ``drivers/regex/hs/hs_regex.h``):

- ``HS_REGEX_RULE_SINGLEMATCH_F``  (bit 32, maps to ``HS_FLAG_SINGLEMATCH``)
- ``HS_REGEX_RULE_PREFILTER_F``    (bit 33, maps to ``HS_FLAG_PREFILTER``)
- ``HS_REGEX_RULE_SOM_LEFTMOST_F`` (bit 34, maps to ``HS_FLAG_SOM_LEFTMOST``)
- ``HS_REGEX_RULE_COMBINATION_F``  (bit 35, maps to ``HS_FLAG_COMBINATION``)
- ``HS_REGEX_RULE_QUIET_F``        (bit 36, maps to ``HS_FLAG_QUIET``)

Unknown flag bits are rejected with an error during ``rule_db_update``.

Extended Match Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~

Per-rule minimum and maximum start offset constraints (Hyperscan
``hs_expr_ext_t``) can be encoded in the upper bits of ``rule_flags``:

- Bits 37-49 (13 bits, mask ``0x1FFF``): maximum start offset,
  mapped to ``HS_EXT_FLAG_MAX_OFFSET``.
- Bits 50-63 (14 bits, mask ``0x3FFF``): minimum start offset,
  mapped to ``HS_EXT_FLAG_MIN_OFFSET``.

A value of 0 leaves the corresponding constraint disabled. These
constraints are applied via ``hs_compile_ext_multi()`` during
``rule_db_compile_activate``.

Prerequisites
-------------

The Hyperscan library must be installed and discoverable via
``pkg-config``.  On Ubuntu/Debian::

    sudo apt install libhyperscan-dev

On Fedora/RHEL::

    sudo dnf install hyperscan-devel

The PMD is built automatically when ``libhs`` is found by the meson
build system.  It is only supported on 64-bit platforms.

Device Setup
------------

The Hyperscan PMD is a virtual device.  Create it with the EAL
``--vdev`` option::

    dpdk-app --vdev regex_hs -- ...

Or programmatically with ``rte_vdev_init()``::

    rte_vdev_init("regex_hs", NULL);

Device Lifecycle
~~~~~~~~~~~~~~~~

.. code-block:: c

    rte_regexdev_configure(dev, &cfg);
    rte_regexdev_queue_pair_setup(dev, qp_id, &qp_conf);
    rte_regexdev_rule_db_update(dev, rules, nb_rules);
    rte_regexdev_rule_db_compile_activate(dev);
    rte_regexdev_start(dev);

    /* data path */
    rte_regexdev_enqueue_burst(dev, qp, ops, n);
    rte_regexdev_dequeue_burst(dev, qp, results, n);

    rte_regexdev_stop(dev);
    rte_regexdev_close(dev);

Alternatively, a pre-compiled serialized database can be loaded
during ``rte_regexdev_configure()`` via ``cfg.rule_db`` and
``cfg.rule_db_len``, or at any time via ``rte_regexdev_rule_db_import()``.

Statistics
~~~~~~~~~~

Extended statistics are reported per queue pair, with names of the
form ``qp<N>_enqueued``, ``qp<N>_dequeued``, and ``qp<N>_matches``.
All counters can be reset in bulk or selectively by stat id via
``rte_regexdev_xstats_reset()``.

Limitations
-----------

- Multi-segment mbufs are linearized (``rte_pktmbuf_linearize()``)
  before scanning. If linearization fails (first mbuf buffer too
  small for the full packet), the op is returned to the application
  with ``RTE_REGEX_OPS_RSP_RESOURCE_LIMIT_REACHED_F`` and zero
  matches. Applications scanning large payloads should allocate
  mbufs with sufficient ``data_room_size``.
- Multi-process mode is not supported. The PMD rejects secondary
  processes at probe time. Hyperscan's compiled database and scratch
  space are allocated in process-private memory and cannot be shared
  across separate OS processes. Multi-lcore (multiple threads within
  a single process) is fully supported — each lcore uses its own
  queue pair with dedicated scratch space.
- Each queue pair must be used by exactly one lcore
  (single-producer/single-consumer model).

Debugging Options
-----------------

Enable PMD debug logging with::

    --log-level='pmd.regex.hs,8'

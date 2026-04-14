..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 AMD Inc.

Topology Library
================

Overview
--------

The Topology library provides NUMA‑aware grouping of DPDK logical cores
based on CPU-CACHE and I/O topology.

It exposes APIs that allow applications to query topology domains and
enumerate logical cores within those domains. This enables topology‑aware
core selection for improved locality and performance.

The library integrates with the ``hwloc`` library to obtain hardware
topology information while maintaining ABI stability.

Motivation
----------

Application performance can be improved when:

- DPDK libraries and PMDs operate within the same topology domain
- Cache sharing is maximized in pipeline and graph applications
- Cache identifiers (L2/L3) are used for:
  - Data placement
  - Platform QoS (PQoS) configuration

This library provides a consistent topology view, including support for
EAL lcore reordering via the ``-R`` option.

Functionality
-------------

The Topology library provides the following functionality:

- Partitioning of logical cores into topology domains
- Support for CPU and I/O based domain selection
- Grouping of lcores by hierarchy levels: L1, L2, L3, L4, IO
- Reverse lookup from lcore to domain index
- Helper APIs for lcore and domain iteration

Dependencies
------------

- ``hwloc-dev`` tested on `2.10.0`

The dependency is used to:

- Discover system topology
- Group logical cores into DPDK‑specific domains
- Provide stable mappings across EAL configurations

API Overview
------------

All APIs are provided under the ``RTE_TOPO`` namespace.

Domain Enumeration
------------------

Get the number of domains for a selected topology type.

.. code-block:: c

   uint32_t
   rte_topo_get_domain_count(enum rte_topo_domain_sel domain_sel);

Lcore Enumeration
-----------------

Enumerate logical cores within a topology domain.

.. code-block:: c

   uint32_t
   rte_topo_get_lcore_count_from_domain(
       enum rte_topo_domain_sel domain_sel,
       uint32_t domain_idx);

   unsigned int
   rte_topo_get_nth_lcore_in_domain(
       enum rte_topo_domain_sel domain_sel,
       uint32_t domain_idx,
       uint32_t lcore_pos);

Iterate over logical cores with optional filtering.

.. code-block:: c

   unsigned int
   rte_topo_get_next_lcore(
       unsigned int lcore,
       bool skip_main,
       bool wrap,
       uint32_t flag);

   unsigned int
   rte_topo_get_nth_lcore_from_domain(
       uint32_t domain_idx,
       uint32_t lcore_pos,
       bool wrap,
       uint32_t flag);

Domain Lookup
-------------

Query the domain associated with a logical core.

.. code-block:: c

   int
   rte_topo_get_domain_index_from_lcore(
       enum rte_topo_domain_sel domain_sel,
       unsigned int lcore);

Check whether the main lcore belongs to a domain.

.. code-block:: c

   bool
   rte_topo_is_main_lcore_in_domain(
       enum rte_topo_domain_sel domain_sel,
       uint32_t domain_idx);

CPU Set Access
--------------

Retrieve the CPU set associated with a topology domain.

.. code-block:: c

   const rte_cpuset_t *
   rte_topo_get_lcore_cpuset_in_domain(
       enum rte_topo_domain_sel domain_sel,
       uint32_t domain_idx);

Debug Support
-------------

Dump topology information for debugging purposes.

.. code-block:: c

   void
   rte_topo_dump(FILE *f);

Usage Notes
-----------

- Domain‑aware lcore selection can reduce remote memory access.
- Cache‑level domains are suitable for cache‑sensitive workloads.
- Topology mappings remain stable across EAL lcore configurations.

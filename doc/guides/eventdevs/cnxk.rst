..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2021 Marvell International Ltd.

OCTEON CNXK SSO Eventdev Driver
==========================

The SSO PMD (**librte_event_cnxk**) and provides poll mode
eventdev driver support for the inbuilt event device found in the
**Marvell OCTEON CNXK** SoC family.

More information about OCTEON CNXK SoC can be found at `Marvell Official Website
<https://www.marvell.com/embedded-processors/infrastructure-processors/>`_.

Supported OCTEON CNXK SoCs
--------------------------

- CN9XX
- CN10XX

Features
--------

Features of the OCTEON CNXK SSO PMD are:

- 256 Event queues
- 26 (dual) and 52 (single) Event ports on CN10XX
- 52 Event ports on CN9XX
- HW event scheduler
- Supports 1M flows per event queue
- Flow based event pipelining
- Flow pinning support in flow based event pipelining
- Queue based event pipelining
- Supports ATOMIC, ORDERED, PARALLEL schedule types per flow
- Event scheduling QoS based on event queue priority
- Open system with configurable amount of outstanding events limited only by
  DRAM
- HW accelerated dequeue timeout support to enable power management

Prerequisites and Compilation procedure
---------------------------------------

   See :doc:`../platform/cnxk` for setup information.


Runtime Config Options
----------------------

- ``Maximum number of in-flight events`` (default ``8192``)

  In **Marvell OCTEON CNXK** the max number of in-flight events are only limited
  by DRAM size, the ``xae_cnt`` devargs parameter is introduced to provide
  upper limit for in-flight events.

  For example::

    -a 0002:0e:00.0,xae_cnt=16384

- ``Event Group QoS support``

  SSO GGRPs i.e. queue uses DRAM & SRAM buffers to hold in-flight
  events. By default the buffers are assigned to the SSO GGRPs to
  satisfy minimum HW requirements. SSO is free to assign the remaining
  buffers to GGRPs based on a preconfigured threshold.
  We can control the QoS of SSO GGRP by modifying the above mentioned
  thresholds. GGRPs that have higher importance can be assigned higher
  thresholds than the rest. The dictionary format is as follows
  [Qx-XAQ-TAQ-IAQ][Qz-XAQ-TAQ-IAQ] expressed in percentages, 0 represents
  default.

  For example::

    -a 0002:0e:00.0,qos=[1-50-50-50]

Debugging Options
-----------------

.. _table_octeon_cnxk_event_debug_options:

.. table:: OCTEON CNXK event device debug options

   +---+------------+-------------------------------------------------------+
   | # | Component  | EAL log command                                       |
   +===+============+=======================================================+
   | 1 | SSO        | --log-level='pmd\.event\.cnxk,8'                      |
   +---+------------+-------------------------------------------------------+

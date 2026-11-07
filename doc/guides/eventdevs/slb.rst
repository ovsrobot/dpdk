..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>

Software Load Balancer (SLB) Eventdev Driver
============================================

The Software Load Balancer (SLB) event device is a poll-mode eventdev driver
which distributes events among multiple worker ports and cores without requiring
dedicated scheduling service cores or hardware coprocessors.

Features
--------

Queues
~~~~~~

* **Parallel**: Lock-free multi-producer, multi-consumer ring-based queue allowing
  concurrent dequeues across all serving worker ports.
* **Atomic**: Flow-pinned scheduling guaranteeing strict per-flow packet ordering.
  Includes dynamic load tracking and automatic flow migration to rebalance overloaded
  ports while preserving in-flight sequence integrity.
* **Ordered**: Ticket-based sequence tracking and reorder buffer providing end-to-end
  packet order restoration across parallel processing workers.
* **Single-Link**: Dedicated direct queue mapping from a producer port to a single
  consumer port using optimized single-consumer rings.

Ports & Scheduling Capabilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* **Distributed Scheduling**: No dedicated service core required; scheduling work is
  performed inline during enqueue and dequeue operations.
* **Prefix Sum Burst Enqueue**: Interleaved multi-queue bursts are grouped and scattered
  via prefix-sum offsets, dispatching single batched bursts to queue rings to eliminate
  atomic Compare-And-Swap contention on multi-producer rings.
* **Dynamic Flow Migration**: Atomic queues monitor port dequeue loads and migrate
  eligible victim flows from overloaded ports to underloaded ports with cooling cycles.
* **Credit Pool Management**: Centralized event credit pool with per-port credit caching
  to enforce device-wide in-flight event limits (``max_num_events``).
* **Runtime Port Linking**: Supports dynamic linking and unlinking of ports and queues
  both when stopped and at runtime.
* **Maintenance Free**: Operates without requiring periodic maintenance calls
  (``RTE_EVENT_DEV_CAP_MAINTENANCE_FREE``).

Configuration and Options
-------------------------

The SLB event device is a virtual device (vdev) and can be initialized from the
application code or from the EAL command line:

* From application code:

  .. code-block:: c

      rte_vdev_init("event_slb0", NULL);

* From EAL command-line options:

  .. code-block:: console

      ./your_dpdk_application --vdev="event_slb0"

Limitations
-----------

* **Flow Hash Table Size**: Atomic queues use an internal flow mapping table
  dimensioned to 2048 concurrent active flows per queue (``SLB_ATOMIC_FLOWS``).
* **Maximum Ports and Queues**: Configured for up to 64 ports (``SLB_MAX_PORTS``)
  and 64 queues (``SLB_MAX_QUEUES``).

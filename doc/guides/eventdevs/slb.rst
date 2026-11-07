..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>

Software Load Balancer (SLB) Eventdev Driver
============================================

The Software Load Balancer (SLB) is a software event device and a poll-mode Eventdev driver.
It uses a distributed scheduler, allowing it to scale well. SLB does not require dedicated
cores for scheduling. It supports Atomic, Parallel, and Ordered queues with dynamic atomic
flow load balancing. SLB also requires no internal core communication and is maintenance-free.

Features
--------

Queues
~~~~~~

* **Parallel**: Lock-free multi-producer, multi-consumer ring-based queue allowing
  concurrent dequeues across all serving worker ports.
* **Atomic**: Flow-pinned scheduling guaranteeing strict per-flow packet ordering.
  Includes dynamic load tracking and automatic flow migration to rebalance overloaded
  ports while preserving in-flight sequence integrity.
* **Ordered**: Sequence number-based tracking and reordering.
* **Single-Link**: Implemented using optimized multi-producer single-consumer rings.

Ports & Scheduling Capabilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* **Distributed Scheduling**: No dedicated service core required.
* **Dynamic Flow Migration**: Atomic queues monitor port dequeue loads and migrate
  Eligible flows from overloaded ports to underloaded ports with cooling cycles.
* **Credit Pool Management**: Centralized event credit pool with per-port credit caching
  to enforce device-wide in-flight event limits (``max_num_events``).
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

* **Maximum Ports and Queues**: Supports up to 64 ports and 64 queues.
* **Priorities and linking**: Supports two levels of service priority to link up to
  eight queues per port at each priority. SLB currently does not support event priority.
* **Queues Types**: Does not support all-type queues.

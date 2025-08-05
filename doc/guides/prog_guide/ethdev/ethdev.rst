..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2015 Intel Corporation.

Poll Mode Driver
================

The Data Plane Development Kit (DPDK) supports a wide range of Ethernet speeds,
from 10 Megabits to 400 Gigabits, depending on hardware capability.

DPDK’s Poll Mode Drivers (PMDs) are high-performance, optimized drivers for various
network interface cards that bypass the traditional kernel network stack to reduce
latency and improve throughput. They access RX and TX descriptors directly in a polling
mode without relying on interrupts (except for Link Status Change notifications), enabling
efficient packet reception and transmission in user-space applications.

This section outlines the requirements of Ethernet PMDs, their design principles,
and presents a high-level architecture along with a generic external API.


Requirements and Assumptions
----------------------------

The DPDK environment for packet processing applications allows for two models: run-to-completion and pipeline:

*   In the *run-to-completion*  model, a specific port’s RX descriptor ring is polled for packets through an API.
    Packets are then processed on the same core and transmitted via the port’s TX descriptor ring using another API.

*   In the *pipeline*  model, one core polls the RX descriptor ring(s) of one or more ports via an API.
    Received packets are then passed to another core through a ring for further processing,
     which may include transmission through the TX descriptor ring using an API.

In a synchronous run-to-completion model, each logical core (lcore)
assigned to DPDK executes a packet processing loop, a procedure which is as follows:

*   Retrieving input packets using the PMD receive API

*   Processing each received packet individually, up to its forwarding

*   Transmitting output packets using the PMD transmit API

In contrast, the asynchronous pipeline model assigns some logical cores to retrieve received packets
and others to process them. Packets are exchanged between cores via rings.

The packet retrieval loop includes:

*   Retrieve input packets through the PMD receive API

*   Provide received packets to processing lcores through packet queues

The packet processing loop includes:

*   Dequeuing received packets from the packet queue

*   Processing packets, including retransmission if forwarded

To minimize interrupt-related overhead, the execution environment should avoid asynchronous
notification mechanisms. When asynchronous communication is required, it should be implemented
using rings where possible. Minimizing lock contention is critical in multi-core environments.
To support this, PMDs are designed to use per-core private resources whenever possible.
For example, if a PMD is not RTE_ETH_TX_OFFLOAD_MT_LOCKFREE capable, it maintains a separate
transmit queue per core and per port. Similarly, each receive queue is assigned to and polled by a single lcore.

To support Non-Uniform Memory Access (NUMA), memory management is designed to assign each logical
core a private buffer pool in local memory to reduce remote memory access. Configuration of packet
buffer pools should consider the underlying physical memory layout, such as DIMMs, channels, and ranks.
The application must ensure that proper parameters are set during memory pool creation.

See :doc:`../mempool_lib`.

Design Principles
-----------------

The API and architecture of the Ethernet* Poll Mode Drivers (PMDs) are designed according to the following principles:
PMDs should support the enforcement of global, policy-driven decisions at the upper application level.
At the same time, NIC PMD functions must not hinder the performance gains expected by these higher-level policies,
or worse, prevent them from being implemented.
For example, both the receive and transmit functions of a PMD define a maximum number of packets to poll.

This enables a run-to-completion processing stack to either statically configure or dynamically adjust its
behavior according to different global loop strategies, such as:

*   Receiving, processing, and transmitting packets one at a time in a piecemeal fashion

*   Receiving as many packets as possible, then processing and transmitting them all immediately

*   Receiving a set number of packets, processing them, and batching them for transmission at once

To maximize performance, overall software architecture and optimization techniques must be considered
alongside available low-level hardware optimizations (e.g., CPU cache behavior, bus speed, and NIC PCI bandwidth).

One common example of this software/hardware tradeoff is packet transmission in burst-oriented network engines.
Originally, a PMD could expose only the rte_eth_tx_one function to transmit a single packet at a time on a given queue.

While it’s possible to build an rte_eth_tx_burst function by repeatedly calling rte_eth_tx_one,
most PMDs implement rte_eth_tx_burst directly to reduce per-packet transmission overhead.

This implementation includes several key optimizations:


*   Sharing the fixed cost of invoking rte_eth_tx_one across multiple packets

*   Taking advantage of burst-oriented hardware features (e.g., data prefetching, NIC head/tail registers, vector extensions)
    to reduce CPU cycles per packet.
    This includes minimizing unnecessary memory accesses or leveraging pointer arrays that align with cache line boundaries and sizes.

*   Applying software-level burst optimizations to eliminate otherwise unavoidable overheads, such as ring index wrap-around handling.

The API also introduces burst-oriented functions for PMD-intensive services, such as buffer allocation.
For instance, buffer allocators used to populate NIC rings often support functions that allocate or free multiple buffers in a single call.
An example is rte_pktmbuf_alloc_bulk, which returns an array of rte_mbuf pointers, significantly improving PMD performance
when replenishing multiple descriptors in the receive ring.


Logical Cores, Memory and NIC Queues Relationships
--------------------------------------------------

DPDK supports NUMA (Non-Uniform Memory Access), which enables improved performance when a processor’s logical
cores and network interfaces use memory that is local to that processor. To maximize this benefit, mbufs
associated with local PCIe* interfaces should be allocated from memory pools located in the same NUMA node.

Ideally, these buffers should remain on the local processor to achieve optimal performance. RX and TX buffer
descriptors should be populated with mbufs from mempools created in local memory.
The run-to-completion model also benefits from having packet data and associated operations performed
in local memory, rather than accessing remote memory across NUMA nodes.

The same applies to the pipeline model, provided that all logical cores involved are on the same processor.
Receive and transmit queues should never be shared between multiple logical cores, as doing so would require
global locks and severely impact performance. If the PMD supports the RTE_ETH_TX_OFFLOAD_MT_LOCKFREE offload,
multiple threads can call rte_eth_tx_burst() concurrently on the same TX queue without needing a software lock.

This capability, available in some NICs, can be advantageous in the following scenarios:

*  Eliminating the need for explicit spinlocks in applications where TX queues are not mapped 1:1 to logical cores.

*  In eventdev-based workloads, allow all worker threads to transmit packets, removing the need for a dedicated
   TX core and enabling greater scalability.

See `Hardware Offload`_ for ``RTE_ETH_TX_OFFLOAD_MT_LOCKFREE`` capability probing details.


Device Identification, Ownership and Configuration
--------------------------------------------------

Device Identification
~~~~~~~~~~~~~~~~~~~~~

Each NIC port is uniquely identified by its PCI BDF identifiers,
which are assigned during the PCI probing and enumeration phase at DPDK initialization.
Based on these PCI identifiers, each NIC port is also assigned two additional identifiers:

*   A port index, used to refer to the NIC port in all PMD API function calls.

*   A port name, used in console messages for administration and debugging.
    For convenience, the port name includes the port index.

Port Ownership
~~~~~~~~~~~~~~

Ethernet device ports can be owned by a single DPDK entity such as an application, library, PMD, or process.
The ownership mechanism is managed through ethdev APIs, which allow entities to set, remove, or retrieve port
ownership. This ensures that Ethernet ports are not concurrently controlled by multiple entities.

.. note::

    It is the DPDK entity’s responsibility to set the port owner before using it and to manage the port usage synchronization between different threads or processes.


It is recommended to set port ownership early,
ideally, during the probing notification ``RTE_ETH_EVENT_NEW``.

Device Configuration
~~~~~~~~~~~~~~~~~~~~

The configuration of each NIC port involves the following operations:

* Configuring hardware for:

   * Packet inspection, classification, and associated actions

   * Traffic metering and policing, if required

   * RX and TX queues, including hairpin queues if supported

* Allocating PCI resources

* Reset the hardware (issue a Global Reset) to a well-known default state

* Set up the PHY and the link

* Initialize statistics counters

The PMD API must also provide functions to enable or disable the all-multicast feature,
as well as functions to set or clear promiscuous mode for each port.

Some hardware offload capabilities must be explicitly configured during port initialization
using specific parameters. Examples include Receive Side Scaling (RSS) and Data Center Bridging (DCB).


On-the-Fly Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

Device features that can be enabled or disabled on the fly (without stopping the device)
do not require the PMD API to expose dedicated functions for their control.
Instead, configuring these features externally only requires access to the mapped address
of the device’s PCI registers. This allows configuration to be handled by functions outside the driver itself.

To support this, the PMD API provides a function that returns all relevant device information
needed to configure such features externally. This includes:

*  PCI vendor ID

*  PCI device ID

*  Mapped address of the PCI device registers

*  Name of the driver

The key advantage of this approach is that it provides flexibility, allowing any API
or external mechanism to be used for feature configuration, activation, or deactivation.

For example, the IEEE1588 feature on the Intel® 82576 Gigabit Ethernet Controller
and Intel® 82599 10 Gigabit Ethernet Controller can be configured this way using the testpmd application.
Other features, such as L3/L4 5-Tuple packet filtering, can also be configured similarly. Ethernet
flow control (pause frame) is configurable per port. See the testpmd source code for implementation details.

In addition, L4 checksum offload (UDP/TCP/SCTP) can be enabled on a per-packet basis, provided
the packet’s mbuf is correctly set up. See `Hardware Offload`_ for details


Configuration of Transmit Queues
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each transmit (TX) queue is configured independently with the following parameters:

* Number of descriptors in the transmit ring.

* Socket identifier to select the appropriate DMA memory zone for TX ring allocation in NUMA systems.

* Threshold values for the prefetch, host, and write-back registers of the TX queue if supported by the PMD.

* Transmit free threshold (tx_free_thresh) — the minimum number of transmitted packets that must accumulate before checking whether the network adapter has written back descriptors.

   * If set to 0, the default value is used.

   * The default is 32, ensuring that the PMD does not poll for completed descriptors until at least 32 have been processed by the NIC.

* Transmit RS (Report Status) threshold (tx_free_thresh): the minimum number of TX descriptors used before setting the RS bit in a descriptor.

   * This parameter is typically relevant for Intel 10 GbE network adapters.

   * The RS bit is set on the last descriptor used to transmit a packet if the number of descriptors used since the last RS bit exceeds this threshold.

   * If set to 0, the default value is used.

   * The default value is 32, which helps conserve PCIe* bandwidth by reducing write-backs to host memory.

   * When tx_rs_thresh > 1, TX write-back threshold (TX wthresh) should be set to 0.

For more details, refer to the Intel® 82599 10 Gigabit Ethernet Controller Datasheet.

.. note::

    When configuring for DCB operation, at port initialization, both the number of transmit queues and the number of receive queues must be set to 128.


Free Tx mbuf on Demand
~~~~~~~~~~~~~~~~~~~~~~

Many drivers do not immediately return mbufs to the mempool or local cache after a packet has been transmitted.
Instead, they retain the mbuf in the TX ring and either:

* Perform a bulk release once the tx_rs_thresh threshold has been crossed, or

* Free the mbuf only when a slot in the TX ring is needed.

To manually trigger the release of used mbufs, applications can use the rte_eth_tx_done_cleanup() API.
This function requests the driver to free all mbufs no longer in use—regardless of whether tx_rs_thresh has been crossed.

There are two main use cases where immediate mbuf release may be desired:

1. Multi-destination Packet Transmission

When a single packet must be sent to multiple destination interfaces (e.g., Layer 2 flooding or Layer 3 multicast), two approaches exist:

Copy the packet, or at least the header portion to modify as needed for each destination.

Use rte_eth_tx_done_cleanup() to release the mbuf after the first transmission.
Once the reference count is decremented, the same packet can be sent to another destination.

Note: The application remains responsible for making any necessary packet modifications between transmissions.
This method works whether the packet was transmitted or dropped. As long as the mbuf is no longer in use by the interface.

2. Applications with Multiple Execution Runs

Some applications, such as packet generators, may operate in repeated runs.
For consistency and performance, they may wish to return to a clean state between runs,
ensuring all mbufs are returned to the mempool.

In this case, the application can call rte_eth_tx_done_cleanup() for each interface used,
requesting the driver to release all in-use mbufs.

To check if a driver supports this feature, refer to the Free Tx mbuf on demand capability
listed in the Network Interface Controller Drivers documentation.

Hardware Offload
~~~~~~~~~~~~~~~~

Based on the capabilities reported by rte_eth_dev_info_get(),
a PMD may support various hardware offload features, including:

* Checksumming (IP, UDP, TCP)
* UDP and TCP segmentation
* VLAN insertion and stripping
* MACsec (Media Access Control Security)
* Large Receive Offload (LRO)
* Lock-free multithreaded TX bursts on the same TX queue
* Buffer split offload
* Timestamping

When buffer split offload is supported, the driver must configure an appropriate memory pool
and set the required parameters to enable the feature.

Support for these offloads introduces additional status bits and value fields in the rte_mbuf structure.
These fields must be correctly handled by the PMD’s transmit and receive functions.
The complete list of flags, their usage, and detailed explanations are provided in the mbuf API
documentation and the :ref:mbuf_meta chapter.

Additionally, drivers should be capable of handling scattered packets, where the data is spread
across multiple mbuf segments stitched together.


Per-Port and Per-Queue Offloads
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In the DPDK offload API, offloads are divided into per-port and per-queue offloads as follows:

* A per-queue offloading can be enabled on a queue and disabled on another queue at the same time.
* A pure per-port offload is the one supported by device but not per-queue type.
* A pure per-port offloading can't be enabled on a queue and disabled on another queue at the same time.
* A pure per-port offloading must be enabled or disabled on all queues at the same time.
* Any offloading is per-queue or pure per-port type, but can't be both types at same devices.
* Port capabilities = per-queue capabilities + pure per-port capabilities.
* Any supported offloading can be enabled on all queues.

The different offloads capabilities can be queried using ``rte_eth_dev_info_get()``.
The ``dev_info->[rt]x_queue_offload_capa`` returned from ``rte_eth_dev_info_get()`` includes all per-queue offloading capabilities.
The ``dev_info->[rt]x_offload_capa`` returned from ``rte_eth_dev_info_get()`` includes all pure per-port and per-queue offloading capabilities.
Supported offloads can be either per-port or per-queue.

Offloads are enabled using the existing ``RTE_ETH_TX_OFFLOAD_*`` or ``RTE_ETH_RX_OFFLOAD_*`` flags.
Any requested offloading by an application must be within the device capabilities.
Any offloading is disabled by default if it is not set in the parameter
``dev_conf->[rt]xmode.offloads`` to ``rte_eth_dev_configure()`` and
``[rt]x_conf->offloads`` to ``rte_eth_[rt]x_queue_setup()``.

If any offloading is enabled in ``rte_eth_dev_configure()`` by an application,
it is enabled on all queues no matter whether it is per-queue or
per-port type and no matter whether it is set or cleared in
``[rt]x_conf->offloads`` to ``rte_eth_[rt]x_queue_setup()``.

If a per-queue offloading hasn't been enabled in ``rte_eth_dev_configure()``,
it can be enabled or disabled in ``rte_eth_[rt]x_queue_setup()`` for individual queue.
A newly added offloads in ``[rt]x_conf->offloads`` to ``rte_eth_[rt]x_queue_setup()`` input by application
is the one which hasn't been enabled in ``rte_eth_dev_configure()`` and is requested to be enabled
in ``rte_eth_[rt]x_queue_setup()``. It must be per-queue type, otherwise trigger an error log.

Poll Mode Driver API
--------------------

Generalities
~~~~~~~~~~~~

By default, all functions exported by a PMD are lock-free functions that are assumed
not to be invoked in parallel on different logical cores to work on the same target object.
For instance, a PMD receive function cannot be invoked in parallel on two logical cores to poll the same RX queue of the same port.
Of course, this function can be invoked in parallel by different logical cores on different RX queues.
It is the responsibility of the upper-level application to enforce this rule.

If needed, parallel accesses by multiple logical cores to shared queues can be explicitly protected by dedicated inline lock-aware functions
built on top of their corresponding lock-free functions of the PMD API.

Generic Packet Representation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A packet is represented by an rte_mbuf structure, which is a generic metadata structure containing all necessary housekeeping information.
This includes fields and status bits corresponding to offload hardware features, such as checksum computation of IP headers or VLAN tags.

The rte_mbuf data structure includes specific fields to represent, in a generic way, the offload features provided by network controllers.
For an input packet, most fields of the rte_mbuf structure are filled in by the PMD receive function with the information contained in the receive descriptor.
Conversely, for output packets, most fields of rte_mbuf structures are used by the PMD transmit function to initialize transmit descriptors.

See :doc:`../mbuf_lib` chapter for more details.

Ethernet Device API
~~~~~~~~~~~~~~~~~~~

The Ethernet device API exported by the Ethernet PMDs is described in the *DPDK API Reference*.

.. _ethernet_device_standard_device_arguments:

Ethernet Device Standard Device Arguments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Standard Ethernet device arguments allow for a set of commonly used arguments/
parameters which are applicable to all Ethernet devices to be available to for
specification of specific device and for passing common configuration
parameters to those ports.

* ``representor`` for a device which supports the creation of representor ports
  this argument allows user to specify which switch ports to enable port
  representors for::

   -a DBDF,representor=vf0
   -a DBDF,representor=vf[0,4,6,9]
   -a DBDF,representor=vf[0-31]
   -a DBDF,representor=vf[0,2-4,7,9-11]
   -a DBDF,representor=sf0
   -a DBDF,representor=sf[1,3,5]
   -a DBDF,representor=sf[0-1023]
   -a DBDF,representor=sf[0,2-4,7,9-11]
   -a DBDF,representor=pf1vf0
   -a DBDF,representor=pf[0-1]sf[0-127]
   -a DBDF,representor=pf1
   -a DBDF,representor=[pf[0-1],pf2vf[0-2],pf3[3,5-8]]
   (Multiple representors in one device argument can be represented as a list)

Note: PMDs are not required to support the standard device arguments and users
should consult the relevant PMD documentation to see support devargs.

Extended Statistics API
~~~~~~~~~~~~~~~~~~~~~~~

The extended statistics API allows a PMD to expose all statistics that are
available to it, including statistics that are unique to the device.
Each statistic has three properties ``name``, ``id`` and ``value``:

* ``name``: A human readable string formatted by the scheme detailed below.
* ``id``: An integer that represents only that statistic.
* ``value``: A unsigned 64-bit integer that is the value of the statistic.

Note that extended statistic identifiers are
driver-specific, and hence might not be the same for different ports.
The API consists of various ``rte_eth_xstats_*()`` functions, and allows an
application to be flexible in how it retrieves statistics.

Scheme for Human Readable Names
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A naming scheme exists for the strings exposed to clients of the API. This is
to allow scraping of the API for statistics of interest. The naming scheme uses
strings split by a single underscore ``_``. The scheme is as follows:

* direction
* detail 1
* detail 2
* detail n
* unit

Examples of common statistics xstats strings, formatted to comply to the scheme
proposed above:

* ``rx_bytes``
* ``rx_crc_errors``
* ``tx_multicast_packets``

The scheme, although quite simple, allows flexibility in presenting and reading
information from the statistic strings. The following example illustrates the
naming scheme:``rx_packets``. In this example, the string is split into two
components. The first component ``rx`` indicates that the statistic is
associated with the receive side of the NIC.  The second component ``packets``
indicates that the unit of measure is packets.

A more complicated example: ``tx_size_128_to_255_packets``. In this example,
``tx`` indicates transmission, ``size``  is the first detail, ``128`` etc are
more details, and ``packets`` indicates that this is a packet counter.

Some additions in the metadata scheme are as follows:

* If the first part does not match ``rx`` or ``tx``, the statistic does not
  have an affinity with either receive of transmit.

* If the first letter of the second part is ``q`` and this ``q`` is followed
  by a number, this statistic is part of a specific queue.

An example where queue numbers are used is as follows: ``tx_q7_bytes`` which
indicates this statistic applies to queue number 7, and represents the number
of transmitted bytes on that queue.

API Design
^^^^^^^^^^

The xstats API uses the ``name``, ``id``, and ``value`` to allow performant
lookup of specific statistics. Performant lookup means two things;

* No string comparisons with the ``name`` of the statistic in fast-path
* Allow requesting of only the statistics of interest

The API ensures these requirements are met by mapping the ``name`` of the
statistic to a unique ``id``, which is used as a key for lookup in the fast-path.
The API allows applications to request an array of ``id`` values, so that the
PMD only performs the required calculations. Expected usage is that the
application scans the ``name`` of each statistic, and caches the ``id``
if it has an interest in that statistic. On the fast-path, the integer can be used
to retrieve the actual ``value`` of the statistic that the ``id`` represents.

API Functions
^^^^^^^^^^^^^

The API is built out of a small number of functions, which can be used to
retrieve the number of statistics and the names, IDs and values of those
statistics.

* ``rte_eth_xstats_get_names_by_id()``: returns the names of the statistics. When given a
  ``NULL`` parameter the function returns the number of statistics that are available.

* ``rte_eth_xstats_get_id_by_name()``: Searches for the statistic ID that matches
  ``xstat_name``. If found, the ``id`` integer is set.

* ``rte_eth_xstats_get_by_id()``: Fills in an array of ``uint64_t`` values
  with matching the provided ``ids`` array. If the ``ids`` array is NULL, it
  returns all statistics that are available.


Application Usage
^^^^^^^^^^^^^^^^^

Imagine an application that wants to view the dropped packet count. If no
packets are dropped, the application does not read any other metrics for
performance reasons. If packets are dropped, the application has a particular
set of statistics that it requests. This "set" of statistics allows the app to
decide what next steps to perform. The following code-snippets show how the
xstats API can be used to achieve this goal.

First step is to get all statistics names and list them:

.. code-block:: c

    struct rte_eth_xstat_name *xstats_names;
    uint64_t *values;
    int len, i;

    /* Get number of stats */
    len = rte_eth_xstats_get_names_by_id(port_id, NULL, NULL, 0);
    if (len < 0) {
        printf("Cannot get xstats count\n");
        goto err;
    }

    xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * len);
    if (xstats_names == NULL) {
        printf("Cannot allocate memory for xstat names\n");
        goto err;
    }

    /* Retrieve xstats names, passing NULL for IDs to return all statistics */
    if (len != rte_eth_xstats_get_names_by_id(port_id, xstats_names, NULL, len)) {
        printf("Cannot get xstat names\n");
        goto err;
    }

    values = malloc(sizeof(values) * len);
    if (values == NULL) {
        printf("Cannot allocate memory for xstats\n");
        goto err;
    }

    /* Getting xstats values */
    if (len != rte_eth_xstats_get_by_id(port_id, NULL, values, len)) {
        printf("Cannot get xstat values\n");
        goto err;
    }

    /* Print all xstats names and values */
    for (i = 0; i < len; i++) {
        printf("%s: %"PRIu64"\n", xstats_names[i].name, values[i]);
    }

The application has access to the names of all of the statistics that the PMD
exposes. The application can decide which statistics are of interest, cache the
ids of those statistics by looking up the name as follows:

.. code-block:: c

    uint64_t id;
    uint64_t value;
    const char *xstat_name = "rx_errors";

    if(!rte_eth_xstats_get_id_by_name(port_id, xstat_name, &id)) {
        rte_eth_xstats_get_by_id(port_id, &id, &value, 1);
        printf("%s: %"PRIu64"\n", xstat_name, value);
    }
    else {
        printf("Cannot find xstats with a given name\n");
        goto err;
    }

The API provides flexibility to the application so that it can look up multiple
statistics using an array containing multiple ``id`` numbers. This reduces the
function call overhead of retrieving statistics, and makes lookup of multiple
statistics simpler for the application.

.. code-block:: c

    #define APP_NUM_STATS 4
    /* application cached these ids previously; see above */
    uint64_t ids_array[APP_NUM_STATS] = {3,4,7,21};
    uint64_t value_array[APP_NUM_STATS];

    /* Getting multiple xstats values from array of IDs */
    rte_eth_xstats_get_by_id(port_id, ids_array, value_array, APP_NUM_STATS);

    uint32_t i;
    for(i = 0; i < APP_NUM_STATS; i++) {
        printf("%d: %"PRIu64"\n", ids_array[i], value_array[i]);
    }


This array lookup API for xstats allows the application create multiple
"groups" of statistics, and look up the values of those IDs using a single API
call. As an end result, the application is able to achieve its goal of
monitoring a single statistic ("rx_errors" in this case), and if that shows
packets being dropped, it can easily retrieve a "set" of statistics using the
IDs array parameter to ``rte_eth_xstats_get_by_id`` function.

NIC Reset API
~~~~~~~~~~~~~

.. code-block:: c

    int rte_eth_dev_reset(uint16_t port_id);

Sometimes a port has to be reset passively. For example when a PF is
reset, all its VFs should also be reset by the application to make them
consistent with the PF. A DPDK application also can call this function
to trigger a port reset. Normally, a DPDK application would invokes this
function when an RTE_ETH_EVENT_INTR_RESET event is detected.

It is the duty of the PMD to trigger RTE_ETH_EVENT_INTR_RESET events and
the application should register a callback function to handle these
events. When a PMD needs to trigger a reset, it can trigger an
RTE_ETH_EVENT_INTR_RESET event. On receiving an RTE_ETH_EVENT_INTR_RESET
event, applications can handle it as follows: Stop working queues, stop
calling Rx and Tx functions, and then call rte_eth_dev_reset(). For
thread safety all these operations should be called from the same thread.

For example when PF is reset, the PF sends a message to notify VFs of
this event and also trigger an interrupt to VFs. Then in the interrupt
service routine the VFs detects this notification message and calls
rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_RESET, NULL).
This means that a PF reset triggers an RTE_ETH_EVENT_INTR_RESET
event within VFs. The function rte_eth_dev_callback_process() will
call the registered callback function. The callback function can trigger
the application to handle all operations the VF reset requires including
stopping Rx/Tx queues and calling rte_eth_dev_reset().

The rte_eth_dev_reset() itself is a generic function which only does
some hardware reset operations through calling dev_unint() and
dev_init(), and itself does not handle synchronization, which is handled
by application.

The PMD itself should not call rte_eth_dev_reset(). The PMD can trigger
the application to handle reset event. It is duty of application to
handle all synchronization before it calls rte_eth_dev_reset().

The above error handling mode is known as ``RTE_ETH_ERROR_HANDLE_MODE_PASSIVE``.

Proactive Error Handling Mode
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This mode is known as ``RTE_ETH_ERROR_HANDLE_MODE_PROACTIVE``,
different from the application invokes recovery in PASSIVE mode,
the PMD automatically recovers from error in PROACTIVE mode,
and only a small amount of work is required for the application.

During error detection and automatic recovery,
the PMD sets the data path pointers to dummy functions
(which will prevent the crash),
and also make sure the control path operations fail with a return code ``-EBUSY``.

Because the PMD recovers automatically,
the application can only sense that the data flow is disconnected for a while
and the control API returns an error in this period.

In order to sense the error happening/recovering,
as well as to restore some additional configuration,
three events are available:

``RTE_ETH_EVENT_ERR_RECOVERING``
   Notify the application that an error is detected
   and the recovery is being started.
   Upon receiving the event, the application should not invoke
   any control path function until receiving
   ``RTE_ETH_EVENT_RECOVERY_SUCCESS`` or ``RTE_ETH_EVENT_RECOVERY_FAILED`` event.

.. note::

   Before the PMD reports the recovery result,
   the PMD may report the ``RTE_ETH_EVENT_ERR_RECOVERING`` event again,
   because a larger error may occur during the recovery.

``RTE_ETH_EVENT_RECOVERY_SUCCESS``
   Notify the application that the recovery from error is successful,
   the PMD already re-configures the port,
   and the effect is the same as a restart operation.

``RTE_ETH_EVENT_RECOVERY_FAILED``
   Notify the application that the recovery from error failed,
   the port should not be usable anymore.
   The application should close the port.

The error handling mode supported by the PMD can be reported through
``rte_eth_dev_info_get``.

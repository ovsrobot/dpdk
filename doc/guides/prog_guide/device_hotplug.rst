..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2025 Intel Corporation.

.. _device_hotplug:

Device Hotplug
==============

Introduction
------------

Device hotplug refers to the ability to attach and detach devices at runtime, after the initial EAL initialization has completed.
This feature allows applications to dynamically add or remove physical or virtual devices while the DPDK application is running.

.. note::
   Device hotplug does not support multiprocess operation nor kernel device event notifications on platforms other than Linux.


Basic Usage
-----------

The primary interface for device hotplug is through two complementary functions: ``rte_dev_probe()`` to attach a device using a devargs string, and ``rte_dev_remove()`` to detach a device.
For detailed information about device argument format and syntax, see :doc:`dev_args`.

A typical workflow for attaching a device is:

.. code-block:: c

   /* Probe a PCI device with specific parameters */
   ret = rte_dev_probe("0000:02:00.0,arg1=value1");
   if (ret < 0) {
       /* Handle error */
   }

   /* Later, find the device and remove it */
   struct rte_device *dev = /* find device */;
   ret = rte_dev_remove(dev);

For convenience, DPDK also provides ``rte_eal_hotplug_add()`` and ``rte_eal_hotplug_remove()`` functions, which accept separate bus name, device name, and arguments instead of a combined devargs string:

.. code-block:: c

   /* Attach a virtual device */
   rte_eal_hotplug_add("vdev", "net_ring0", "");

   /* Remove by bus and device name */
   rte_eal_hotplug_remove("vdev", "net_ring0");


Device Lifecycle Example
~~~~~~~~~~~~~~~~~~~~~~~~

The ``testpmd`` application provides a reference implementation of device hotplug through the ``port attach`` and ``port detach`` commands, demonstrating proper device lifecycle management.

The following example demonstrates attaching a virtual ring PMD Ethernet device, configuring it, and then detaching it:

.. code-block:: c

   char *devargs = "net_ring0";
   struct rte_eth_dev_info info;
   struct rte_dev_iterator iterator;
   unsigned port_id;

   /* Probe the device */
   rte_dev_probe(devargs);

   /* Enumerate newly attached ports */
   RTE_ETH_FOREACH_MATCHING_DEV(port_id, devargs, &iterator) {
      /* Get device handle */
      rte_eth_dev_info_get(port_id, &info);

      /* Set up the device and use it */
   }

   /* Stop the port */
   rte_eth_dev_stop(port_id);

   /* Remove the device */
   ret = rte_dev_remove(info.device);

The key steps in this lifecycle are:

1. **Attach**: Call ``rte_dev_probe()`` with the device identifier
2. **Find the device**: Use device iterators (such as ``RTE_ETH_FOREACH_MATCHING_DEV()``) to find newly attached port
3. **Configure and use**: Configure the port using normal device configuration/start flow
4. **Detach**: Stop the device before calling ``rte_dev_remove()``


Device Events
-------------

In addition to providing generic hotplug infrastructure to be used in the above described manner, EAL also offers a device event infrastructure.

.. warning::
   Because all events are always delivered within the context of an interrupt thread, attempting any memory allocations/deallocations within that context may cause deadlocks.
   Therefore, it is recommended to set up a deferred application resource allocation/cleanup with ``rte_eal_alarm_set()`` API or otherwise trigger allocation/cleanup of application resources in another context.

Ethernet Device Events
~~~~~~~~~~~~~~~~~~~~~~

When new Ethernet devices are added (hot plugged using device probe API) to EAL or removed (hot unplugged using device remove API) from EAL, the following events are delivered:

* ``RTE_ETH_EVENT_NEW`` - delivered after device probe
* ``RTE_ETH_EVENT_DESTROY`` - delivered after device removal

The user may subscribe to these events using ``rte_eth_dev_callback_register()`` function.


Kernel Device Events
~~~~~~~~~~~~~~~~~~~~

EAL may also subscribe to generic device events delivered from kernel uevent infrastructure. The following events are delivered:

* ``RTE_DEV_EVENT_ADD`` - delivered whenever a new device becomes available for probing
* ``RTE_DEV_EVENT_REMOVE`` - delivered whenever a device becomes unavailable (device failure, hot unplug, etc.)

The kernel event monitoring is not enabled by default, so before using this feature the user must do the following:

* Call ``rte_dev_hotplug_handle_enable()`` to enable ``SIGBUS`` handling in EAL for devices that were hot-unplugged
* Call ``rte_dev_event_monitor_start()`` to enable kernel device event monitoring

The user may then subscribe to kernel device events using ``rte_dev_event_callback_register()`` function.

.. note::
   Currently, for ``RTE_DEV_EVENT_ADD``, only PCI devices are monitored

.. note::
   The ``RTE_DEV_EVENT_ADD`` by itself does not probe the device, it is only a notification that the application may use ``rte_dev_probe()`` on the device in question.
   When ``RTE_DEV_EVENT_REMOVE`` event is delivered, the EAL has already released all internal resources associated with the device.


Event Notification Usage
~~~~~~~~~~~~~~~~~~~~~~~~

Example generic device event callback with deferred probe:

.. code-block:: c

   void
   deferred_attach(void *arg)
   {
       const char *devname = (const char *)arg;
       rte_dev_probe(devname);
       /* match strdup with free */
       free(devname);
   }

   int
   device_event_callback(const char *device_name,
                         enum rte_dev_event_type event,
                         void *cb_arg)
   {
       if (event == RTE_DEV_EVENT_ADD) {
           /* Schedule deferred attach - don't call rte_dev_probe() here! */
           char *devname = strdup(device_name);
           if (rte_eal_alarm_set(1, deferred_attach, devname) < 0) {
               /* error */
           }
       } else if (event == RTE_DEV_EVENT_REMOVE) {
           /* Handle device removal - schedule cleanup if needed */
       }
       return 0;
   }

   rte_dev_event_callback_register(NULL, device_event_callback, user_arg);  /* NULL = all devices */


Implementation Details
======================

Attach and Detach
-----------------

When ``rte_dev_probe()`` is called, the following sequence occurs:

1. **Devargs Parsing**:
   The devargs string is parsed to extract the bus name, device name, and driver arguments, which are stored in an ``rte_devargs`` structure and inserted into the global devargs list.

2. **Bus Scan**:
   The appropriate bus driver's ``scan()`` method is invoked, causing the bus to search for the device.
   For PCI devices, this may involve scanning the sysfs filesystem, while for virtual devices, this may create the device structure directly.

3. **Device Discovery**:
   After scanning, the bus's ``find_device()`` method locates the device by name, and the attach operation fails if the device is not found.

4. **Device Probe**:
   The bus's ``plug()`` method is called, which triggers the device driver's probe function.
   The probe function typically allocates device-specific resources, maps device memory regions, initializes device hardware, and registers the device with the appropriate subsystem (e.g., ethdev for network devices).

5. **Multi-process Synchronization**:
   If successful in the primary process, an IPC message is sent to all secondary processes to attach the same device.
   See `Multi-process Synchronization`_ for details.


When ``rte_dev_remove()`` is called, the following sequence occurs:

1. **Device Validation**:
   The function verifies that the device is currently probed using ``rte_dev_is_probed()``.

2. **Multi-process Coordination**:
   In multi-process scenarios, the primary process first coordinates with all secondary processes to detach the device, and only if all secondaries successfully detach does the primary proceed.
   See `Multi-process Synchronization`_ for details.

3. **Device Unplug**:
   The bus's ``unplug()`` method is called (``dev->bus->unplug()``), which triggers the driver's remove function.
   This typically stops device operations, releases device resources, unmaps memory regions, and unregisters from subsystems.

4. **Devargs Cleanup**:
   The devargs associated with the device are removed from the global list.


Multi-process Synchronization
-----------------------------

DPDK's hotplug implementation ensures that devices are attached or detached consistently across all processes in a multi-process deployment.
Both primary and secondary processes can initiate hotplug operations (by calling ``rte_dev_probe()`` or ``rte_dev_remove()``), which will be synchronized across all processes.

.. note::
   Multiprocess operations are only supported on Linux

**When Application Initiates from Primary**:

1. Primary performs the local operation
2. Primary broadcasts the request to all secondaries using IPC
3. Primary waits for replies from all secondaries with a timeout
4. If all secondaries succeed, the operation is complete
5. If any secondary fails, primary initiates rollback

**When Application Initiates from Secondary**:

1. Secondary sends attach/detach request to primary via IPC
2. Primary receives the request and performs the local operation
3. Primary broadcasts the request to all other secondaries
4. Primary waits for replies from all secondaries
5. If all succeed, primary sends success reply to the requesting secondary
6. If any fail, primary initiates rollback and sends failure reply to the requesting secondary

**Secondary Process Flow** (when receiving request from primary):

1. Secondary receives IPC request from primary
2. Secondary performs the local attach/detach operation
3. Secondary sends reply with success or failure status

Rollback on Failure
~~~~~~~~~~~~~~~~~~~

If any step in the attach or detach process fails in a multi-process scenario, DPDK attempts to rollback the operation.
For attach failures, the primary process sends rollback requests to detach the device from all secondary processes where it succeeded.
For detach failures, the primary process sends rollback requests to all secondary processes to re-attach the device, restoring the previous state.

Virtual Devices and Multi-process
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Virtual devices have special handling in multi-process scenarios.

During initial startup, when a secondary process starts, it sends a scan request to the primary process via IPC, and the primary responds by sending the list of all virtual devices it has created.
This synchronization happens during the bus scan phase.
Unlike physical devices where both processes can independently discover hardware, virtual devices only exist in memory, so secondaries must obtain the device list from the primary.

At runtime, virtual devices can be hotplugged from either primary or secondary processes using the standard hotplug flow described above, and will be synchronized across all processes.
Note that secondary processes can specify virtual devices via ``--vdev`` on the command line during initialization, which creates process-local devices, but runtime hotplug operations using ``rte_dev_probe()`` always synchronize devices across all processes.


Kernel Uevent Handling (Linux only)
-----------------------------------

DPDK's device event monitoring works by listening to Linux kernel uevents via a netlink socket. The application must explicitly start monitoring by calling ``rte_dev_event_monitor_start()``.
When ``rte_dev_event_monitor_start()`` is called, DPDK creates a ``NETLINK_KOBJECT_UEVENT`` socket that receives notifications from the kernel about device state changes.

The mechanism works as follows:

1. **Netlink Socket Creation**: DPDK creates a netlink socket bound to receive all kernel kobject uevents (``nl_groups = 0xffffffff``).
2. **Uevent Reception**: When a device is added or removed, the Linux kernel broadcasts a uevent message containing:
   - ``ACTION=add`` or ``ACTION=remove``
   - ``SUBSYSTEM=pci``, ``uio``, or ``vfio``
   - ``PCI_SLOT_NAME=<device>`` (e.g., ``0000:02:00.0``)
3. **Event Parsing**: DPDK parses these messages to extract the device name, action type, and subsystem, then invokes registered application callbacks.
4. **Interrupt-driven**: The socket is registered with DPDK's interrupt framework, so uevent handling is asynchronous and doesn't require polling.

This infrastructure only monitors physical devices managed by the kernel. Virtual devices created by DPDK do not generate kernel uevents.

SIGBUS Handling
---------------

If the application attempts to access memory-mapped device registers after the device is removed, a ``SIGBUS`` signal may be generated.
The ``rte_dev_hotplug_handle_enable()`` function registers a signal handler that identifies which device caused the fault using the faulting address, invokes the bus's signal handler to handle the error, and allows the application to continue rather than crashing.

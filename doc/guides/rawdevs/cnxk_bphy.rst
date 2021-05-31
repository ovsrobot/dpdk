..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2021 Marvell International Ltd.

Marvell CNXK BPHY Driver
==========================================

CN10K/CN9K Fusion product families offer an internal BPHY unit which provides
set of hardware accelerators for performing baseband related operations. Connectivity
to the outside world happens through a block called RFOE which is backed by
ethernet I/O block called CGX or RPM (depending on the chip version). RFOE
stands for Radio Frequency Over Ethernet and provides support for
IEEE 1904.3 (RoE) standard.

Features
--------

The BPHY CGX/RPM implements following features in the rawdev API:

- Access to BPHY CGX/RPM via set of predefined messages.

Device Setup
------------

The BPHY CGX/RPM  devices will need to be bound to a user-space IO driver for
use. The script ``dpdk-devbind.py`` script included with DPDK can be used to
view the state of the devices and to bind them to a suitable DPDK-supported
kernel driver. When querying the status of the devices, they will appear under
the category of "Misc (rawdev) devices", i.e. the command
``dpdk-devbind.py --status-dev misc`` can be used to see the state of those
devices alone.

To perform data transfer use standard ``rte_rawdev_enqueue_buffers()`` and
``rte_rawdev_dequeue_buffers()`` APIs. Not all messages produce sensible
responses hence dequeueing is not always necessary.

Self test
---------

On EAL initialization, BPHY CGX/RPM devices will be probed and populated into
the raw devices. The rawdev ID of the device can be obtained using invocation
of ``rte_rawdev_get_dev_id("NAME:x")`` from the test application, where:

- NAME is the desired subsystem: use "BPHY_CGX" for
  RFOE module,
- x is the device's bus id specified in "bus:device.func" (BDF) format.

Use this identifier for further rawdev function calls.

The driver's selftest rawdev API can be used to verify the BPHY CGX/RPM
functionality.

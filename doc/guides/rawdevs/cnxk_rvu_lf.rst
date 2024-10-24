..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2024 Marvell.

Marvell CNXK RVU LF Driver
==========================

CNXK product families can have a use case to allow PF and VF
applications to communicate using mailboxes and also get notified
of any interrupt that may occur on the device.
Hence, a new raw device driver is added for such RVU LF devices.
These devices can map to a PF or a VF which can send mailboxes to
each other.

Features
--------

The RVU LF device implements following features in the rawdev API:

- Register mailbox callbacks for the other side to process mailboxes.
- Register interrupt handler callbacks.
- Process mailbox.
- Set range of message IDs allowed for communication.

Limitations
-----------

In multiprocess mode user-space application must ensure
no resources sharing takes place.
Otherwise, user-space application should ensure synchronization.

Device Setup
------------

The RVU LF devices will need to be bound to a user-space IO driver for use.
The script ``dpdk-devbind.py`` included with DPDK can be used to
view the state of the devices and to bind them to a suitable DPDK-supported
kernel driver. When querying the status of the devices, they will appear under
the category of "Misc (rawdev) devices", i.e. the command
``dpdk-devbind.py --status-dev misc`` can be used to see the state of those
devices alone.

Get NPA and SSO PF FUNC
-----------------------

APIs ``rte_pmd_rvu_lf_npa_pf_func_get()`` and ``rte_pmd_rvu_lf_sso_pf_func_get()``
can be used to get the cnxk NPA PF func and SSO PF func which application
can use for NPA/SSO specific configuration.

Register or remove interrupt handler
------------------------------------

Application can register interrupt handlers using ``rte_pmd_rvu_lf_irq_register()``
or remove interrupt handler using ``rte_pmd_rvu_lf_irq_unregister()``.
The irq numbers for which the interrupts are registered is negotiated separately
and is not in scope of the driver.

RVU LF RAW MESSAGE PROCESSING
-----------------------------

Once a RVU LF raw device is probed, a range of message ids can be configured for
which mailboxes will be sent using the API ``rte_pmd_rvu_lf_msg_id_range_set``.

For processing of mailboxes received on PF/VF application, application
can register callbacks using ``rte_pmd_rvu_lf_msg_handler_register()``
and fill required responses as per the request and message id received.
Application can also unregister already registered message callbacks using
``rte_pmd_rvu_lf_msg_handler_unregister()``.

A PMD API ``rte_pmd_rvu_lf_msg_process()`` is created to send a request and
receive corresponding response from the other side(PF/VF).
It accepts an opaque pointer of a request and its size which can be defined by application
and provides an opaque pointer for a response and its length.
PF and VF application can define its own request and response based on the message id
of the mailbox.
For sample usage of the APIs, please refer to ``rvu_lf_rawdev_selftest()``.

Get BAR addresses
-----------------

Application can retrieve PCI BAR addresses of the device using the API
``rte_pmd_rvu_lf_bar_get()``. This helps application to configure the
registers of the hardware device.

Self test
---------

On EAL initialization RVU_LF devices will be probed and populated into
the raw devices. The rawdev ID of the device can be obtained using invocation
of ``rte_rawdev_get_dev_id("NAME:x")`` from the test application, where:

- NAME is the desired subsystem: use "RVU_LF".
- x is the device's bus id specified in "bus:device.func" (BDF) format. BDF follows convention
  used by lspci i.e bus, device and func are specified using respectively two, two and one hex
  digit(s).

Use this identifier for further rawdev function calls.

Selftest rawdev API can be used to verify the mailbox communication between
PF and VF devices based applications. There can be multiple VFs for a particular PF.
Each VF can send mailboxes to PF and PF can broadcast message to all VFs.

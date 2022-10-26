.. SPDX-License-Identifier: BSD-3-Clause
   Copyright (c) 2015-2022 Atomic Rules LLC

=============================================
 Atomic Rules LLC, Baseband Poll Mode Driver
=============================================

The Atomic Rules, Arkville Baseband poll model driver supports the data
movement portion of a baseband device implemented within an FPGA.
The specifics of the encode or decode functions within the FPGA are
outside the scope of Arkville's data movement. Hence this PMD requires and
provides for the customization needed to advertise its
features and support for out-of-band (or meta data) to accompany packet
data between the FPGA device and the host software.


==========
 Features
==========

* Support for LDPC encode and decode operations.
* Support for Turbo encode and decode operations.
* Support for scatter/gather.
* Support Mbuf data room sizes up to 32K bytes for improved performance.
* Support for up to 64 queues
* Support for runtime switching of Mbuf size, per queue, for improved perormance.
* Support for PCIe Gen3x16, Gen4x16, and Gen5x8 endpoints.


=================================
 Required Customization Functions
=================================

The following customization functions are required:
  * Set the capabilities structure for the device `ark_bbdev_info_get()`
  * An optional device start function `rte_pmd_ark_bbdev_start()`
  * An optional device stop function `rte_pmd_ark_bbdev_stop()`
  * Functions for defining meta data format shared between
    the host and FPGA.
    `rte_pmd_ark_bbdev_enqueue_ldpc_dec()`,
    `rte_pmd_ark_bbdev_dequeue_ldpc_dec()`,
    `rte_pmd_ark_bbdev_enqueue_ldpc_enc()`,
    `rte_pmd_ark_bbdev_dequeue_ldpc_enc()`.


=============
 Limitations
=============

* MBufs for the output data from the operation must be sized exactly
   to hold the result based on DATAROOM sizes.
* Side-band or meta data accompaning packet data is limited to 20 Bytes.

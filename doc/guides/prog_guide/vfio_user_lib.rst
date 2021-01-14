..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2020 Intel Corporation.

Vfio User Library
=============

The vfio-user library implements the vfio-user protocol, which is a protocol
that allows an I/O device to be emulated in a separate process outside of a
Virtual Machine Monitor (VMM). The protocol has a client/server model, in which
the server emulates the device and the client (e.g., VMM) consumes the device.
Vfio-user library uses the device model of Linux kernel VFIO and core concepts
defined in its API. The main difference between kernel VFIO and vfio-user is
that the device consumer uses messages over a UNIX domain socket instead of
system calls in vfio-user.

The vfio-user library is used to construct and consume emulated devices. The
server side implementation is mainly for construction of devices and the client
side implementation is mainly for consumption and manipulation of devices. You
use server APIs mainly for two things: provide the device information (e.g.,
region/irq information) to vfio-user library and acquire the configuration
(e.g., DMA table) from client. To construct a device, you could only focus on
the device abstraction that vfio-user library defines rather than how the
server side communicated with client. You use client APIs mainly for acquiring
the device information and configuring the device. The client API usage is
almost the same as the kernel VFIO ioctl.


Vfio User Server API Overview
------------------

The following is an overview of key Vfio User Server API functions. You will
know how to build an emulated device with this overview.

There are mainly four steps of using Vfio User API to build your device:

1. Register

This step includes one API in Vfio User.

* ``rte_vfio_user_register(sock_addr, notify_ops)``

  This function registers a session to communicate with vfio-user client. A
  session maps to one device so that a device instance will be created upon
  registration.

  ``sock_addr`` specifies the Unix domain socket file path and is the identity
  of the session.

  ``notify_ops`` is the a set of callbacks for vfio-user library to notify
  emulated device. Currently, there are five callbacks:

  - ``new_device``
    This callback is invoked when the device is configured and becomes ready.
    The dev_id is for vfio-user library to identify one uniqueue device.

  - ``destroy_device``
    This callback is invoked when the device is destroyed. In most cases, it
    means the client is disconnected from the server.

  - ``update_status``
    This callback is invoked when the device configuration is updated (e.g.,
    DMA table/IRQ update)

  - ``lock_dp``
    This callback is invoked when data path needs to be locked or unlocked.

  - ``reset_device``
    This callback is invoked when the emulated device need reset.

2. Set device information

This step includes three APIs in Vfio User.

* ``rte_vfio_user_set_dev_info(sock_addr, dev_info)``

  This function sets the device information to vfio-user library. The device
  information is defined in Linux VFIO which mainly consists of device type
  and the number of vfio regions and IRQs.

* ``rte_vfio_user_set_reg_info(sock_addr, reg)``

  This function sets the vfio region information to vfio-user library. Regions
  should be created before using this API. The information mainly includes the
  process virtual address, size, file descriptor, attibutes and capabilities of
  regions.

* ``rte_vfio_user_set_irq_info(sock_addr, irq)``

  This function sets the IRQ information to vfio-user library. The information
  includes how many IRQ type the device supports (e.g., MSI/MSI-X) and the IRQ
  count of each type.

3. Start

This step includes one API in Vfio User.

* ``rte_vfio_user_start(sock_addr)``

  This function starts the registered session with vfio-user client. This means
  a control thread will start to listen and handle messages sent from the client.
  Note that only one thread is created for all vfio-user based devices.

  ``sock_addr`` specifies the Unix domain socket file path and is the identity
  of the session.

4. Get device configuration

This step includes two APIs in Vfio User. Both APIs should be called when the
device is ready could be updated anytime. A simple usage of both APIs is using
them in new_device and update_status callbacks.

* ``rte_vfio_user_get_mem_table(dev_id)``

  This function gets the DMA memory table from vfio-user library. The memory
  table entry has the information of guest physical address, process virtual
  address, size and file descriptor. Emulated devices could use the memory
  table to perform DMA read/write on guest memory.

  ``dev_id`` specifies the device ID.

* ``rte_vfio_user_get_irq(dev_id, index, count, fds)``

  This function gets the IRQ's eventfd from vfio-user library. In vfio-user
  library, an efficient way to send interrupts is using eventfds. The eventfd
  should be sent from client. Emulated devices could only call eventfd_write
  to trigger interrupts.

  ``dev_id`` specifies the device ID.

  ``index`` specifies the interrupt type. The mapping of interrupt index and
  type is defined by emulated device.

  ``count`` specifies the interrupt count.

  ``fds`` is for saving the file descriptors.


Vfio User Client API Overview
------------------

The following is an overview of key Vfio User Client API functions. You will
know how to use an emulated device with this overview.

There are mainly three steps of using Vfio User Client API to consume the
device:

1. Attach

This step includes one API in Vfio User.

* ``rte_vfio_user_attach_dev(sock_addr)``

  This function attaches to an emulated device. After the function call
  success, it is viable to acquire device information and configure the device

  ``sock_addr`` specifies the Unix domain socket file path and is the identity
  of the session/device.

2. Get device information

This step includes three APIs in Vfio User.

* ``rte_vfio_user_get_dev_info(dev_id, info)``

  This function gets the device information of the emulated device on the other
  side of socket. The device information is defined in Linux VFIO which mainly
  consists of device type and the number of vfio regions and IRQs.

  ``dev_id`` specifies the identity of the device.

  ``info`` specifies the information of the device.

* ``rte_vfio_user_get_reg_info(dev_id, info, fd)``

  This function gets the region information of the emulated device on the other
  side of socket. The region information is defined in Linux VFIO which mainly
  consists of region size, index and capabilities.

  ``info`` specifies the information of the region.

  ``fd`` specifies the file descriptor of the region.

* ``rte_vfio_user_get_irq_info(dev_id, irq)``

  This function sets the IRQ information to vfio-user library. The IRQ
  information includes IRQ count and index.

  ``info`` specifies the information of the IRQ.

3. Configure the device

This step includes three APIs in Vfio User.

* ``rte_vfio_user_dma_map(dev_id, mem, fds, num)``

  This function maps DMA memory regions for the emulated device.

  ``mem`` specifies the information of DMA memory regions.

  ``fds`` specifies the file descriptors of the DMA memory regions.

  ``num`` specifies the number of the DMA memory regions.

* ``rte_vfio_user_dma_unmap(dev_id, mem, num)``

  This function unmaps DMA memory regions for the emulated device.

* ``rte_vfio_user_set_irqs(dev_id, set)``

  This function configure the interrupts for the emulated device.

  ``set`` specifies the configuration of interrupts.

After the above three steps are done, users can easily use the emulated device
(e.g., do I/O operations).
..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2017-2018 Intel Corporation.

Vhost_Crypto Sample Application
===============================

Overview
--------

The vhost_crypto sample application implements a crypto device used
as the backend of a QEMU vhost-user-crypto device. Similar to the
vhost-user-net and vhost-user-scsi devices, the sample application uses a
domain socket to communicate with QEMU, and the virtio ring is processed
by the vhost_crypto sample application.

This section shows how to start a VM with the crypto device as a
fast data path for critical applications.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``examples`` sub-directory.

Running the Application
-----------------------

Start the vhost_crypto Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

    ./dpdk-vhost_crypto [EAL options] --
            --config (lcore,cdev-id,queue-id)[,(lcore,cdev-id,queue-id)]
            --socket-file lcore,PATH
            [--zero-copy]
            [--guest-polling]
            [--asymmetric-crypto]

where:

**--config (lcore,cdev-id,queue-id)**
    Builds the lcore-cryptodev-queue connection. When specified, the lcore
    works only with the specified cryptodev's queue.

**--socket-file lcore,PATH**
    Specifies the path of the UNIX socket file to be created and the lcore
    that handles all workloads for the socket. Multiple instances of this
    option are supported, and one lcore can process multiple sockets.

**--zero-copy**
    Enables the zero-copy feature when present. Otherwise, zero-copy is
    disabled. Note that the zero-copy feature is experimental and may cause
    problems such as segmentation faults. If the user wants to use LKCF in
    the guest, this feature should be disabled.

**--guest-polling**
    When present, the application assumes the guest works in polling mode
    and does not notify the guest of processing completion.

**--asymmetric-crypto**
    When present, the application can handle asymmetric crypto requests.
    When this option is used, symmetric crypto requests cannot be handled
    by the application.

The application requires that crypto devices capable of performing
the specified crypto operation are available at initialization.
This means that hardware crypto devices must be bound to a DPDK driver or
software crypto devices (virtual crypto PMD) must be created using --vdev.

.. _vhost_crypto_app_run_vm:

Start the VM
~~~~~~~~~~~~

.. code-block:: console

    qemu-system-x86_64 -machine accel=kvm \
        -m $mem -object memory-backend-file,id=mem,size=$mem,\
        mem-path=/dev/hugepages,share=on -numa node,memdev=mem \
        -drive file=os.img,if=none,id=disk \
        -device ide-hd,drive=disk,bootindex=0 \
        -chardev socket,id={chardev_id},path={PATH} \
        -object cryptodev-vhost-user,id={obj_id},chardev={chardev_id} \
        -device virtio-crypto-pci,id={dev_id},cryptodev={obj_id} \
        ...

.. note::
    Verify that your QEMU supports ``vhost-user-crypto``.

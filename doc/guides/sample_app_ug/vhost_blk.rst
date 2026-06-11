..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2017 Intel Corporation.

Vhost_blk Sample Application
=============================

Overview
--------

The vhost_blk sample application implements a simple block device,
which serves as the backend for the QEMU vhost-user-blk device. Users can
extend the existing example to use other types of block devices (e.g., AIO)
besides memory-based block devices. Similar to the vhost-user-net device,
the sample application uses a Unix domain socket to communicate with QEMU
and processes the virtio ring (split or packed format).

The sample application reuses code from SPDK (Storage Performance
Development Kit, https://github.com/spdk/spdk) vhost-user-blk target.
For DPDK vhost library usage in storage applications, users can refer
to SPDK as well.

This section shows how to start a VM with the block device as
fast data path for critical application.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``examples/vhost_blk`` directory.

You will need to build DPDK both on the host and inside the guest.

Running the Application
-----------------------

Start the vhost_blk application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

        ./dpdk-vhost_blk -m 1024

.. _vhost_blk_app_run_vm:

Start the VM
~~~~~~~~~~~~

.. code-block:: console

    qemu-system-x86_64 -machine accel=kvm \
        -m $mem -object memory-backend-file,id=mem,size=$mem,\
        mem-path=/dev/hugepages,share=on -numa node,memdev=mem \
        -drive file=os.img,if=none,id=disk \
        -device ide-hd,drive=disk,bootindex=0 \
        -chardev socket,id=char0,reconnect=1,path=/tmp/vhost.socket \
        -device vhost-user-blk-pci,packed=on,chardev=char0,num-queues=1 \
        ...

QEMU Options
^^^^^^^^^^^^

QEMU v4.0 or newer is required for vhost-user-blk support.

reconnect=1
   Enables live recovery support, allowing QEMU to reconnect to the
   vhost_blk application after it restarts.

packed=on
   Enables packed virtqueue support. Requires guest kernel version 5.0
   or newer.

QEMU commit 9bb73502321d supports both vhost-blk reconnect and packed ring.

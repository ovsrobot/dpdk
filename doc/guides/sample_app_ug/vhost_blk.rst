..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2017 Intel Corporation.

Vhost_blk Sample Application
============================

Overview
--------

The vhost_blk sample application implements a simple block device
used as the backend of a QEMU vhost-user-blk device. Users can extend
the existing example to use other types of block devices (for example, AIO)
in addition to memory-based block devices. Similar to the vhost-user-net
device, the sample application uses a domain socket to communicate with QEMU,
and the virtio ring (split or packed format) is processed by the vhost_blk
sample application.

The sample application reuses code from SPDK (Storage Performance
Development Kit, https://github.com/spdk/spdk) vhost-user-blk target.
For DPDK vhost library use in storage applications, SPDK can also serve
as a reference.

This section shows how to start a VM with the block device as a
fast data path for critical applications.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``examples`` sub-directory.

You need to build DPDK both on the host and inside the guest.

Running the Application
-----------------------

Start the vhost_blk Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

.. note::
    Verify that your QEMU supports ``vhost-user-blk``. QEMU v4.0 or later
    is required.

    * ``reconnect=1`` enables live recovery support, allowing QEMU to reconnect
      to vhost_blk after the vhost_blk example is restarted.
    * ``packed=on`` enables packed ring support, which requires guest kernel
      version 5.0 or later.

    QEMU commit 9bb73502321d46f4d320fa17aa38201445783fc4 supports both
    vhost-blk reconnect and packed ring.

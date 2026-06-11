..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2017-2018 Intel Corporation.

Vhost_Crypto Sample Application
===============================

The vhost_crypto sample application implements a Crypto device,
which serves as the backend for the QEMU vhost-user-crypto device.
Similar to vhost-user-net and vhost-user-scsi devices, the application uses
a domain socket to communicate with QEMU, and processes the virtio rings
to provide cryptographic services to the guest.

This section shows the steps to start a VM with the crypto device as
fast data path for critical application.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``examples`` sub-directory.

Running the Application
-----------------------

Start the vhost_crypto example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

    ./dpdk-vhost_crypto [EAL options] --
    		--config (lcore,cdev-id,queue-id)[,(lcore,cdev-id,queue-id)]
    		--socket-file lcore,PATH
    		[--zero-copy]
    		[--guest-polling]
    		[--asymmetric-crypto]

where,

* config (lcore,cdev-id,queue-id): builds the lcore-cryptodev id-queue id
  connection. When specified, the lcore only works with the
  specified cryptodev queue.

* socket-file lcore,PATH: specifies the path of the UNIX socket file to be created and
  the lcore id that handles all workloads of the socket. Multiple
  instances of this config item are supported and one lcore can process
  multiple sockets.

* zero-copy: when present, indicates the zero-copy feature will be
  enabled. Otherwise it is disabled.

* guest-polling: when present, assumes the guest works in polling
  mode and does not notify the guest upon completion of
  processing.

* asymmetric-crypto: when present, indicates the application handles
  asymmetric crypto requests. When this option is used, the application
  cannot handle symmetric crypto requests.

.. note::
   The zero-copy feature is experimental and may cause segmentation faults.
   If you want to use LKCF in the guest, disable this feature.

.. note::
   The application requires that crypto devices capable of performing
   the specified crypto operation are available on application initialization.
   HW crypto devices must be bound to a DPDK driver or an SW crypto device
   (virtual crypto PMD) must be created using --vdev.

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
   You must verify that your QEMU supports vhost-user-crypto.

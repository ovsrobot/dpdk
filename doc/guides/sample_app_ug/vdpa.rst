..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Intel Corporation.

Vdpa Sample Application
=======================

Overview
--------

The vDPA sample application creates vhost-user sockets by using the
vDPA backend. vDPA (vhost Data Path Acceleration) uses virtio ring
compatible devices to serve a virtio driver directly, enabling
datapath acceleration. A vDPA driver can help to set up the vhost datapath.
This application does not need dedicated worker threads for vhost
enqueue/dequeue operations.

The following shows how to start VMs with a vDPA vhost-user
backend and verify network connection and live migration.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``vdpa`` sub-directory.

Running the Application
-----------------------

Start the vDPA Example
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

        ./dpdk-vdpa [EAL options]  -- [--client] [--interactive|-i] or [--iface SOCKET_PATH]

where:

* --client runs the vdpa application in client mode. In client mode, QEMU
  runs as the server and is responsible for socket file creation.
* --iface specifies the path prefix of the UNIX domain socket file (for example,
  /tmp/vhost-user-). The socket files are named /tmp/vhost-user-<n>
  where n starts from 0.
* --interactive runs the vDPA sample in interactive mode with the following
  commands:

  #. help: show help message

  #. list: list all available vDPA devices

  #. create: create a new vDPA port with socket file and vDPA device address

  #. stats: show statistics of virtio queues

  #. quit: unregister vhost driver and exit the application

The following example uses the IFCVF driver:

.. code-block:: console

        ./dpdk-vdpa -l 1 --numa-mem 1024,1024 \
                -a 0000:06:00.3,vdpa=1 -a 0000:06:00.4,vdpa=1 \
                -- --interactive

.. note::
    Here 0000:06:00.3 and 0000:06:00.4 refer to virtio ring compatible devices.
    Bind vfio-pci to them before running the vdpa sample:

    * modprobe vfio-pci
    * ./usertools/dpdk-devbind.py -b vfio-pci 06:00.3 06:00.4

Then, create two vdpa ports in the interactive command line.

.. code-block:: console

        vdpa> list
        device id       device address  queue num       supported features
        0               0000:06:00.3    1               0x14c238020
        1               0000:06:00.4    1               0x14c238020
        2               0000:06:00.5    1               0x14c238020

        vdpa> create /tmp/vdpa-socket0 0000:06:00.3
        vdpa> create /tmp/vdpa-socket1 0000:06:00.4

.. _vdpa_app_run_vm:

Start the VMs
~~~~~~~~~~~~~

.. code-block:: console

       qemu-system-x86_64 -cpu host -enable-kvm \
       <snip>
       -mem-prealloc \
       -chardev socket,id=char0,path=<socket_file created in above steps> \
       -netdev type=vhost-user,id=vdpa,chardev=char0 \
       -device virtio-net-pci,netdev=vdpa,mac=00:aa:bb:cc:dd:ee,page-per-vq=on \

After the VMs launch, log into the VMs and configure the IP address to verify
network connection via ping or netperf.

.. note::
    QEMU 3.0.0 or later is recommended as it extends vhost-user for vDPA.

Live Migration
~~~~~~~~~~~~~~
vDPA supports cross-backend live migration. Users can migrate a SW vhost
backend VM to a vDPA backend VM and vice versa. The following are the
detailed steps. Assume A is the source host with the SW vhost VM and B is
the destination host with vDPA.

#. Start the vdpa sample and launch a VM with the same parameters as the VM
   on A, in migration-listen mode:

   .. code-block:: console

        B: <qemu-command-line> -incoming tcp:0:4444 (or other PORT)

#. Start the migration (on source host):

   .. code-block:: console

        A: (qemu) migrate -d tcp:<B ip>:4444 (or other PORT)

#. Check the status (on source host):

   .. code-block:: console

        A: (qemu) info migrate

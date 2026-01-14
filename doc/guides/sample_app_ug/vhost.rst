..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2016 Intel Corporation.

Vhost Sample Application
========================

Overview
--------

The vhost sample application demonstrates integration of the Data Plane
Development Kit (DPDK) with the Linux* KVM hypervisor by implementing the
vhost-net offload API. The sample application performs simple packet
switching between virtual machines based on Media Access Control (MAC)
address or Virtual Local Area Network (VLAN) tag. The splitting of Ethernet
traffic from an external switch is performed in hardware by the Virtual
Machine Device Queues (VMDQ) and Data Center Bridging (DCB) features of
the Intel® 82599 10 Gigabit Ethernet Controller.

Testing Steps
~~~~~~~~~~~~~

This section shows how to test a typical PVP case with the dpdk-vhost sample,
where packets are received from the physical NIC port first and enqueued to the
VM's Rx queue. Through the guest testpmd's default forwarding mode (io forward),
those packets are put into the Tx queue. The dpdk-vhost example, in turn,
gets the packets and puts them back to the same physical NIC port.

Compiling the Application
-------------------------

To compile the sample application, see :doc:`compiling`.

The application is located in the ``vhost`` sub-directory.

.. note::
   In this example, you need to build DPDK both on the host and inside guest.

.. _vhost_app_run_vm:

Start the VM
~~~~~~~~~~~~

.. code-block:: console

    qemu-system-x86_64 -machine accel=kvm -cpu host \
        -m $mem -object memory-backend-file,id=mem,size=$mem,mem-path=/dev/hugepages,share=on \
                -mem-prealloc -numa node,memdev=mem \
        \
        -chardev socket,id=char1,path=/tmp/sock0,server \
        -netdev type=vhost-user,id=hostnet1,chardev=char1  \
        -device virtio-net-pci,netdev=hostnet1,id=net1,mac=52:54:00:00:00:14 \
        ...

.. note::
    For basic vhost-user support, QEMU 2.2 or later is required. For
    some specific features, a higher version might be needed. For example,
    QEMU 2.7 or later is required for the reconnect feature.


Start the vswitch Example
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

        ./dpdk-vhost -l 0-3 --numa-mem 1024  \
             -- --socket-file /tmp/sock0 --client \
             ...

See the `Parameters`_ section for explanations of the command-line options.

Running the Application
-----------------------

.. _vhost_app_run_dpdk_inside_guest:

Run testpmd Inside Guest
~~~~~~~~~~~~~~~~~~~~~~~~

Ensure DPDK is built inside the guest and that the corresponding virtio-net
PCI device is bound to a UIO driver. This can be done as follows:

.. code-block:: console

   modprobe vfio-pci
   dpdk/usertools/dpdk-devbind.py -b vfio-pci 0000:00:04.0

Then, start testpmd for packet forwarding testing.

.. code-block:: console

    ./<build_dir>/app/dpdk-testpmd -l 0-1 -- -i
    > start tx_first

For more information about vIOMMU, NO-IOMMU, and VFIO, see the
:doc:`/../linux_gsg/linux_drivers` section of the DPDK Getting Started Guide.

Explanation
-----------

Inject Packets
~~~~~~~~~~~~~~

When a virtio-net device connects to dpdk-vhost, a VLAN tag starting with
1000 is assigned to it. Configure your packet generator with the appropriate
MAC and VLAN tag. The following log message should appear on the dpdk-vhost
console::

    VHOST_DATA: (0) mac 52:54:00:00:00:14 and vlan 1000 registered


.. _vhost_app_parameters:

Parameters
~~~~~~~~~~

**--socket-file path**
    Specifies the vhost-user socket file path.

**--client**
    DPDK vhost-user acts as the client when this option is given.
    In client mode, QEMU creates the socket file. Otherwise, DPDK
    creates it. The server always creates the socket file.

**--vm2vm mode**
    Sets the mode of packet switching between guests in the host.

    - 0 disables vm2vm, meaning VM packets always go to the NIC port.
    - 1 enables normal MAC lookup packet routing.
    - 2 enables hardware mode packet forwarding between guests. Packets
      can go to the NIC port, and the hardware L2 switch determines which
      guest the packet should be forwarded to or whether it needs to be
      sent externally, based on the packet destination MAC address and
      VLAN tag.

**--mergeable 0|1**
    Set to 0 to disable or 1 to enable the mergeable Rx feature.
    Disabled by default.

**--stats interval**
    Controls the printing of virtio-net device statistics.
    The parameter specifies an interval in seconds to print statistics.
    An interval of 0 disables statistics.

**--rx-retry 0|1**
    Enables or disables enqueue retries when the guest's Rx queue
    is full. This feature resolves packet loss observed at high data
    rates by allowing delay and retry in the receive path. Enabled by default.

**--rx-retry-num num**
    Specifies the number of retries on an Rx burst. Takes effect only when
    rx-retry is enabled. The default value is 4.

**--rx-retry-delay msec**
    Specifies the timeout in microseconds between retries on an Rx burst.
    Takes effect only when rx-retry is enabled. The default value is 15.

**--builtin-net-driver**
    Uses a simple vhost-user net driver that demonstrates how to use the
    generic vhost APIs. Disabled by default.

**--dmas**
    Specifies the assigned DMA device of a vhost device.
    The async vhost-user net driver is used when --dmas is set. For example,
    ``--dmas [txd0@00:04.0,txd1@00:04.1,rxd0@00:04.2,rxd1@00:04.3]`` means
    DMA channel 00:04.0/00:04.2 is used for vhost device 0 enqueue/dequeue
    operations and DMA channel 00:04.1/00:04.3 is used for vhost device 1
    enqueue/dequeue operations. The index of the device corresponds to the
    socket file in order: vhost device 0 is created through the first socket
    file, vhost device 1 is created through the second socket file, and so on.

**--total-num-mbufs 0-N**
    Sets the number of mbufs to be allocated in mbuf pools.
    The default value is 147456. This option can be used if port launch fails
    due to shortage of mbufs.

**--tso 0|1**
    Disables or enables TCP segment offload.

**--tx-csum 0|1**
    Disables or enables TX checksum offload.

**-p mask**
    Port mask specifying the ports to be used.

Common Issues
~~~~~~~~~~~~~

* QEMU fails to allocate memory on hugetlbfs and shows an error like the
  following::

      file_ram_alloc: can't mmap RAM pages: Cannot allocate memory

  When running QEMU, the above error indicates that it has failed to allocate
  memory for the Virtual Machine on the hugetlbfs. This is typically due to
  insufficient hugepages being free to support the allocation request. The
  number of free hugepages can be checked as follows:

  .. code-block:: console

     dpdk-hugepages.py --show

  The command above indicates how many hugepages are free to support QEMU's
  allocation request.

* Failed to build DPDK in VM

  Ensure the ``-cpu host`` QEMU option is given.

* Device start fails if NIC's max queues exceeds the default of 128

  The mbuf pool size depends on the MAX_QUEUES configuration. If the NIC's
  max queue number is larger than 128, device start fails due to
  insufficient mbufs. Adjust using the ``--total-num-mbufs`` parameter.

* Option ``builtin-net-driver`` is incompatible with QEMU

  The QEMU vhost net device start fails if the protocol feature is not
  negotiated. DPDK virtio-user PMD can be used as a replacement for QEMU.

* Device start fails when enabling ``builtin-net-driver`` without memory
  pre-allocation

  The builtin example does not support dynamic memory allocation. When the
  vhost backend enables ``builtin-net-driver``, the ``--numa-mem`` option
  should be added at the virtio-user PMD side as a startup item.

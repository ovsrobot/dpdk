..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2021 Advanced Micro Devices, Inc. All rights reserved.

PTDMA Rawdev Driver
===================

The ``ptdma`` rawdev driver provides a poll-mode driver (PMD) for AMD PTDMA device.

Hardware Requirements
----------------------

The ``dpdk-devbind.py`` script, included with DPDK,
can be used to show the presence of supported hardware.
Running ``dpdk-devbind.py --status-dev misc`` will show all the miscellaneous,
or rawdev-based devices on the system.

Sample output from a system with PTDMA is shown below

Misc (rawdev) devices using DPDK-compatible driver
==================================================
0000:01:00.2 'Starship/Matisse PTDMA 1498' drv=igb_uio unused=vfio-pci
0000:02:00.2 'Starship/Matisse PTDMA 1498' drv=igb_uio unused=vfio-pci

Devices using UIO drivers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The HW devices to be used will need to be bound to a user-space IO driver for use.
The ``dpdk-devbind.py`` script can be used to view the state of the PTDMA devices
and to bind them to a suitable DPDK-supported driver, such as ``igb_uio``.
For example::

        $ sudo ./usertools/dpdk-devbind.py  --force --bind=igb_uio 0000:01:00.2 0000:02:00.2

Compilation
------------

For builds using ``meson`` and ``ninja``, the driver will be built when the target platform is x86-based.
No additional compilation steps are necessary.


Using PTDMA Rawdev Devices
--------------------------

To use the devices from an application, the rawdev API can be used, along
with definitions taken from the device-specific header file
``rte_ptdma_rawdev.h``. This header is needed to get the definition of
structure parameters used by some of the rawdev APIs for PTDMA rawdev
devices, as well as providing key functions for using the device for memory
copies.

Getting Device Information
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic information about each rawdev device can be queried using the
``rte_rawdev_info_get()`` API. For most applications, this API will be
needed to verify that the rawdev in question is of the expected type. For
example, the following code snippet can be used to identify an PTDMA
rawdev device for use by an application:

.. code-block:: C

        for (i = 0; i < count && !found; i++) {
                struct rte_rawdev_info info = { .dev_private = NULL };
                found = (rte_rawdev_info_get(i, &info, 0) == 0 &&
                                strcmp(info.driver_name,
                                                PTDMA_PMD_RAWDEV_NAME) == 0);
        }

When calling the ``rte_rawdev_info_get()`` API for an PTDMA rawdev device,
the ``dev_private`` field in the ``rte_rawdev_info`` struct should either
be NULL, or else be set to point to a structure of type
``rte_ptdma_rawdev_config``, in which case the size of the configured device
input ring will be returned in that structure.

Device Configuration
~~~~~~~~~~~~~~~~~~~~~

Configuring an PTDMA rawdev device is done using the
``rte_rawdev_configure()`` API, which takes the same structure parameters
as the, previously referenced, ``rte_rawdev_info_get()`` API. The main
difference is that, because the parameter is used as input rather than
output, the ``dev_private`` structure element cannot be NULL, and must
point to a valid ``rte_ptdma_rawdev_config`` structure, containing the ring
size to be used by the device. The ring size must be a power of two,
between 64 and 4096.
If it is not needed, the tracking by the driver of user-provided completion
handles may be disabled by setting the ``hdls_disable`` flag in
the configuration structure also.

The following code shows how the device is configured in
``test_ptdma_rawdev.c``:

.. code-block:: C

   #define PTDMA_TEST_RINGSIZE 512
        struct rte_ptdma_rawdev_config p = { .ring_size = -1 };
        struct rte_rawdev_info info = { .dev_private = &p };

        /* ... */

        p.ring_size = PTDMA_TEST_RINGSIZE;
        if (rte_rawdev_configure(dev_id, &info, sizeof(p)) != 0) {
                printf("Error with rte_rawdev_configure()\n");
                return -1;
        }

Once configured, the device can then be made ready for use by calling the
``rte_rawdev_start()`` API.

Performing Data Copies
~~~~~~~~~~~~~~~~~~~~~~~

To perform data copies using PTDMA rawdev devices, the functions
``rte_ptdma_enqueue_copy()`` and ``rte_ptdma_perform_ops()`` should be used.
Once copies have been completed, the completion will be reported back when
the application calls ``rte_ptdma_completed_ops()``.

The ``rte_ptdma_enqueue_copy()`` function enqueues a single copy to the
device ring for copying at a later point. The parameters to that function
include the IOVA addresses of both the source and destination buffers,
as well as two "handles" to be returned to the user when the copy is
completed. These handles can be arbitrary values, but two are provided so
that the library can track handles for both source and destination on
behalf of the user, e.g. virtual addresses for the buffers, or mbuf
pointers if packet data is being copied.

While the ``rte_ptdma_enqueue_copy()`` function enqueues a copy operation on
the device ring, the copy will not actually be performed until after the
application calls the ``rte_ptdma_perform_ops()`` function. This function
informs the device hardware of the elements enqueued on the ring, and the
device will begin to process them. It is expected that, for efficiency
reasons, a burst of operations will be enqueued to the device via multiple
enqueue calls between calls to the ``rte_ptdma_perform_ops()`` function.

The following code from ``test_ptdma_rawdev.c`` demonstrates how to enqueue
a burst of copies to the device and start the hardware processing of them:

.. code-block:: C

        struct rte_mbuf *srcs[32], *dsts[32];
        unsigned int j;

        for (i = 0; i < RTE_DIM(srcs); i++) {
                char *src_data;

                srcs[i] = rte_pktmbuf_alloc(pool);
                dsts[i] = rte_pktmbuf_alloc(pool);
                srcs[i]->data_len = srcs[i]->pkt_len = length;
                dsts[i]->data_len = dsts[i]->pkt_len = length;
                src_data = rte_pktmbuf_mtod(srcs[i], char *);

                for (j = 0; j < length; j++)
                        src_data[j] = rand() & 0xFF;

                if (rte_ptdma_enqueue_copy(dev_id,
                                srcs[i]->buf_iova + srcs[i]->data_off,
                                dsts[i]->buf_iova + dsts[i]->data_off,
                                length,
                                (uintptr_t)srcs[i],
                                (uintptr_t)dsts[i]) != 1) {
                        printf("Error with rte_ptdma_enqueue_copy for buffer %u\n",
                                        i);
                        return -1;
                }
        }
        rte_ptdma_perform_ops(dev_id);

To retrieve information about completed copies, the API
``rte_ptdma_completed_ops()`` should be used. This API will return to the
application a set of completion handles passed in when the relevant copies
were enqueued.

The following code from ``test_ptdma_rawdev.c`` shows the test code
retrieving information about the completed copies and validating the data
is correct before freeing the data buffers using the returned handles:

.. code-block:: C

        if (rte_ptdma_completed_ops(dev_id, 64, (void *)completed_src,
                        (void *)completed_dst) != RTE_DIM(srcs)) {
                printf("Error with rte_ptdma_completed_ops\n");
                return -1;
        }
        for (i = 0; i < RTE_DIM(srcs); i++) {
                char *src_data, *dst_data;

                if (completed_src[i] != srcs[i]) {
                        printf("Error with source pointer %u\n", i);
                        return -1;
                }
                if (completed_dst[i] != dsts[i]) {
                        printf("Error with dest pointer %u\n", i);
                        return -1;
                }

                src_data = rte_pktmbuf_mtod(srcs[i], char *);
                dst_data = rte_pktmbuf_mtod(dsts[i], char *);
                for (j = 0; j < length; j++)
                        if (src_data[j] != dst_data[j]) {
                                printf("Error with copy of packet %u, byte %u\n",
                                                i, j);
                                return -1;
                        }
                rte_pktmbuf_free(srcs[i]);
                rte_pktmbuf_free(dsts[i]);
        }

Querying Device Statistics
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The statistics from the PTDMA rawdev device can be got via the xstats
functions in the ``rte_rawdev`` library, i.e.
``rte_rawdev_xstats_names_get()``, ``rte_rawdev_xstats_get()`` and
``rte_rawdev_xstats_by_name_get``. The statistics returned for each device
instance are:

* ``failed_enqueues``
* ``successful_enqueues``
* ``copies_started``
* ``copies_completed``

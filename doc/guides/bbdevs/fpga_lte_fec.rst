..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2019 Intel Corporation

Intel(R) FPGA LTE FEC Poll Mode Driver
======================================

The BBDEV FPGA LTE FEC poll mode driver (PMD) supports an FPGA implementation of a VRAN
Turbo Encode / Decode LTE wireless acceleration function, using Intel's PCI-e and FPGA
based Vista Creek device.

Features
--------

FPGA LTE FEC PMD supports the following features:

- Turbo Encode in the DL with total throughput of 4.5 Gbits/s
- Turbo Decode in the UL with total throughput of 1.5 Gbits/s assuming 8 decoder iterations
- 8 VFs per PF (physical device)
- Maximum of 32 UL queues per VF
- Maximum of 32 DL queues per VF
- PCIe Gen-3 x8 Interface
- MSI-X
- SR-IOV


FPGA LTE FEC PMD supports the following BBDEV capabilities:

* For the turbo encode operation:
   - ``RTE_BBDEV_TURBO_CRC_24B_ATTACH`` :  set to attach CRC24B to CB(s)
   - ``RTE_BBDEV_TURBO_RATE_MATCH`` :  if set then do not do Rate Match bypass
   - ``RTE_BBDEV_TURBO_ENC_INTERRUPTS`` :  set for encoder dequeue interrupts


* For the turbo decode operation:
   - ``RTE_BBDEV_TURBO_CRC_TYPE_24B`` :  check CRC24B from CB(s)
   - ``RTE_BBDEV_TURBO_SUBBLOCK_DEINTERLEAVE`` :  perform subblock de-interleave
   - ``RTE_BBDEV_TURBO_DEC_INTERRUPTS`` :  set for decoder dequeue interrupts
   - ``RTE_BBDEV_TURBO_NEG_LLR_1_BIT_IN`` :  set if negative LLR encoder i/p is supported
   - ``RTE_BBDEV_TURBO_DEC_TB_CRC_24B_KEEP`` :  keep CRC24B bits appended while decoding


Limitations
-----------

FPGA LTE FEC does not support the following:

- Scatter-Gather function


Installation
--------------

Section 3 of the DPDK manual provides instructions on installing and compiling DPDK.

DPDK requires hugepages to be configured as detailed in section 2 of the DPDK manual.
The bbdev test application has been tested with a configuration 40 x 1GB hugepages. The
hugepage configuration of a server may be examined using:

.. code-block:: console

   grep Huge* /proc/meminfo


Initialization
--------------

When the device first powers up, its PCI Physical Functions (PF) can be listed through this command:

.. code-block:: console

  sudo lspci -vd1172:5052


Binding and Virtual Functions enablement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The PMD relies on kernel modules to interface with the device: both UIO and VFIO kernel modules
are supported.
See :ref:`linux_gsg_binding_kernel` section for more details, notably with regards to
generic kernel modules binding and VF enablement.
More details on usage model is captured in the :ref:`pf_bb_config_fpga_lte` section.

Device configuration
~~~~~~~~~~~~~~~~~~~~

The device must be configured to work properly.
The configuration involves allocating the number of hardware
queues, priorities, load balance, bandwidth and other settings necessary for the
device to perform FEC functions.

This configuration needs to be executed at least once after reboot or PCI FLR and can
be achieved by either using ``pf_bb_config`` or the function ``rte_fpga_lte_fec_configure()``,
which sets up the parameters defined in the compatible ``rte_fpga_lte_fec_conf`` structure.
This is the method used in the bbdev-test test application.


Test Application
----------------

BBDEV provides a test application, ``test-bbdev.py`` and range of test data for testing
the functionality of FPGA LTE FEC turbo encode and turbo decode, depending on the device's
capabilities. The test application is located under app->test-bbdev folder and has the
following options:

.. code-block:: console

  "-p", "--testapp-path": specifies path to the bbdev test app.
  "-e", "--eal-params"	: EAL arguments which are passed to the test app.
  "-t", "--timeout"	: Timeout in seconds (default=300).
  "-c", "--test-cases"	: Defines test cases to run. Run all if not specified.
  "-v", "--test-vector"	: Test vector path (default=dpdk_path+/app/test-bbdev/test_vectors/bbdev_null.data).
  "-n", "--num-ops"	: Number of operations to process on device (default=32).
  "-b", "--burst-size"	: Operations enqueue/dequeue burst size (default=32).
  "-l", "--num-lcores"	: Number of lcores to run (default=16).
  "-i", "--init-device" : Initialise PF device with default values.


To execute the test application tool using simple turbo decode or turbo encode data,
type one of the following:

.. code-block:: console

  ./test-bbdev.py -c validation -n 64 -b 8 -v ./turbo_dec_default.data
  ./test-bbdev.py -c validation -n 64 -b 8 -v ./turbo_enc_default.data


The test application ``test-bbdev.py``, supports the ability to configure the PF device with
a default set of values, if the "-i" or "- -init-device" option is included. The default values
are defined in test_bbdev_perf.c as:

- VF_UL_QUEUE_VALUE 4
- VF_DL_QUEUE_VALUE 4
- UL_BANDWIDTH 3
- DL_BANDWIDTH 3
- UL_LOAD_BALANCE 128
- DL_LOAD_BALANCE 128
- FLR_TIMEOUT 610


Test Vectors
~~~~~~~~~~~~

In addition to the simple turbo decoder and turbo encoder tests, bbdev also provides
a range of additional tests under the test_vectors folder, which may be useful. The results
of these tests will depend on the FPGA LTE FEC capabilities:

* turbo decoder tests:
   - ``turbo_dec_c1_k6144_r0_e10376_crc24b_sbd_negllr_high_snr.data``
   - ``turbo_dec_c1_k6144_r0_e10376_crc24b_sbd_negllr_low_snr.data``
   - ``turbo_dec_c1_k6144_r0_e34560_negllr.data``
   - ``turbo_dec_c1_k6144_r0_e34560_sbd_negllr.data``
   - ``turbo_dec_c2_k3136_r0_e4920_sbd_negllr_crc24b.data``
   - ``turbo_dec_c2_k3136_r0_e4920_sbd_negllr.data``


* turbo encoder tests:
   - ``turbo_enc_c1_k40_r0_e1190_rm.data``
   - ``turbo_enc_c1_k40_r0_e1194_rm.data``
   - ``turbo_enc_c1_k40_r0_e1196_rm.data``
   - ``turbo_enc_c1_k40_r0_e272_rm.data``
   - ``turbo_enc_c1_k6144_r0_e18444.data``
   - ``turbo_enc_c1_k6144_r0_e32256_crc24b_rm.data``
   - ``turbo_enc_c2_k5952_r0_e17868_crc24b.data``
   - ``turbo_enc_c3_k4800_r2_e14412_crc24b.data``
   - ``turbo_enc_c4_k4800_r2_e14412_crc24b.data``


.. _pf_bb_config_fpga_lte:

Alternate Baseband Device configuration tool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On top of the embedded configuration feature supported in test-bbdev using "- -init-device"
option, there is also a tool available to perform that device configuration using a companion
application.
The ``pf_bb_config`` application notably enables then to run bbdev-test from the VF
and not only limited to the PF as captured above.

See for more details: https://github.com/intel/pf-bb-config

Specifically for the BBDEV FPGA LTE FEC PMD, the command below can be used:

.. code-block:: console

  ./pf_bb_config FPGA_LTE -c fpga_lte/fpga_lte_config_vf.cfg
  ./test-bbdev.py -e="-c 0xff0 -a${VF_PCI_ADDR}" -c validation -n 64 -b 32 -l 1 -v ./turbo_dec_default.data

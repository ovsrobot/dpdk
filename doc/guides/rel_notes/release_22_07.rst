.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2022 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 22.07
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_22_07.html


New Features
------------

.. This section should contain new features added in this release.
   Sample format:

   * **Add a title in the past tense with a full stop.**

     Add a short 1-2 sentence description in the past tense.
     The description should be enough to allow someone scanning
     the release notes to understand the new feature.

     If the feature adds a lot of sub-features you can use a bullet list
     like this:

     * Added feature foo to do something.
     * Enhanced feature bar to do something else.

     Refer to the previous release notes for examples.

     Suggested order in release notes items:
     * Core libs (EAL, mempool, ring, mbuf, buses)
     * Device abstraction libs and PMDs (ordered alphabetically by vendor name)
       - ethdev (lib, PMDs)
       - cryptodev (lib, PMDs)
       - eventdev (lib, PMDs)
       - etc
     * Other libs
     * Apps, Examples, Tools (if significant)

     This section is a comment. Do not overwrite or remove it.
     Also, make sure to start the actual text at the margin.
     =======================================================

* **Added initial RISC-V architecture support.***

  Added EAL implementation for RISC-V architecture. The initial device the
  porting was tested on is a HiFive Unmatched development board based on the
  SiFive Freedom U740 SoC. In theory this implementation should work with any
  ``rv64gc`` ISA compatible implementation with MMU supporting a reasonable
  address space size (U740 uses sv39 MMU).

  * Verified with meson tests. ``fast-tests`` suite passing with default config.
  * Verified PMD operation with Intel x520-DA2 NIC (``ixgbe``) and ``test-pmd``
    application. Packet transfer checked using all UIO drivers available for
    non-IOMMU platforms: ``uio_pci_generic``, ``vfio-pci noiommu`` and
    ``igb_uio``.
  * The ``i40e`` PMD driver is disabled on RISC-V as ``rv64gc`` ISA has no
    vector operations.
  * RISCV support is currently limited to Linux.
  * Clang compilation currently not supported due to issues with relocation
    relaxation.
  * Debug build of ``app/test/dpdk-test`` fails currently on RISC-V due to
    seemingly invalid loop and goto jump code generation by GCC in
    ``test_ring.c`` where extensive inlining increases the code size beyond the
    capability of the generated instruction (JAL: +/-1MB PC-relative). The
    workaround is to disable ``test_ring_basic_ex()`` and ``test_ring_with_exact_size()`` on RISC-V on ``-O0`` or ``-Og``.

* **Updated Intel iavf driver.**

  * Added Tx QoS queue rate limitation support.
  * Added quanta size configuration support.

* **Updated Mellanox mlx5 driver.**

  * Added support for promiscuous mode on Windows.
  * Added support for MTU on Windows.

* **Added scalar version of the LPM library.**

  * Added scalar implementation of ``rte_lpm_lookupx4``. This is a fall-back
    implementation for platforms that don't support vector operations.


Removed Items
-------------

.. This section should contain removed items in this release. Sample format:

   * Add a short 1-2 sentence description of the removed item
     in the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================


API Changes
-----------

.. This section should contain API changes. Sample format:

   * sample: Add a short 1-2 sentence description of the API change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================


ABI Changes
-----------

.. This section should contain ABI changes. Sample format:

   * sample: Add a short 1-2 sentence description of the ABI change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* No ABI change that would break compatibility with 21.11.


Known Issues
------------

.. This section should contain new known issues in this release. Sample format:

   * **Add title in present tense with full stop.**

     Add a short 1-2 sentence description of the known issue
     in the present tense. Add information on any known workarounds.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================


Tested Platforms
----------------

.. This section should contain a list of platforms that were tested
   with this release.

   The format is:

   * <vendor> platform with <vendor> <type of devices> combinations

     * List of CPU
     * List of OS
     * List of devices
     * Other relevant details...

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

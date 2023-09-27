.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2023 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 23.11
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_23_11.html

* Build Requirements: From DPDK 23.11 onwards,
  building DPDK will require a C compiler which supports the C11 standard,
  including support for C11 standard atomics.

  More specifically, the requirements will be:

  * Support for flag "-std=c11" (or similar)
  * __STDC_NO_ATOMICS__ is *not defined* when using c11 flag

  Please note:

  * C11, including standard atomics, is supported from GCC version 5 onwards,
    and is the default language version in that release
    (Ref: https://gcc.gnu.org/gcc-5/changes.html)
  * C11 is the default compilation mode in Clang from version 3.6,
    which also added support for standard atomics
    (Ref: https://releases.llvm.org/3.6.0/tools/clang/docs/ReleaseNotes.html)

New Features
------------

   * **Added support for models with multiple I/O in mldev library.**

     Added support in mldev library for models with multiple inputs and outputs.

   * **Added support for Marvell TVM models in ML CNXK driver.**

     Added support models compiled using TVM framework in ML CNXK driver.


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

* build: Enabling deprecated libraries is now done using the new
  ``enable_deprecated_libraries`` build option.

* build: Optional libraries can now be selected with the new ``enable_libs``
  build option similarly to the existing ``enable_drivers`` build option.


Removed Items
-------------

.. This section should contain removed items in this release. Sample format:

   * Add a short 1-2 sentence description of the removed item
     in the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* eal: Removed deprecated ``RTE_FUNC_PTR_OR_*`` macros.

* flow_classify: Removed flow classification library and examples.

* kni: Removed the Kernel Network Interface (KNI) library and driver.

* mldev: Removed APIs ``rte_ml_io_input_size_get`` and ``rte_ml_io_output_size_get``.


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

* eal: The thread API has changed.
  The function ``rte_thread_create_control()`` does not take attributes anymore.
  The whole thread API was promoted to stable level,
  except ``rte_thread_setname()`` and ``rte_ctrl_thread_create()`` which are
  replaced with ``rte_thread_set_name()`` and ``rte_thread_create_control()``.

* mldev: Updated mldev API to support models with multiple inputs and outputs.
  Updated the structure ``rte_ml_model_info`` to support input and output with
  arbitrary shapes. Introduced support for ``rte_ml_io_layout``. Two layout types
  split and packed are supported by the specification, which enables higher
  control in handling models with multiple inputs and outputs. Updated ``rte_ml_op``,
  ``rte_ml_io_quantize`` and ``rte_ml_io_dequantize`` to support an array of
  ``rte_ml_buff_seg`` for inputs and outputs and removed use of batches argument.


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

.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2025 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 25.07
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_25_07.html


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

* **Added support for string and boolean types to the "argparse" library.**

  The "argparse" library now supports parsing of string and boolean types.
  String values are simply saved as-is,
  while the boolean support allows for values "true", "false", "1" or "0".

Removed Items
-------------

.. This section should contain removed items in this release. Sample format:

   * Add a short 1-2 sentence description of the removed item
     in the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* eal: Removed the ``rte_function_versioning.h`` header from the exported headers.


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

* argparse: The ``rte_argparse_arg`` structure used for defining arguments has been updated.
    See next section, :ref:`ABI-Changes` for details.

.. _ABI-Changes:

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

* No ABI change that would break compatibility with 24.11.

* argparse: The experimental "argparse" library has had the following updates:
   * The main parsing function, ``rte_argparse_parse()``,
     now returns the number of arguments parsed on success, rather than zero.
     It still returns a negative value on error.
   * When parsing a list of arguments,
     ``rte_argparse_parse()`` stops processing arguments when a ``--`` argument is encountered.
     This behaviour mirrors the behaviour of the ``getopt()`` function,
     as well as the behaviour of ``rte_eal_init()`` function.
   * The ``rte_argparse_arg`` structure used for defining arguments has been updated
     to separate out into separate fields the options for:

     #. Whether the argument is required or optional.
     #. What the type of the argument is (in case of saving the parameters automatically).
     #. Any other flags - of which there is only one, ``RTE_ARGPARSE_FLAG_SUPPORT_MULTI``, at this time.

   * With the splitting of the flags into separate enums for categories,
     the names of the flags have been changed to better reflect their purpose.
     The flags/enum values are:

     * For the ``value_required`` field:

        * ``RTE_ARGPARSE_VALUE_NONE``
        * ``RTE_ARGPARSE_VALUE_REQUIRED``
        * ``RTE_ARGPARSE_VALUE_OPTIONAL``

     * For the ``value_type`` field:

        * ``RTE_ARGPARSE_VALUE_TYPE_NONE`` (No argument value type is specified, callback is to be used for processing.)
        * ``RTE_ARGPARSE_VALUE_TYPE_INT``
        * ``RTE_ARGPARSE_VALUE_TYPE_U8``
        * ``RTE_ARGPARSE_VALUE_TYPE_U16``
        * ``RTE_ARGPARSE_VALUE_TYPE_U32``
        * ``RTE_ARGPARSE_VALUE_TYPE_U64``
        * ``RTE_ARGPARSE_VALUE_TYPE_STR``
        * ``RTE_ARGPARSE_VALUE_TYPE_BOOL``

     * Other flags:

        * ``RTE_ARGPARSE_FLAG_SUPPORT_MULTI`` (Allows the argument to be specified multiple times.)


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

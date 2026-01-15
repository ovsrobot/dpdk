..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Intel Corporation

dpdk-telemetry-watcher Application
===================================

The ``dpdk-telemetry-watcher`` tool is a Data Plane Development Kit (DPDK) utility
that provides continuous monitoring of DPDK telemetry statistics on the command line.
It wraps the ``dpdk-telemetry.py`` script to provide real-time statistics display capabilities.


Running the Application
-----------------------

The tool has a number of command line options:

.. code-block:: console

   dpdk-telemetry-watcher.py [options] stat1 stat2 ...


Options
-------

.. program:: dpdk-telemetry-watcher.py

.. option:: -h, --help

   Display usage information and quit

.. option:: -f FILE_PREFIX, --file-prefix FILE_PREFIX

   Provide file-prefix for DPDK runtime directory.
   Passed to ``dpdk-telemetry.py`` to identify the target DPDK application.
   Default is ``rte``.

.. option:: -i INSTANCE, --instance INSTANCE

   Provide instance number for DPDK application when multiple applications are running with the same file-prefix.
   Passed to ``dpdk-telemetry.py`` to identify the target DPDK application instance.
   Default is ``0``.

.. option:: -l, --list

   List all possible file-prefixes and exit.
   This is useful to discover which DPDK applications are currently running.

Dependencies
------------

The tool requires:

* Python 3
* The ``dpdk-telemetry.py`` script must be available in the same directory
  or in the system PATH
* A running DPDK application with telemetry enabled

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

.. _installing_prebuilt_packages:

Installing Pre-built Packages
=============================

Pre-built packages provide a convenient way to install DPDK without the need to compile
the source code manually. These packages are created and maintained by the DPDK
community or OS vendors and are available for various operating systems and
distributions.

Available Distributions
-----------------------

Linux
^^^^^

Pre-built DPDK packages are available for several popular Linux distributions,
including but not limited to:

Alpine

.. code-block:: bash

   sudo apk add dpdk

Debian and Ubuntu and derivatives

.. code-block:: bash

   sudo apt-get install dpdk

Fedora and RedHat Enterprise Linux RHEL

.. code-block:: bash

   sudo dnf install dpdk

openSUSE

.. code-block:: bash

   sudo zypper install dpdk

FreeBSD
^^^^^^^

To install DPDK on FreeBSD, use the following command:

.. code-block:: bash

   sudo pkg install dpdk
..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

.. _building_from_sources:

Building and Installing DPDK from Sources
=========================================

This chapter provides a comprehensive guide for building DPDK from sources on both
Linux and FreeBSD platforms. It covers the necessary steps, prerequisites, 
and considerations for different architectures and compilers.

Required Tools
--------------

To build DPDK, you'll need the following tools:

- A C compiler like ``gcc`` (version 5+) or ``clang`` (version 3.6+)
- ``pkg-config`` or ``pkgconf``
- Python 3.6 or later
- ``meson`` (version 0.53.2+) and ``ninja``
- ``pyelftools`` (version 0.22+)

Here's how to install them:

Linux
^^^^^

Alpine

.. code-block:: bash

   sudo apk add alpine-sdk bsd-compat-headers
   pip install meson ninja

Debian and Ubuntu and derivatives

.. code-block:: bash

   sudo apt install build-essential
   pip install meson ninja

Fedora and RedHat Enterprise Linux RHEL

.. code-block:: bash

   sudo dnf groupinstall "Development Tools"
   pip install meson ninja

openSUSE

.. code-block:: bash

   sudo zypper install -t pattern devel_basis python3-pyelftools
   pip install meson ninja

FreeBSD
^^^^^^^

FreeBSD (as root)

.. code-block:: bash

   pkg install meson pkgconf py38-pyelftools

Note: If you're using FreeBSD, you'll also need kernel sources. Make sure they're included during the FreeBSD installation.

Getting the DPDK Source
-----------------------

Download the DPDK source code from the official repository 
``https://fast.dpdk.org/rel/``.

Use ``wget`` to grab the DPDK version::

        wget https://fast.dpdk.org/rel/dpdk-<version>.tar.xz

Extract the downloaded archive:

.. code-block:: bash

   tar -xvf dpdk-<version>.tar.gz

Navigate to the DPDK directory:

.. code-block:: bash

   cd dpdk-<version>

Building DPDK
-------------

Configure the build based on your needs, hardware, and environment. 
This might include setting specific flags or options. For example: “meson setup -Dbuildtype=debugoptimized build”. Then compile using “ninja” and install using “meson install”.

.. code-block:: bash

   ninja -C build
   cd build
   sudo ninja install
   ldconfig

For detailed information on Meson build configuration options specific to DPDK, see :ref:`DPDK Meson Build Configuration Options <dpdk_meson_build_options>`.

Cross-Compilation Instructions for Different Architectures
----------------------------------------------------------

For instructions on building DPDK for ARM64, LoongArch, and RISC-V, refer to :ref:`cross_compile_dpdk`.

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2025 Intel Corporation.

.. _dpdk_meson_build_options:

DPDK Meson Build Configuration Options
======================================

DPDK provides a number of build configuration options that can be adjusted using the Meson build system. These options can be listed by running ``meson configure`` inside a configured build
folder.

Changing the Build Type
-----------------------

To change the build type from the default "release" to a regular "debug" build,
you can either:

- Pass ``-Dbuildtype=debug`` or ``--buildtype=debug`` to meson when configuring the build folder initially.
- Run ``meson configure -Dbuildtype=debug`` inside the build folder after the initial meson run.

Platform Options
----------------

The "platform" option specifies a set of configuration parameters that will be used. 
The valid values are:

- ``-Dplatform=native`` will tailor the configuration to the build machine.
- ``-Dplatform=generic`` will use configuration that works on all machines of the same architecture as the build machine.
- ``-Dplatform=<SoC>`` will use configuration optimized for a particular SoC.

Consult the "socs" dictionary in ``config/arm/meson.build`` to see which SoCs are supported.

Overriding Platform Parameters
------------------------------

The values determined by the platform parameter may be overwritten. For example,
to set the ``max_lcores`` value to 256, you can either:

- Pass ``-Dmax_lcores=256`` to meson when configuring the build folder initially.
- Run ``meson configure -Dmax_lcores=256`` inside the build folder after the initial meson run.

Building Sample Applications
----------------------------

Some of the DPDK sample applications in the examples directory can be automatically built as
part of a meson build. To do so, pass a comma-separated list of the examples to build to the
``-Dexamples`` meson option as below::

    meson setup -Dexamples=l2fwd,l3fwd build

There is also a special value "all" to request that all example applications whose dependencies
are met on the current system are built. When ``-Dexamples=all`` is set as a meson option,
meson will check each example application to see if it can be built, and add all which can be
built to the list of tasks in the ninja build configuration file.

For a complete list of options, run ``meson configure`` inside your configured build
folder.
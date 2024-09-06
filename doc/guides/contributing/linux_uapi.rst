.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2024 Red Hat, Inc.

Linux uAPI header files
=======================

Rationale
---------

The system a DPDK library or driver is built on is not necessarily running the
same Kernel version than the system that will run it.
Importing Linux Kernel uAPI headers enable to build features that are not
supported yet by the build system.

For example, the build system runs upstream Kernel v5.19 and we would like to
build a VDUSE application that will use VDUSE_IOTLB_GET_INFO ioctl() introduced
in Linux Kernel v6.0.

`Linux Kernel licence exception regarding syscalls
<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/LICENSES/exceptions/Linux-syscall-note>`_
enable importing unmodified Linux Kernel uAPI header files.

Importing or updating an uAPI header file
-----------------------------------------

In order to ensure the imported uAPI headers are both unmodified and from a
released version of the linux Kernel, a helper script is made available and
MUST be used.
Below is an example to import ``linux/vduse.h`` file from Linux ``v6.10``:

.. code-block:: console

   ./devtools/import-linux-uapi.sh linux/vduse.h v6.10

Once imported, the header files should be committed without any other change,
and the commit message MUST specify the imported version using
``uAPI Version:`` tag and title MUST be prefixed with uapi keyword.
For example::

  uapi: import VDUSE header file

  This patch imports VDUSE uAPI header file for inclusion
  into the Vhost library.

  uAPI Version: v6.10

  Signed-off-by: Alex Smith <alex.smith@example.com>

Updating an already imported header to a newer released version should only
be done on a need basis.
The commit message should reflect why updating the header is necessary.

Once committed, user can check headers and commit message are valid by using
the Linux uAPI checker tool:

.. code-block:: console

   ./devtools/check-linux-uapi.sh

Header inclusion into library or driver
---------------------------------------

The library or driver willing to make use of imported uAPI headers needs to
explicitly add uAPI headers path to the ``includes`` var in its ``meson.build``
file:

.. code-block:: python

   includes += linux_uapi_inc

Then, it can be included with ``uapi/`` prefix in C files.
For example to include VDUSE uAPI:

.. code-block:: c

   #include <uapi/linux/vduse.h>


..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2018 The DPDK contributors

Design
======

Environment or Architecture-specific Sources
--------------------------------------------

In DPDK and DPDK applications, some code is specific to an architecture (i686, x86_64) or to an executive environment (freebsd or linux) and so on.
As far as is possible, all such instances of architecture or env-specific code should be provided via standard APIs in the EAL.

By convention, a file is common if it is not located in a directory indicating that it is specific.
For instance, a file located in a subdir of "x86_64" directory is specific to this architecture.
A file located in a subdir of "linux" is specific to this execution environment.

.. note::

   Code in DPDK libraries and applications should be generic.
   The correct location for architecture or executive environment specific code is in the EAL.

When absolutely necessary, there are several ways to handle specific code:

* Use a ``#ifdef`` with a build definition macro in the C code.
  This can be done when the differences are small and they can be embedded in the same C file:

  .. code-block:: c

     #ifdef RTE_ARCH_I686
     toto();
     #else
     titi();
     #endif


Per Architecture Sources
~~~~~~~~~~~~~~~~~~~~~~~~

The following macro options can be used:

* ``RTE_ARCH`` is a string that contains the name of the architecture.
* ``RTE_ARCH_I686``, ``RTE_ARCH_X86_64``, ``RTE_ARCH_X86_64_32`` or ``RTE_ARCH_PPC_64`` are defined only if we are building for those architectures.

Per Execution Environment Sources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following macro options can be used:

* ``RTE_EXEC_ENV`` is a string that contains the name of the executive environment.
* ``RTE_EXEC_ENV_FREEBSD`` or ``RTE_EXEC_ENV_LINUX`` are defined only if we are building for this execution environment.

Mbuf features
-------------

The ``rte_mbuf`` structure must be kept small (128 bytes).

In order to add new features without wasting buffer space for unused features,
some fields and flags can be registered dynamically in a shared area.
The "dynamic" mbuf area is the default choice for the new features.

The "dynamic" area is eating the remaining space in mbuf,
and some existing "static" fields may need to become "dynamic".

Adding a new static field or flag must be an exception matching many criteria
like (non exhaustive): wide usage, performance, size.


PF and VF Considerations
------------------------

The primary goal of DPDK is to provide a userspace dataplane. Managing VFs from
a PF driver is a control plane feature and developers should generally rely on
the Linux Kernel for that.

Developers should work with the Linux Kernel community to get the required
functionality upstream. PF functionality should only be added to DPDK for
testing and prototyping purposes while the kernel work is ongoing. It should
also be marked with an "EXPERIMENTAL" tag. If the functionality isn't
upstreamable then a case can be made to maintain the PF functionality in DPDK
without the EXPERIMENTAL tag.

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2024 The DPDK contributors

Glossary of Terms
==================

EAL
  Environment Abstraction Layer. Originally used to isolate differences between running
  on bare metal versus running as a userspace process. Bare metal is no longer supported.
  Now used to provide abstraction across operating system envrionments.

Process
  An operating system process consisting of one or more threads.

Thread
  The unit of execution in the operating system. A thread maybe bound to a specific physical
  core on the CPU or migrate among core's via the operating system scheduler.

Lcore
  A logical core. In DPDK lcore's are usually bound to a isolated physical CPU core.

Isolated core
  A core is isolated if it is reserved by the operating system and not used for normal
  (muggle) processes. The operating system scheduler will not migrate a thread onto an
  isolated core; the only way a thread will run on an isolated core is by requesting
  affinity to that core.

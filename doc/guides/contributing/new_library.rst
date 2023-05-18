.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2023 Marvell.

Process for new library approval in principle
=============================================

Rationale
---------

Adding a new library to DPDK with proper RFC and then full patch-sets is significant work.
In order to save effort, developers will get an early approval in principle, or early feedback in
case the library is not suitable for various reasons.

Process
-------

#. When a contributor would like to add a new library to DPDK code base, the contributor must send
   the following items to DPDK mailing list for technical board approval-in-principle.

   * Purpose of the library.
   * Scope of work: outline the various additional tasks planned for this library, such as
     developing new test applications, adding new drivers, and updating existing applications.
   * Expected usage models of the library.
   * Any licensing constraints.
   * Justification for adding to DPDK.
   * Any other implementations of the same functionality in other libraries/projects and how this
     version differs.
   * Public API specification header file as RFC.

       * Optional and good to have.
       * Technical board may additionally request this collateral if needed to get more clarity
         on scope and purpose.
   * Any new library dependencies to DPDK.

#. Technical board to schedule discussion on this in upcoming technical board meeting along with
   author. Based on the technical board schedule and/or author availability, technical board may
   need a maximum of **five** technical board meeting slots.

#. Based on mailing list and technical board meeting discussions, technical board to vote and share
   the decision in the mailing list. The decision outcome can be any of the following.

   * Approved in principal
   * Not approved
   * Further information needed

#. Once technical board approves the library in principle, it is safe to start working on the
   implementation. However, the patches will need to meet the usual quality criteria in order to be
   effectively accepted.

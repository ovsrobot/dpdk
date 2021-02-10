..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2018 The DPDK contributors

.. _testing_guidelines:

DPDK Testing Guidelines
=======================

This document outlines the guidelines for running and adding new
tests to the in-tree DPDK test suites.

The DPDK test suite model is loosely based on the xunit model, where
tests are grouped into test suites, and suites are run by runners.
For a basic overview, see the basic Wikipedia article on xunit:
`xUnit - Wikipedia <https://en.wikipedia.org/wiki/XUnit>`_.


Running a test
--------------

DPDK tests are run via the main test runner, the `dpdk-test` app.
The `dpdk-test` app is a command-line interface that facilitates
running various tests or test suites.

There are two modes of operation.  The first mode is as an interactive
command shell that allows launching specific test suites.  This is
the default operating mode of `dpdk-test` and can be done by::

  $ ./build/app/test/dpdk-test --dpdk-options-here
  EAL: Detected 4 lcore(s)
  EAL: Detected 1 NUMA nodes
  EAL: Static memory layout is selected, amount of reserved memory can be adjusted with -m or --socket-mem
  EAL: Multi-process socket /run/user/26934/dpdk/rte/mp_socket
  EAL: Selected IOVA mode 'VA'
  EAL: Probing VFIO support...
  EAL: PCI device 0000:00:1f.6 on NUMA socket -1
  EAL:   Invalid NUMA socket, default to 0
  EAL:   probe driver: 8086:15d7 net_e1000_em
  APP: HPET is not enabled, using TSC as default timer
  RTE>>

At the prompt, simply type the name of the test suite you wish to run
and it will execute.

The second form is useful for a scripting environment, and is used by
the DPDK meson build system.  This mode is invoked by assigning a
specific test suite name to the environment variable `DPDK_TEST`
before invoking the `dpdk-test` command, such as::

  $ DPDK_TEST=version_autotest ./build/app/test/dpdk-test --dpdk-options-here
  EAL: Detected 4 lcore(s)
  EAL: Detected 1 NUMA nodes
  EAL: Static memory layout is selected, amount of reserved memory can be adjusted with -m or --socket-mem
  EAL: Multi-process socket /run/user/26934/dpdk/rte/mp_socket
  EAL: Selected IOVA mode 'VA'
  EAL: Probing VFIO support...
  EAL: PCI device 0000:00:1f.6 on NUMA socket -1
  EAL:   Invalid NUMA socket, default to 0
  EAL:   probe driver: 8086:15d7 net_e1000_em
  APP: HPET is not enabled, using TSC as default timer
  RTE>>version_autotest
  Version string: 'DPDK 20.02.0-rc0'
  Test OK
  RTE>>$

The above shows running a specific test case.  On success, the return
code will be '0', otherwise it will be set to some error value (such
as '255').


Running all tests
-----------------

In order to allow developers to quickly execute all the standard
internal tests without needing to remember or look up each test suite
name, the build system includes a standard way of executing the
default test suites.  After building via `ninja`, the ``meson test``
command will execute the standard tests and report errors.

There are four groups of default test suites.  The first group is
the **fast** test suite, which is the largest group of test cases.
These are the bulk of the unit tests to validate functional blocks.
The second group is the **perf** tests.  These test suites can take
longer to run and do performance evaluations.  The third group is
the **driver** test suite, which is mostly for special hardware
related testing (such as `cryptodev`).  The last group are the
**debug** tests.  These mostly are used to dump system information.

The suites can be selected by adding the ``--suite`` option to the
``meson test`` command.  Ex: ``meson test --suite fast-tests``::

  $ meson test -C build --suite fast-tests
  ninja: Entering directory `/home/aconole/git/dpdk/build'
  [2543/2543] Linking target app/test/dpdk-test.
  1/60 DPDK:fast-tests / acl_autotest          OK       3.17 s
  2/60 DPDK:fast-tests / bitops_autotest       OK       0.22 s
  3/60 DPDK:fast-tests / byteorder_autotest    OK       0.22 s
  4/60 DPDK:fast-tests / cmdline_autotest      OK       0.28 s
  5/60 DPDK:fast-tests / common_autotest       OK       0.57 s
  6/60 DPDK:fast-tests / cpuflags_autotest     OK       0.27 s
  ...


Adding test suites
------------------

To add a test suite to the DPDK test application, create a new test
file for that suite (ex: see *app/test/test_version.c* for the
``version_autotest`` test suite).  There are two important functions
for interacting with the test harness:

  1. REGISTER_TEST_COMMAND(command_name, function_to_execute)
     Registers a test command with the name `command_name` and which
     runs the function `function_to_execute` when `command_name` is
     invoked.

  2. unit_test_suite_runner(struct unit_test_suite \*)
     Returns a runner for a full test suite object, which contains
     a test suite name, setup, tear down, and vector of unit test
     cases.

Each test suite has a setup and tear down function that runs at the
beginning and end of the test suite execution.  Each unit test has
a similar function for test case setup and tear down.

Test cases are added to the `.unit_test_cases` element of the unit
test suite structure.  Ex:

.. code-block:: c
   :linenos:

   #include <time.h>

   #include <rte_common.h>
   #include <rte_cycles.h>
   #include <rte_hexdump.h>
   #include <rte_random.h>

   #include "test.h"

   static int testsuite_setup(void) { return TEST_SUCCESS; }
   static void testsuite_teardown(void) { }

   static int ut_setup(void) { return TEST_SUCCESS; }
   static void ut_teardown(void) { }

   static int test_case_first(void) { return TEST_SUCCESS; }

   static struct unit_test_suite example_testsuite = {
          .suite_name = "EXAMPLE TEST SUITE",
          .setup = testsuite_setup,
          .teardown = testsuite_teardown,
          .unit_test_cases = {
               TEST_CASE_ST(ut_setup, ut_teardown, test_case_first),

               TEST_CASES_END(), /**< NULL terminate unit test array */
          },
   };

   static int example_tests()
   {
       return unit_test_suite_runner(&example_testsuite);
   }

   REGISTER_TEST_COMMAND(example_autotest, example_tests);

The above code block is a small example that can be used to create a
complete test suite with test case.


Designing a test
----------------

Test cases have multiple ways of indicating an error has occurred,
in order to reflect failure state back to the runner.  Using the
various methods of indicating errors can assist in not only validating
the requisite functionality is working, but also to help debug when
a change in environment or code has caused things to go wrong.

The first way to indicate a generic error is by returning a test
result failure, using the *TEST_FAILED* error code.  This is the most
basic way of indicating that an error has occurred in a test routine.
It isn't very informative to the user, so it should really be used in
cases where the test has catastrophically failed.

The preferred method of indicating an error is via the
`RTE_TEST_ASSERT` family of macros, which will immediately return
*TEST_FAILED* error condition, but will also log details about the
failure.  The basic form is:

.. code-block:: c

   RTE_TEST_ASSERT(cond, msg, ...)

In the above macro, *cond* is the condition to evaluate to **true**.
Any generic condition can go here.  The *msg* parameter will be a
message to display if *cond* evaluates to **false**.  Some specialized
macros already exist.  See `lib/librte_eal/include/rte_test.h` for
a list of defined test assertions.

Sometimes it is important to indicate that a test needs to be
skipped, either because the environment isn't able to support running
the test, or because some requisite functionality isn't available.  The
test suite supports returning a result of `TEST_SKIPPED` during test
case setup, or during test case execution to indicate that the
preconditions of the test aren't available.  Ex::

  $ meson test -C build --suite fast-tests
  ninja: Entering directory `/home/aconole/git/dpdk/build
  [2543/2543] Linking target app/test/dpdk-test.
  1/60 DPDK:fast-tests / acl_autotest          OK       3.17 s
  2/60 DPDK:fast-tests / bitops_autotest       OK       0.22 s
  3/60 DPDK:fast-tests / byteorder_autotest    OK       0.22 s
  ...
  46/60 DPDK:fast-tests / ipsec_autotest       SKIP     0.22 s
  ...


Checking code coverage
----------------------
The meson build system supports generating a code coverage report
via the `-Db_coverage=true` option, in conjunction with a package
like **lcov**, to generate an HTML code coverage report.  Example::

  $ meson covered -Db_coverage=true
  $ meson test -C covered --suite fast-tests
  $ ninja coverage-html -C covered

The above will generate an html report in the
`covered/meson-logs/coveragereport/` directory that can be explored
for detailed code covered information.  This can be used to assist
in test development.


Adding a suite to the default
-----------------------------

Adding to one of the default tests involves editing the appropriate
meson build file `app/test/meson.build` and adding the command to
the correct test suite class.  Once added, the new test suite will
be run as part of the appropriate class (fast, perf, driver, etc.).

Some of these default test suites are run during continuous integration
tests, making regression checking automatic for new patches submitted
to the project.

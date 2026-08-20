..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2024 Intel Corporation

dpdk-test-mempool-perf Application
====================================

The ``dpdk-test-mempool-perf`` tool measures the alloc/free throughput of DPDK mempool implementations.
Worker threads repeatedly allocate and free objects in configurable burst sizes following a randomised pattern,
exercising the pool under varying levels of occupancy.
Any mempool driver registered with the DPDK mempool ops table can be tested.
Pool elements are sized to match ``rte_pktmbuf_pool_create()`` with default data room.


Running the Application
-----------------------

.. code-block:: console

   dpdk-test-mempool-perf [EAL options] -- [application options]

See the *DPDK Getting Started Guide* for a description of EAL options.

The application operates in two modes depending on whether application-specific options are supplied after ``--``:

interactive
   Invoked with no options or only EAL options (nothing after ``--``, or ``--`` omitted).
   The tool prompts for each parameter in turn; pressing Enter accepts the displayed default.
   After configuration, a command line is printed that reproduces the same settings non-interactively.

non-interactive
   All configuration is supplied on the command line.
   ``--mempool-type`` is required; all other parameters are optional.


Application Options
~~~~~~~~~~~~~~~~~~~

``--mempool-type <name>`` / ``-M <name>``
   Name of the mempool driver to test.
   Required in non-interactive mode.
   To list the drivers available on the current system,
   run the application in interactive mode; the available names are printed at startup.
   Common names include ``ring_mp_mc`` and ``stack``.

``--nb-bufs <n>`` / ``-n <n>``
   Total number of objects in the pool.
   Default: 1024 multiplied by the total lcore count.
   The pool must be large enough that it is not exhausted when all workers hold their maximum simultaneous in-flight objects,
   which is ``(rand-factor / 2) * burst-size`` objects per worker.

``--cache-size <n>`` / ``-c <n>``
   Per-lcore object cache size, in objects.
   Default: 512.
   A larger cache reduces contention on the central pool at the cost of higher per-core memory usage.
   Set to 0 to disable the per-lcore cache and measure underlying data structure throughput.

``--nb-threads <n>`` / ``-t <n>``
   Number of worker lcores to launch.
   Default: all available worker lcores (total lcores minus the main lcore).

``--rand-factor <n>`` / ``-r <n>``
   Controls the width of the randomised allocation pattern.
   Default: 8.
   The value is rounded down to the nearest even number (minimum 2).
   Half of the resulting slots perform bulk allocations and half perform bulk frees;
   the order is reshuffled randomly at regular intervals.
   A larger value means workers hold more in-flight objects on average
   and vary their occupancy over a wider range,
   exercising the pool under a more realistic mix of pressure levels.

``--burst-size <n>`` / ``-b <n>``
   Number of objects per alloc or free call.
   Default: 32.
   Higher burst sizes amortise per-call overhead
   and can reveal differences between pool implementations that batch internal operations.

``--access-on-alloc`` / ``-A``
   Touch every cache line of each allocated object immediately after allocation (default behaviour).
   This models workloads that initialise or write packet data after allocation,
   ensuring that the measured throughput reflects both pool overhead and memory bandwidth pressure.

``--no-access-on-alloc`` / ``-N``
   Skip the memory-access step after allocation.
   Use this to isolate pure pool ring or lock overhead from memory bandwidth effects.

``--summary`` / ``-s``
   Print only the aggregate total in the results, suppressing the per-worker-lcore breakdown.
   Useful when scripting comparisons across pool types or configurations.


Interactive Mode
----------------

Running the tool with only EAL options enters interactive mode::

   dpdk-test-mempool-perf [EAL options]

The application lists all available mempool drivers then prompts for each parameter.
Pressing Enter at any prompt keeps the displayed default value.
``--mempool-type`` is the only mandatory entry.

After configuration the tool prints an equivalent non-interactive command::

   Reproduce using parameters: -M ring_mp_mc -n 4096 -c 512 -t 3 -r 8 -b 32 -A

Append this output after the EAL options on subsequent runs to reproduce the exact same configuration without prompting.


Test Output
-----------

Each run lasts a fixed 5 seconds.
On completion, a results table is printed showing per-worker throughput and an aggregate total:

.. code-block:: console

   lcore    get (Mops/s)  fail/burst  put (Mops/s)
   ------   ------------  ----------  ------------
   1              23.871           0       23.871
   2              24.012           0       24.012
   Total          47.883           0

lcore
   Worker lcore ID.

get (Mops/s)
   Successful allocation throughput in millions of operations per second.

fail/burst
   Number of allocation calls that failed because the pool had insufficient free objects.
   A non-zero value indicates ``--nb-bufs`` is too small for the configured workload.

put (Mops/s)
   Free throughput in millions of operations per second.
   Under a balanced workload this matches the get rate.

The ``Total`` row shows aggregate get throughput and failure count across all workers;
it does not include a put rate.
With ``--summary``, only the ``Total`` row is printed.


Examples
--------

Run interactively, letting the tool prompt for all settings:

.. code-block:: console

   dpdk-test-mempool-perf -l 0-3

Run non-interactively with four worker threads:

.. code-block:: console

   dpdk-test-mempool-perf -l 0-4 -- -M ring_mp_mc -t 4 -n 20480

Disable the per-lcore cache to measure raw ring throughput:

.. code-block:: console

   dpdk-test-mempool-perf -l 0-1 -- -M ring_mp_mc -c 0

Measure without memory access to isolate pool overhead from bandwidth:

.. code-block:: console

   dpdk-test-mempool-perf -l 0-4 -- -M ring_mp_mc -N

Print only the aggregate total, suitable for scripted comparisons:

.. code-block:: console

   dpdk-test-mempool-perf -l 0-4 -- -M ring_mp_mc -s

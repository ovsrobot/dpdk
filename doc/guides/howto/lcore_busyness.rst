..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2022 Intel Corporation.

Lcore Poll Busyness Telemetry
========================

The lcore poll busyness telemetry provides a built-in, generic method of gathering
lcore utilization metrics for running applications. These metrics are exposed
via a new telemetry endpoint.

Since most DPDK APIs poll for packets, the poll busyness is calculated based on
APIs receiving packets. Empty polls are considered as idle, while non-empty polls
are considered busy. Using the amount of cycles spent processing empty polls, the
busyness can be calculated and recorded.

Application Specified Busyness
------------------------------

Improved accuracy of the reported busyness may need more contextual awareness
from the application. For example, a pipelined application may make a number of
calls to rx_burst before processing packets. Any processing done on this 'bulk'
would need to be marked as "busy" cycles, not just the last received burst. This
type of awareness is only available within the application.

Applications can be modified to incorporate the extra contextual awareness in
order to improve the reported busyness by marking areas of code as "busy" or
"idle" appropriately. This can be done by inserting the timestamping macro::

    RTE_LCORE_TELEMETRY_TIMESTAMP(0)    /* to mark section as idle */
    RTE_LCORE_TELEMETRY_TIMESTAMP(32)   /* where 32 is nb_pkts to mark section as busy (non-zero is busy) */

All cycles since the last state change will be counted towards the current state's
counter.

Consuming the Telemetry
-----------------------

The telemetry gathered for lcore poll busyness can be read from the `telemetry.py`
script via the new `/eal/lcore/poll_busyness` endpoint::

    $ ./usertools/dpdk-telemetry.py
    --> /eal/lcore/poll_busyness
    {"/eal/lcore/poll_busyness": {"12": -1, "13": 85, "14": 84}}

* Cores not collecting poll busyness will report "-1". E.g. control cores or inactive cores.
* All enabled cores will report their poll busyness in the range 0-100.

Disabling Lcore Poll Busyness Telemetry
----------------------------------

Some applications may not want lcore poll busyness telemetry to be tracked, for
example performance critical applications or applications that are already being
monitored by other tools gathering similar or more application specific information.

For those applications, there are two ways in which this telemetry can be disabled.

At compile time
^^^^^^^^^^^^^^^

Support can be disabled at compile time via the meson option. It is enabled by
default.::

    $ meson configure -Denable_lcore_poll_busyness=false

At run time
^^^^^^^^^^^

Support can also be disabled during runtime. This comes at the cost of an
additional branch, however no additional function calls are performed.

To disable support at runtime, a call can be made to the
`/eal/lcore/poll_busyness_disable` endpoint::

    $ ./usertools/dpdk-telemetry.py
    --> /eal/lcore/poll_busyness_disable
    {"/eal/lcore/poll_busyness_disable": {"poll_busyness_enabled": 0}}

It can be re-enabled at run time with the `/eal/lcore/poll_busyness_enable`
endpoint.

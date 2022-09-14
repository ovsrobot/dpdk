..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2022 Intel Corporation.

Lcore Poll Busyness Telemetry
=============================

The lcore poll busyness telemetry provides a built-in, generic method of gathering
lcore utilization metrics for running applications. These metrics are exposed
via a new telemetry endpoint.

Since most DPDK APIs polling based, the poll busyness is calculated based on
APIs receiving 'work' (packets, completions, events, etc). Empty polls are
considered as idle, while non-empty polls are considered busy. Using the amount
of cycles spent processing empty polls, the busyness can be calculated and recorded.

Application Specified Busyness
------------------------------

Improved accuracy of the reported busyness may need more contextual awareness
from the application. For example, an application may make a number of calls to
rx_burst before processing packets. If the last burst was an "empty poll", then
the processing time of the packets would be falsely considered as "idle", since
the last burst was empty. The application should track if any of the polls
contained "work" to do and should mark the 'bulk' as "busy" cycles before
proceeding to the processesing. This type of awareness is only available within
the application.

Applications can be modified to incorporate the extra contextual awareness in
order to improve the reported busyness by marking areas of code as "busy" or
"idle" appropriately. This can be done by inserting the timestamping macro::

    RTE_LCORE_POLL_BUSYNESS_TIMESTAMP(0)    /* to mark section as idle */
    RTE_LCORE_POLL_BUSYNESS_TIMESTAMP(32)   /* where 32 is nb_pkts to mark section as busy (non-zero is busy) */

All cycles since the last state change (idle to busy, or vice versa) will be
counted towards the current state's counter.

Consuming the Telemetry
-----------------------

The telemetry gathered for lcore poll busyness can be read from the `telemetry.py`
script via the new `/eal/lcore/poll_busyness` endpoint::

    $ ./usertools/dpdk-telemetry.py
    --> /eal/lcore/poll_busyness
    {"/eal/lcore/poll_busyness": {"12": -1, "13": 85, "14": 84}}

* Cores not collecting poll busyness will report "-1". E.g. control cores or inactive cores.
* All enabled cores will report their poll busyness in the range 0-100.

Enabling and Disabling Lcore Poll Busyness Telemetry
----------------------------------------------------

By default, the lcore poll busyness telemetry is disabled at compile time. In
order to allow DPDK to gather this metric, the ``enable_lcore_poll_busyness``
meson option must be set to ``true``.

.. note::
    Enabling lcore poll busyness telemetry may impact performance due to the
    additional timestamping, potentially per poll depending on the application.
    This can be measured with the `lcore_poll_busyness_perf_autotest`.

At compile time
^^^^^^^^^^^^^^^

Support can be enabled/disabled at compile time via the meson option.
It is disabled by default.::

    $ meson configure -Denable_lcore_poll_busyness=true     #enable

    $ meson configure -Denable_lcore_poll_busyness=false    #disable

At run time
^^^^^^^^^^^

Support can also be enabled/disabled during runtime (if the meson option is
enabled at compile time). Disabling at runtime comes at the cost of an additional
branch, however no additional function calls are performed.

To enable/disable support at runtime, a call can be made to the appropriately
telemetry endpoint.

Disable::

    $ ./usertools/dpdk-telemetry.py
    --> /eal/lcore/poll_busyness_disable
    {"/eal/lcore/poll_busyness_disable": {"poll_busyness_enabled": 0}}

Enable::

    $ ./usertools/dpdk-telemetry.py
    --> /eal/lcore/poll_busyness_enable
    {"/eal/lcore/poll_busyness_enable": {"poll_busyness_enabled": 1}}

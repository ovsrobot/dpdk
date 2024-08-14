.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2024 The DPDK contributors


Upstreaming New DPDK Drivers Guide
==================================

The DPDK project continuously grows its ecosystem by adding support for new devices.
This document is designed to assist contributors in creating DPDK
drivers, also known as Poll Mode Drivers (PMD's).

By having public support for a device, we can ensure accessibility across various
operating systems and guarantee community maintenance in future releases.
If a new device is similar to a device already supported by an existing driver,
it is more efficient to update the existing driver.

Here are our best practice recommendations for creating a new driver.


Early Engagement with the Community
-----------------------------------

When creating a new driver, we highly recommend engaging with the DPDK
community early instead of waiting the work to mature.

These public discussions help align development of your driver with DPDK expectations.
You may submit a roadmap before the release to inform the community of
your plans. Additionally, sending a Request for Comments (RFC) early in
the release cycle, or even during the prior release, is advisable.

DPDK is mainly consumed via Long Term Support (LTS) releases.
It is common to target a new PMD to a LTS release. For this, it is
suggested to start upstreaming at least one release before a LTS release.


Progressive Work
----------------

To continually progress your work, we recommend planning for incremental
upstreaming across multiple patch series or releases.

It's important to prioritize quality of the driver over upstreaming
in a single release or single patch series.


Finalizing
----------

Once the driver has been upstreamed, the author has
a responsibility to the community to maintain it.

This includes the public test report. Authors must send a public
test report after the first upstreaming of the PMD. The same
public test procedure may be reproduced regularly per release.

After the PMD is upstreamed, the author should send a patch
to update the website with the name of the new PMD and supported devices
via the DPDK mailing list..

For more information about the role of maintainers, see :doc:`patches`.



Splitting into Patches
----------------------

We recommend that drivers are split into patches, so that each patch represents
a single feature. If the driver code is already developed, it may be challenging
to split. However, there are many benefits to doing so.

Splitting patches makes it easier to understand a feature and clarifies the
list of components/files that compose that specific feature.

It also enables the ability to track from the source code to the feature
it is enabled for and helps users to understand the reasoning and intention
of implementation. This kind of tracing is regularly required
for defect resolution and refactoring.

Another benefit of splitting the codebase per feature is that it highlights
unnecessary or irrelevant code, as any code not belonging to any specific
feature becomes obvious.

Git bisect is also more useful if patches are split per patch.

The split should focus on logical features
rather than file-based divisions.

Each patch in the series must compile without errors
and should maintain functionality.

Enable the build as early as possible within the series
to facilitate continuous integration and testing.
This approach ensures a clear and manageable development process.

We suggest splitting patches following this approach:

* Each patch should be organized logically as a new feature.
* Run test tools per patch (See :ref:`tool_list`:).
* Update relevant documentation and <driver>.ini file with each patch.


The following order in the patch series is as suggested below.

The first patch should have the driver's skeleton which should include:

* Maintainer's file update
* Driver documentation
* Document must have links to official product documentation web page
* The  new document should be added into the index (`doc/guides/index.rst`)
* Initial <drive>.ini file
* Release notes announcement for the new driver


The next patches should include basic device features.
The following is suggested sample list to include in these patches:

=======================   ========================
Net                       Crypto
=======================   ========================
Initialization            Initialization
Configure queues          Configure queues
Start queues              Start queues
Simple Rx / Tx            Simple Data Processing
Statistics                Statistics
Device info
Link interrupt
Burst mode info
Promisc all-multicast
RSS
=======================   ========================


Advanced features should be in the next group of patches.
The suggestions for these, listed below, are in no specific order:

=============================
Net
=============================
Advanced Rx / Tx
Scatter Support
Vector Support
TSO / LRO
Rx / Tx Descriptor Status
RX / Tx Queue Info
Flow Offload
Traffic Management/Metering
Extended statistics
Secondary Process Support
FreeBSD / Windows Support
Flow control
FEC
EEPROM access
Register Dump
Time Synchronization, PTP
Perf documentation
=============================


After all features are enabled, if there is remaining base code that
is not upstreamed, they can be upstreamed at the end of the patch series.
However, we recommend these patches are still split into logical groups.


Additional Suggestions
----------------------

* We recommend using DPDK macros instead of inventing new ones in the PMD.
* Do not include unused headers. Use the ./devtools/process-iwyu.py tool.
* Do not disable compiler warnings in the build file.
* Do not use #ifdef with driver-defined macros, instead prefer runtime configuration.
* Document device parameters in the driver guide.
* Make device operations struct 'const'.
* Use dynamic logging.
* Do not use DPDK version checks in the upstream code.
* Be sure to have SPDX license tags and copyright notice on each side.
  Use ./devtools/check-spdx-tag.sh
* Run the Coccinelle scripts ./devtools/cocci.sh which check for common cleanups such as
  useless null checks before calling free routines.

Dependencies
------------

At times, drivers may have dependencies to external software.
For driver dependencies, same DPDK rules for dependencies applies.
Dependencies should be publicly and freely available,
or this is a blocker for upstreaming the driver.


.. _tool_list:

Test Tools
----------

Build and check the driver's documentation. Make sure there are no
warnings and driver shows up in the relevant index page.

Be sure to run the following test tools per patch in a patch series:

* checkpatches.sh
* check-git-log.sh
* check-meson.py
* check-doc-vs-code.sh

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2024 The DPDK contributors

Integrating DPDK with IDEs
==========================

DPDK does not mandate nor recommend a specific IDE for development. However,
some developers may prefer to use an IDE for their development work. This guide
provides information on how to integrate DPDK with some popular IDEs.


Visual Studio Code
------------------

`Visual Studio Code <https://code.visualstudio.com/>` is a popular open-source
code editor with IDE features such as code completion, debugging, Git
integration, and more. It is available on most platforms.


Configuration
~~~~~~~~~~~~~

When configuring a new Meson build directory for DPDK, configuration for Visual
Studio Code will be generated automatically. It will include both a compilation
task, as well as debugging targets for any applications or examples enabled in
meson at configuration step. Generated configuration will be available under
`.vscode` directory in DPDK source tree. The configuration will be updated each
time the build directory is reconfigured with Meson.

Further information on configuring, building and installing DPDK is described in
:doc:`Linux Getting Started Guide <../linux_gsg/build_dpdk>`.

.. note::

    The configuration is generated based on the enabled applications and
    examples at the time of configuration. When new applications or examples are
    added to the configuration using the `meson configure` command (or through
    running `Configure` task), new configuration will be added, but existing
    configuration will never be amended or deleted, even if the application was
    removed from build.


Each generated file will refer to a few common variables defined under
`settings.json`. This is to allow easy reconfiguration of all generated launch
targets while also still allowing user to customize the configuration. Variables
contained within `settings.json` are as follows:

- `<build-dir-name>-builddir`: Path to the build directory (can be in-tree or
  out-of-tree)
- `<build-dir-name>-dbg-path`: Variable for `miDebuggerPath` in launch tasks
- `<build-dir-name>-dbg-mode`: Variable for `MIMode` in launch tasks

It is not recommended to change these variables unless there is a specific need.

.. note::

    Due to the way the configuration generation is implemented, each time the
    configuration is updated, any user comments will be lost.


Running as unprivileged user
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If not running as privileged user, then by default the generated configuration
will not be able to run DPDK applications that require `root` privileges. To
address this, either the system will have to be configured to allow running DPDK
as non-privileged user, or the launch configuration has to be amended to run the
debugger (usually `GDB`) as root.

Further information on configuring the system to allow running DPDK as
non-privileged user can be found in the :ref:`common Linux guide
<Running_Without_Root_Privileges>`.

If the user prefers to run applications as `root` while still working as regular
user instead, the following steps must be taken:

- Allow running GDB with password-less `sudo` (please consult relevant system
  documentation on how to achieve this)
- Set up a local alias for running GDB with `sudo` (e.g. `sudo gdb $@`)
- Amend the `settings.json` file to set `<build-dir>-dbg-path` variable to this
  new alias

Once this is done, any existing or new launch targets will use the new debugger
alias to run DPDK applications.

.. note::

    The above steps are not recommended for production systems, as they may
    introduce security vulnerabilities.

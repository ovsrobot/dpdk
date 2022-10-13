DTS environment
===============
This README contains helpful steps for setting up your own DTS development or execution
environment. As DTS is written purely in Python, we only need to download pre-built
Python packages, obviating the need for build tools. This in turn means that both the
DTS development and execution environments are the same. DTS environment, DTS
development environment and DTS execution environment are used interchangeably, as
they're referring to the same thing.

# DTS definitions
Before talking about environment setup itself, it's useful to sort out some basic
definitions:
* **DTS node**: A generic description of any element/server DTS connects to.
* **DTS execution environment**: An environment containing Python with packages needed
   to run DTS.
* **DTS execution environment node**: A node where at least one DTS execution
   environment is present. This is the node where we run DTS and from which DTS connects
   to other nodes.
* **System under test**: An SUT is the combination of DPDK and the hardware we're
   testing in conjunction with DPDK (NICs, crypto and other devices).
* **System under test node**: A node where at least one SUT is present.
* **Traffic generator**: A TG is either software or hardware capable of sending packets.
* **Traffic generator node**: A node where at least one TG is present. In case of
   hardware traffic generators, the TG and the node are literally the same.

In most cases, referring to an execution environment, SUT, TG or the node they're
running on interchangeably (e.g. using SUT and SUT node interchangeably) doesn't cause
confusion. There could theoretically be more than of these running on the same node and
in that case it's useful to have stricter definitions. An example would be two different
traffic generators (such as Trex and Scapy) running on the same node. A different
example would be a node containing both a DTS execution environment and a traffic
generator, in which case it's both a DTS execution environment node and a TG node.

# [Poetry](https://python-poetry.org/docs/)
The typical style of python dependency management, requirements.txt, has a few issues.
The advantages of Poetry include specifying what python version is required and forcing
you to specify versions, enforced by a lockfile, both of which help prevent broken
dependencies. Another benefit is the use of pyproject.toml, which has become the
standard config file for python projects, improving project organization.

# Python Version
The Python Version required by DTS is specified in [DTS python config file](./pyproject.toml)
in the **[tool.poetry.dependencies]** section. Poetry doesn't install Python, so you may
need to satisfy this requirement if your Python is not up-to-date. A tool such as
[Pyenv](https://github.com/pyenv/pyenv) is a good way to get Python, though not the only
one. However, DTS includes a development environment in the form of a Docker image.

# DTS Environment
The execution and development environments for DTS are the same, a
[Docker](https://docs.docker.com/) container defined by our [Dockerfile](./Dockerfile).
Using a container for the development environment helps with a few things.

1. It helps enforce the boundary between the DTS environment and the TG/SUT, something
   which caused issues in the past.
2. It makes creating containers to run DTS inside automated tooling much easier, since
   they can be based off of a known-working environment that will be updated as DTS is.
3. It abstracts DTS from the server it is running on. This means that the bare-metal os
   can be whatever corporate policy or your personal preferences dictate, and DTS does
   not have to try to support all distros that are supported by DPDK CI.
4. It makes automated testing for DTS easier, since new dependencies can be sent in with
  the patches.
5. It fixes the issue of undocumented dependencies, where some test suites require
   python libraries that are not installed.
6. Allows everyone to use the same python version easily, even if they are using a
   distribution or Windows with out-of-date packages.
7. Allows you to run the tester on Windows while developing via Docker for Windows.

## Tips for setting up a development environment

### Getting a docker shell
These commands will give you a bash shell inside the container with all the python
dependencies installed. This will place you inside a python virtual environment. DTS is
mounted via a volume, which is essentially a symlink from the host to the container.
This enables you to edit and run inside the container and then delete the container when
you are done, keeping your work.

```shell
docker build --target dev -t dpdk-dts .
docker run -v $(pwd)/..:/dpdk -it dpdk-dts bash
$ poetry install
$ poetry shell
```

### Vim/Emacs
Any editor in the ubuntu repos should be easy to use, with vim and emacs already
installed. You can add your normal config files as a volume, enabling you to use your
preferred settings.

```shell
docker run -v ${HOME}/.vimrc:/root/.vimrc -v $(pwd)/..:/dpdk -it dpdk-dts bash
```

### Visual Studio Code
VSCode has first-class support for developing with containers. You may need to run the
non-docker setup commands in the integrated terminal. DTS contains a .devcontainer
config, so if you open the folder in vscode it should prompt you to use the dev
container assuming you have the plugin installed. Please refer to
[VS Development Containers Docs](https://code.visualstudio.com/docs/remote/containers)
to set it all up.

### Other
Searching for '$IDE dev containers' will probably lead you in the right direction.

DTS Devtools
============

# Running the scripts
These scripts should be run in the [dts](.) directory. You can install their
dependencies directly, but all the scripts are designed to run in the DTS container
(specified by [Dockerfile](./Dockerfile)). The .git directory for dpdk must be present
inside the Dockerfile, meaning you may need to mount the repository as a volume, as
outlined earlier.

# Script Descriptions

### [../devtools/python-checkpatch.sh](../devtools/python-checkpatch.sh)
This script runs all the scripts below that provide information on code quality and
correctness,  exiting with a non-zero exit code if any of the scripts below found any
issues.

### [../devtools/python-format.sh](../devtools/python-format.sh)
By default, this script will format all the python code according to the DTS code style
standards. It will not change the semantics of any code, but fixes many issues around
whitespace, comment formatting and line length automatically.

This script uses two tools to accomplish this:

* [isort](https://pycqa.github.io/isort/): which alphabetically sorts python imports
within blocks.
* [black](https://github.com/psf/black): This tool does most of the actual formatting,
and works similarly to clang-format.

### [../devtools/python-lint.sh](../devtools/python-lint.sh)
This script runs [pylama](https://github.com/klen/pylama), which runs a collection of
python linters and aggregates output. It will run these tools over the repository:

* pycodestyle
* pylint
* mccabe
* mypy

Some lints are disabled due to conflicts with the automatic formatters.

Mypy is not running in strict mode since scapy, an important dependency for packet
manipulation, inspection and construction, does not have python type annotations. In
strict mode, this makes mypy fail even an empty file that imports scapy.

# Adding additional scripts
The shebang MUST be "#!/usr/bin/env bash". Many developers will be working inside a
python virtual environment, where environment variables are changed to allow multiple
python versions to coexist on the same system.

If the script provides feedback on code quality or correctness, or can reasonably be
made to do so, it should be added to dts-checkpatch.sh.

# Project: DPDK

## Project Description
DPDK is a set of libraries and drivers for fast packet processing.
It supports many processor architectures and both Linux, FreeBSD and Windows.

## Licensing
Overall project use BSD-3-Clause license with some approved exceptions.

## Build Commands
This is a C library project that uses the meson build system:
- Build: meson setup build && ninja -C build
- Run tests: meson test -C build  --suite fast-tests

## Code Conventions
- license is per file via SPDX-License-Identifier
- use Tabs for indentation
- closing and opening braces on same line as the keyword
- braces that are not necessary should be left out
- avoid using camelCase and PascalCase


## Project Structure
- /lib/ - libraries
- /license - reference copy of licenses
- /drivers - device drivers
- /examples - sample applications
- /doc - documentation
- /devtools - developer tools
- /usertools - user tools
- /kernel/
  - /linux/uapi - exported kernel headers
  - /freebsd - drivers for FreeBSD

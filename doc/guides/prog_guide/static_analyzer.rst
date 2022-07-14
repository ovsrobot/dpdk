.. SPDX-License-Identifier: BSD-3-Clause
   Copyright(c) 2022 Marvell

Running Static Analyzer
========================
Static analyzer is a compiler feature which when enabled scans through the source
code to try and find various problems at compile-time, rather than at runtime.

Static analyzer is a part of clang (9.0.1+) and GCC (10.1.0+).

`GCC Static analyzer document
<https://gcc.gnu.org/onlinedocs/gcc-10.1.0/gcc/Static-Analyzer-Options.html>`_

`Clang static analyzer document
<https://releases.llvm.org/9.0.1/tools/clang/docs/ClangStaticAnalyzer.html>`_

Enabling 'Static analyzer' is done by passing the -Dstatic_analyzer=true option to
the meson build system. By-default static analyzer is disabled.

Example::
  - meson setup -Dstatic_analyzer=true <build_dir>

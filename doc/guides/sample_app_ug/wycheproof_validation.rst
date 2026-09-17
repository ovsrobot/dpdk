..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2026 Intel Corporation.

Wycheproof Validation Example
============================

Overview
--------

This example validates a DPDK cryptodev implementation against the Google
Wycheproof JSON test vectors.

The application reads one JSON file or a directory of JSON files at runtime and
checks the supported algorithm families against the selected PMD. It can be used
with a PMD that advertises AEAD, MAC, DSA, ECDH, or ECDSA support.

Build
-----

Build the example from the DPDK tree with Meson:

.. code-block:: console

   meson setup build -Dexamples=wycheproof_validation -Denable_drivers=crypto/openssl
   meson compile -C build

Standalone Makefile builds are also supported from the example directory.

Run
---

Run the example with an OpenSSL-backed cryptodev and a vector file:

.. code-block:: console

   ./build/examples/dpdk-wycheproof_validation --vdev crypto_openssl -- \
       --vectors ../wycheproof/testvectors_v1/aes_gcm_test.json \
       --cryptodev crypto_openssl --debug

The program accepts a single JSON file or a directory of JSON files. Use
``--debug`` to print each failed or skipped vector with its reason.

The exit code is nonzero when a parsed and supported vector fails validation;
unsupported vectors, capability-skipped cases, and acceptable results are reported
in the summary without forcing a failure.

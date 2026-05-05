..  SPDX-License-Identifier: BSD-3-Clause

Flow Parser Library
===================

Overview
--------

The flow parser library provides **one way** to create ``rte_flow`` C structures
by parsing testpmd-style command strings. This is particularly useful for
applications that need to accept flow rules from user input, configuration
files, or external control planes using the familiar testpmd syntax.

.. note::

   This library is not the only way to create rte_flow structures. Applications
   can also construct ``struct rte_flow_attr``, ``struct rte_flow_item[]``, and
   ``struct rte_flow_action[]`` directly in C code and pass them to the rte_flow
   API (``rte_flow_create()``, ``rte_flow_validate()``, etc.). The parser library
   is an alternative approach for cases where string-based input is preferred.

Public API
----------

The simple API is declared in ``rte_flow_parser.h``.  It provides
lightweight parsing of testpmd-style flow rule fragments into standard
``rte_flow`` C structures that can be used with ``rte_flow_create()``,
``rte_flow_validate()``, and other rte_flow APIs.  The helpers use
internal static storage; returned pointers remain valid until the next
parse call.

.. note::

   Additional functions for full command parsing and cmdline integration are
   available in ``rte_flow_parser_cmdline.h``. These include
   ``rte_flow_parser_parse()`` for parsing complete flow CLI strings and
   cmdline token callbacks for building interactive command interfaces.

One-Shot Flow Rule Parsing
--------------------------

``rte_flow_parser_parse_flow_rule()`` parses a complete flow rule string
(attributes + pattern + actions) in a single call::

  struct rte_flow_attr attr;
  const struct rte_flow_item *pattern;
  const struct rte_flow_action *actions;
  uint32_t pattern_n, actions_n;

  ret = rte_flow_parser_parse_flow_rule(
      "ingress pattern eth / ipv4 / end actions drop / end",
      &attr, &pattern, &pattern_n, &actions, &actions_n);

This is equivalent to calling the three helpers individually but avoids the
caller having to split the string into attribute/pattern/action fragments.

Full Command Parsing
--------------------

``rte_flow_parser_parse()`` from ``rte_flow_parser_cmdline.h`` parses
complete flow CLI commands (create, validate, destroy, list, etc.) into
a ``struct rte_flow_parser_output``.  Applications switch on
``out->command`` to dispatch the result.

Configuration Registration
--------------------------

Applications own all configuration storage and register it with
``rte_flow_parser_config_register()`` before parsing flow rules that
reference encap/decap actions.  Single-instance configs (VXLAN, NVGRE,
L2, MPLS, conntrack) are written directly.  Multi-instance configs
(raw encap/decap, IPv6 extension, sample actions) use setter APIs.

Interactive Cmdline Integration
-------------------------------

Applications that want interactive flow parsing with tab completion
declare a ``cmdline_parse_inst_t`` using ``rte_flow_parser_cmd_flow_cb``
and include it in the ``rte_flow_parser_config`` registration.  See
``app/test-pmd/flow_parser_cli.c`` for the reference implementation.

.. note::

   The library writes to ``inst->help_str`` dynamically during interactive
   parsing to provide context-sensitive help. The registered instances must
   remain valid for the lifetime of the cmdline session.

Example
-------

``examples/flow_parsing/main.c`` demonstrates parsing helpers, one-shot
flow rule parsing, full command parsing, and configuration registration.
EAL initialization is not required.

Build and run::

  meson configure -Dexamples=flow_parsing build
  ninja -C build
  ./build/examples/dpdk-flow_parsing

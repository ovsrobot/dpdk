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

The library factors out the complete testpmd ``flow`` CLI grammar into a
reusable component. Applications can feed testpmd-style commands such as
``flow create ...`` or ``set raw_encap ...`` and receive fully-populated
``rte_flow`` structures along with callbacks for execution. This makes it
possible to:

* Accept user input in the familiar testpmd syntax.
* Reuse the comprehensive parsing logic (attributes, patterns, actions,
  templates, indirect actions, tunnel helpers, and raw encap/decap helpers).
* Integrate with application-specific control planes via callback tables.

The API surface lives in ``rte_flow_parser.h`` and is part of the installed
headers. The library is built as ``librte_flow_parser``.

Parser Initialization
---------------------

The library uses a single global parser instance. Initialize it once at
startup:

* ``rte_flow_parser_init(const struct rte_flow_parser_ops *ops)``
  initializes the global parser with a pair of callback tables. Pass NULL
  if no callbacks are needed (standalone parsing mode).
* ``rte_flow_parser_reset_defaults()`` resets parser state and clears stored
  caches (encap/decap templates, sample actions, etc.).

The parser keeps internal state (defaults, temporary buffers, cmdline tokens)
in global storage. The parser is not thread-safe; guard concurrent parsing
with external synchronization.

Parsing Commands
----------------

``int rte_flow_parser_parse(const char *src, struct rte_flow_parser_output
*result, size_t result_size)`` accepts a string containing one or more
commands. Whitespace or newlines may separate commands.

Output is written into the caller-provided buffer. The buffer must be at least
``sizeof(struct rte_flow_parser_output)`` and must also leave headroom for
embedded pattern/action data (the parser appends specs/masks/confs inside the
same buffer). Allocate a few kilobytes (e.g. 4–8 KiB) for typical commands;
``-ENOBUFS`` is returned if the buffer is too small.

On success the ``result`` fields describe the parsed command:

* ``command`` enumerates the operation (validate, create, destroy, template
  operations, indirect actions, set raw*, etc.).
* ``port``, ``queue``, and ``args.*`` carry the parsed attributes, patterns,
  actions, masks, user IDs, template IDs, and helper data.
* ``pattern``/``actions`` point into the caller buffer; copy or consume them
  before parsing the next command.

``int rte_flow_parser_run(const char *src)`` is a convenience wrapper that
parses and immediately dispatches the command through the installed
``command`` callbacks.

Lightweight Parsing Helpers
---------------------------

For applications that only need fragments of a flow rule, convenience helpers
parse small snippets without callbacks:

* ``rte_flow_parser_parse_attr_str(src, attr)`` parses only flow attributes
  into the provided ``struct rte_flow_attr``.
* ``rte_flow_parser_parse_pattern_str(src, pattern, pattern_n)`` parses only
  a pattern list and returns a pointer to the resulting ``struct rte_flow_item``
  array plus its length.
* ``rte_flow_parser_parse_actions_str(src, actions, actions_n)`` parses only
  an actions list and returns a pointer to the resulting ``struct rte_flow_action``
  array plus its length.

These helpers use internal thread-local storage; the returned pointers remain
valid until the next helper call on the same thread.

Example Usage
-------------

``examples/flow_parsing/main.c`` demonstrates the lightweight parsing helpers:

* Parse flow attributes with ``rte_flow_parser_parse_attr_str()``.
* Parse match patterns with ``rte_flow_parser_parse_pattern_str()``.
* Parse flow actions with ``rte_flow_parser_parse_actions_str()``.
* Print parsed results showing the structured data.

Build and run the example::

  meson configure -Dexamples=flow_parsing build
  ninja -C build
  ./build/examples/dpdk-flow_parsing

The output shows each parsed flow component, demonstrating that the parser
is decoupled from testpmd and usable in standalone applications without
requiring EAL initialization.

Callback Model
--------------

Two callback tables are provided at initialization time via
``struct rte_flow_parser_ops``:

* ``struct rte_flow_parser_ops_query`` supplies read-only helpers used during
  parsing and completion: port validation, queue/template counts, cached IDs
  and objects for completion, flex item handles, etc. RSS type strings come
  from the ethdev global table (``rte_eth_rss_type_info_get()``).
* ``struct rte_flow_parser_ops_command`` is invoked when a command is accepted
  by the cmdline integration helpers. ``rte_flow_parser_parse()`` only parses
  and never dispatches callbacks. Typical command implementations map directly
  to ``rte_flow`` or application-specific control plane functions:
  ``flow_validate``, ``flow_create``, destroy/update variants,
  table/template management, indirect actions, hash calculation, tunnel
  helpers.

Implement only the callbacks your application needs; unused hooks may be NULL.
Encapsulation templates and caches (VXLAN/NVGRE/L2/MPLS* templates, raw
encap/decap, IPv6 extension, and sample actions) are stored inside the parser
and consumed directly during parsing. They can be modified through the
``rte_flow_parser_*_conf()`` accessor functions, and the ``set raw*``,
``set sample_actions`` and ``set ipv6_ext_*`` commands update the global
parser state.

..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>

Flow Rule Compiler
==================

The flow rule compiler (``rte_flow_compile``) turns a textual
description of an ``rte_flow`` rule into the
``struct rte_flow_attr`` / ``struct rte_flow_item`` /
``struct rte_flow_action`` arrays accepted by ``rte_flow_create()``.

It is modelled on ``pcap_compile()`` from libpcap: a single string in,
an opaque compiled object out, with human readable diagnostics
written to a caller supplied buffer.

The compiler depends only on the EAL and the existing
``rte_ethdev`` (``rte_flow.h``) library.  In particular it does not
pull in ``rte_cmdline``, so it is suitable for use from libraries,
control planes and unit tests.


Example
-------

.. code-block:: c

   char errbuf[RTE_FLOW_COMPILE_ERRBUF_SIZE];
   const char *src =
       "ingress group 0 priority 1 "
       "pattern eth / ipv4 src is 10.0.0.1 / udp dst is 4789 / end "
       "actions queue index 3 / count / end";

   struct rte_flow_compile *fc = rte_flow_compile(src, errbuf);
   if (fc == NULL) {
           fprintf(stderr, "%s\n", errbuf);
           return -1;
   }

   struct rte_flow_error err;
   struct rte_flow *f = rte_flow_compile_create(port_id, fc, &err);

   /* fc may be reused on multiple ports or freed now. */
   rte_flow_compile_free(fc);


API summary
-----------

.. code-block:: c

   struct rte_flow_compile *
   rte_flow_compile(const char *str,
                    char errbuf[RTE_FLOW_COMPILE_ERRBUF_SIZE]);

   void
   rte_flow_compile_free(struct rte_flow_compile *fc);

   const struct rte_flow_attr   *rte_flow_compile_attr(...);
   const struct rte_flow_item   *rte_flow_compile_pattern(..., unsigned int *n);
   const struct rte_flow_action *rte_flow_compile_actions(..., unsigned int *n);

   int             rte_flow_compile_validate(uint16_t port_id, ..., struct rte_flow_error *);
   struct rte_flow *rte_flow_compile_create  (uint16_t port_id, ..., struct rte_flow_error *);

The compiled object owns every buffer it returns: attributes,
patterns, actions and all underlying spec/mask/last/conf payloads.
Pointers are valid until ``rte_flow_compile_free()`` is called.
A single compiled rule may be installed on many ports and validated
or created concurrently from multiple threads; the parser itself
holds no static mutable state.


Grammar
-------

The grammar is pure ASCII; ``#`` starts an end-of-line comment.
Whitespace is insignificant.

.. code-block:: bnf

   rule         ::= attribute* "pattern" item-list "actions" action-list
   attribute    ::= "ingress" | "egress" | "transfer"
                  | "group"    UINT
                  | "priority" UINT
   item-list    ::= ( item "/" )* "end"
   item         ::= IDENT field-spec*
   field-spec   ::= IDENT qualifier value
   qualifier    ::= "is" | "spec" | "last" | "mask" | "prefix"
   action-list  ::= ( action "/" )* "end"
   action       ::= IDENT param*
   param        ::= IDENT value
   value        ::= UINT | IPV4 | IPV6 | MAC | HEXSTR | STRING

Both lists may be empty; ``pattern end`` is a wildcard match and is
useful as a catch-all rule.  An empty action list is accepted by the
compiler but typically rejected by the underlying PMD.

Lexical tokens:

.. code-block:: bnf

   IDENT        ::= [A-Za-z_][A-Za-z0-9_]*
   UINT         ::= [0-9]+ | "0x" [0-9A-Fa-f]+         ; up to 16 hex digits
   IPV4         ::= UINT "." UINT "." UINT "." UINT    ; each 0..255
   IPV6         ::= RFC 4291 / 5952 textual form (no embedded IPv4)
   MAC          ::= XX ":" XX ":" XX ":" XX ":" XX ":" XX
   HEXSTR       ::= "0x" [0-9A-Fa-f]{2*N}              ; > 16 hex digits
   STRING       ::= '"' character* '"'

The grammar follows ``testpmd`` closely so that flow rules already
familiar to users carry over; the lexer and parser are independent
implementations and do not depend on testpmd, ``rte_cmdline`` or
``cmdline_parse_*``.


Field qualifier semantics
-------------------------

For each parsed ``field qualifier value`` triple the compiler writes
into one or more of the spec/mask/last buffers.  Semantics match
``testpmd``:

.. list-table::
   :header-rows: 1
   :widths: 10 30 30 20

   * - Qualifier
     - spec
     - mask
     - last
   * - ``is``
     - value
     - all-ones over the field
     - --
   * - ``spec``
     - value
     - --
     - --
   * - ``mask``
     - --
     - value
     - --
   * - ``last``
     - --
     - --
     - value
   * - ``prefix``
     - --
     - high N bits set (CIDR style); IPv4/IPv6 only
     - --

Last write wins.  ``ipv4 src spec 10.0.0.0 src prefix 16`` therefore
matches the entire ``10.0.0.0/16`` range with mask ``255.255.0.0``;
``src is 10.0.0.0`` would have set the mask to all-ones, which is
exact match.


Diagnostics
-----------

Errors are reported as ``LINE:COL: message`` in the caller-supplied
``errbuf`` of at least ``RTE_FLOW_COMPILE_ERRBUF_SIZE`` (256) bytes.
The first error wins; subsequent errors are suppressed so that the
user sees the original cause rather than a cascade.

On failure ``rte_errno`` is set to ``EINVAL`` for parse errors and
``ENOMEM`` for allocation failures.


Extending the compiler
----------------------

The parser is entirely table driven.  Adding a new flow item type
requires no parser changes:

#. In ``flow_compile_tables.c``, define a static
   ``struct field_desc`` array describing the parsable fields of the
   item's spec struct.
#. Add an ``ITEM(...)`` entry to ``flow_items[]``.

Each ``field_desc`` lists the field's offset, byte width and a
``field_kind`` (``FK_U32``, ``FK_BE16``, ``FK_MAC``, ``FK_IPV4``,
``FK_IPV6``, ``FK_BYTES``, ...).  Default setters honor every kind
and produce the correct byte order automatically.

For fields whose layout cannot be expressed as a plain byte range
(C bitfields, indirect arrays, RSS keys, ...) populate the ``set``
function pointer.  The custom setter receives the destination
buffer, an optional mask buffer (non-NULL when the user wrote
``is``) and the parsed value token.

Adding a new action type follows the same pattern with
``flow_actions[]`` and ``ACTION(...)``.


Source layout
-------------

The library sits in ``lib/flow_compile`` and is split for clarity:

================================  ==================================
File                              Contents
================================  ==================================
``rte_flow_compile.h``            Public API.
``flow_compile_priv.h``           Internal types: tokens, descriptors,
                                  parser state.
``flow_compile_lex.c``            Hand-rolled lexer with
                                  source-position tracking for
                                  diagnostics.
``flow_compile_parse.c``          Recursive-descent parser plus the
                                  default field setters used by the
                                  table-driven body parser.
``flow_compile_tables.c``         Per-item and per-action descriptor
                                  tables.  All extension work
                                  happens here.
``rte_flow_compile_api.c``        Public entry points: compile,
                                  free, accessors, validate, create.
================================  ==================================


Implementation notes
--------------------

Locale independence
   Every character classification uses inline ASCII-only predicates
   rather than ``<ctype.h>``; hex parsing uses an inline nibble
   helper rather than ``strtoul()``.  The grammar is pure ASCII, so
   the active locale cannot affect parsing.

Endianness
   All multibyte writes go through ``rte_cpu_to_be_{16,32,64}`` or
   raw byte copies from already network-order tokens
   (``TK_IPV4``, ``TK_MAC``, ``TK_IPV6``).

Alignment
   Spec and mask buffers may contain unaligned multibyte fields
   inside packed-ish header structs.  All writes go through
   ``memcpy`` to handle this portably.

Memory
   All allocations go through ``rte_zmalloc`` and ``rte_free``.  Each
   spec, mask, last and conf payload is its own allocation; the
   pattern and action arrays are separate ``rte_calloc`` allocations
   that grow by doubling.  ``rte_flow_compile_free()`` walks the
   pattern and action arrays and frees every non-NULL slot before
   freeing the arrays themselves, so a partially compiled rule on
   a parse-error path is cleaned up uniformly.

Reentrancy
   The parser holds no static mutable state.  Multiple threads may
   compile rules in parallel and a single compiled rule may be
   installed concurrently on multiple ports.


Limitations
-----------

The initial implementation covers the most common items
(``eth``, ``vlan``, ``ipv4``, ``ipv6``, ``tcp``, ``udp``, ``vxlan``,
``port_id``, ``port_representor``, ``represented_port``) and actions
(``drop``, ``passthru``, ``queue``, ``mark``, ``jump``, ``count``,
``port_id``, ``port_representor``, ``represented_port``,
``of_pop_vlan``, ``vxlan_decap``).  Adding more is purely a matter
of extending the descriptor tables.

Items and actions whose conf has a variable-length payload
(``RSS``, ``RAW``, the various ``RAW_ENCAP``/``RAW_DECAP`` actions)
are not yet wired up; they require custom setters via the
``field_desc.set`` hook.

The IPv6 tokeniser does not accept the embedded-IPv4 dotted-quad
form (``::ffff:10.0.0.1``); use the all-hex form instead.

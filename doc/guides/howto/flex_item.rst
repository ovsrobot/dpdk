.. SPDX-License-Identifier: BSD-3-Clause
   Copyright (c) 2021 NVIDIA Corporation & Affiliates


Flex item API - examples
========================

The document uses known network protocols to demonstrate flex item API
programming examples.

eCPRI protocol
--------------

This example demonstrates basic flex item API usage.

Header structure
~~~~~~~~~~~~~~~~

::

   0    1    2    3    4    5    6    7
   +----+----+----+----+----+----+----+----+
   |  protocol version | reserved     | C  | +0
   +----+----+----+----+----+----+----+----+
   |          message type                 | +1
   +----+----+----+----+----+----+----+----+
   |                                       | +2
   +----      payload size             ----+
   |                                       | +3
   +----+----+----+----+----+----+----+----+

Flex item configuration
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <rte_flow.h>

   const struct rte_flow_item_flex_conf ecpri_flex_conf = {
      /* single eCPRI header in a packet. Can be ether inner or outer */
      .tunnel = FLEX_TUNNEL_MODE_SINGLE,

      /* eCPRI header size description */
      .next_header = {
         .field_mode = FIELD_MODE_FIXED,  /* fixed-size header */
         .field_size = 4 * sizeof(char) * CHAR_BIT;
      },

      /* eCPRI header is followed by a payload */
      .next_protocol = {},

      /* single sample that covers entire eCPRI header */
      .sample_data = {
         {
            .field_mode = FIELD_MODE_FIXED,
            .field_size = 4 * sizeof(char) * CHAR_BIT,
            .field_base = 0
         }
      },
      .nb_samples = 1,

      /* eCPRI protocol follows ether Ethernet or UDP headers */
      .input_link = {
         {
            .item = {
               .type = RTE_FLOW_ITEM_TYPE_ETH,
               .spec = &(struct rte_flow_item_eth) {
                  .type = rte_cpu_to_be_16(0xAEFE),
               },
            }
         },
         {
            .item = {
               .type = RTE_FLOW_ITEM_TYPE_UDP,
               .spec = &(struct rte_flow_item_udp) {
                  .hdr.dst_port = rte_cpu_to_be_16(0xAEFE)
               },
            }
         },
      },
      .nb_inputs = 2,

      /* no network protocol follows eCPRI header */
      .nb_outputs = 0;
   };

   struct rte_flow_item_flex_handle *ecpri_flex_handle;
   ecpri_flex_handle = rte_flow_flex_item_create(port_id, ecpri_flex_conf, error);

Flex flow item
~~~~~~~~~~~~~~

Application defined structure to match eCPRI header:

.. code-block:: c
   :linenos:

   struct ecpri_hdr {
      unsigned char version:4;
      unsigned char reserved:3;
      unsigned char c:1;
      unsigned char msg_type;
      unsigned short payload_size;
   } __rte_packed;


* Match all but last eCPRI PDUs:

   .. code-block:: c
      :linenos:

      const struct ecpri_hdr ecpri_not_last_spec = {
         .version = 1,
         .c = 1
      };
      const struct ecpri_hdr ecpri_not_last_mask = {
         .version = 0xf,
         .c = 1
      };

      const struct rte_flow_item_flex ecpri_not_last_flex_spec = {
         .handle = ecpri_flex_handle,
         .length = sizeof(ecpri_not_last_spec),
         .pattern = &ecpri_not_last_spec
      };

      const struct rte_flow_item_flex ecpri_not_last_flex_mask = {
         .handle = ecpri_flex_handle,
         .length = sizeof(ecpri_not_last_mask),
         .pattern = &ecpri_not_last_mask
      };

      const struct rte_flow_item ecpri_not_last_flow_item = {
         .type = RTE_FLOW_ITEM_TYPE_FLEX,
         .spec = (const void *)&ecpri_not_last_flex_spec,
         .mask = (const void *)&ecpri_not_last_flex_mask,
      };

* Match ``Generic Data Transfer`` type eCPRI PDUs:

   .. code-block:: c
      :linenos:

      const struct ecpri_hdr ecpri_data_transfer_spec = {
         .version = 1,
         .msg_type = 3
      };
      const struct ecpri_hdr ecpri_data_transfer_mask = {
         .version = 0xf,
         .msg_type = 0xff
      };

      const struct rte_flow_item_flex ecpri_data_transfer_flex_spec = {
         .handle = ecpri_flex_handle,
         .length = sizeof(ecpri_data_transfer_spec),
         .pattern = &ecpri_data_transfer_spec
      };

      const struct rte_flow_item_flex ecpri_data_transfer_flex_mask = {
         .handle = ecpri_flex_handle,
         .length = sizeof(ecpri_data_transfer_mask),
         .pattern = &ecpri_data_transfer_mask
      };

      const struct rte_flow_item ecpri_data_transfer_flow_item = {
         .type = RTE_FLOW_ITEM_TYPE_FLEX,
         .spec = (const void *)&ecpri_data_transfer_flex_spec,
         .mask = (const void *)&ecpri_data_transfer_flex_mask,
      };

Geneve protocol
---------------

Demonstrate flex item API usage with variable length network header.
Protocol header is built from a fixed size section that is followed by
variable size section.


Header Structure
~~~~~~~~~~~~~~~~

Geneve header format:

::

                       1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Virtual Network Identifier (VNI)       |    Reserved   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                    Variable-Length Options                    ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Geneve option format:

::

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Option Class         |      Type     |R|R|R| Length  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                  Variable-Length Option Data                  ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Flex item configuration
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <rte_flow.h>

   const struct rte_flow_item_flex_conf geneve_flex_conf = {
      /* Geneve is tunnel protocol */
      .tunnel = FLEX_TUNNEL_MODE_TUNNEL,

      /*
       * Geneve header size description
       * Header size calculation: field_size + ([Length] & offset_mask) << offset_shift
       */
      .next_header = {
         .field_mode = FIELD_MODE_OFFSET,           /* variable header length */
         .field_size = 2 * sizeof(int) * CHAR_BIT,  /* minimal header size */
         .offset_base = 2,                          /* length extension location in the header */
         .offset_mask = 0x3f,                       /* length extension mask */
         .offset_shift = 3,                         /* length extension scale factor */
      },

      /* next protocol location in Geneve header */
      .next_protocol = {
         .field_base = 16,
         .field_size = 16,
      },

      /* Samples for flow matches */
      .sample_data = {
         /* sample first 2 double words */
         {
            .field_mode = FIELD_MODE_FIXED,
            .field_size = 64,
            .field_base = 0,
         },
         /* sample 6 optional double words */
         {
            .field_mode = FIELD_MODE_FIXED,
            .field_size = 192,
            .field_base = 64,
         },
      },
      .nb_samples = 2,

      /* Geneve follows UDP header */
      .input_link = {
         {
            .item = {
               .type = RTE_FLOW_ITEM_TYPE_UDP,
               .spec = &(struct rte_flow_item_udp) {
                  .hdr.dst_port = rte_cpu_to_be_16(6081)
               }
            }
         }
      },
      .nb_inputs = 1,

      .output_link = {
         {
            .item = { .type = RTE_FLOW_ITEM_TYPE_ETH },
            .next = rte_cpu_to_be_16(0x6558)
         },
         {
            .item = { .type = RTE_FLOW_ITEM_TYPE_IPv4 },
            .next = rte_cpu_to_be_16(0x0800)
         },
         {
            .item = { .type = RTE_FLOW_ITEM_TYPE_IPv6 },
            .next = rte_cpu_to_be_16(0x86dd)
         },
      },
      .nb_output = 3
   };

   struct rte_flow_item_flex_handle *geneve_flex_handle;
   geneve_flex_handle = rte_flow_flex_item_create(port_id, geneve_flex_conf, error);

Flex flow item
~~~~~~~~~~~~~~

Application defined structure for Geneve header:

.. code-block:: c
   :linenos:

   struct geneve_hdr {
      unsigned int ver:2;
      unsigned int opt_len:6;
      unsigned int o:1;
      unsigned int c:1;
      unsigned int reserved1:6;
      unsigned int next_protocol:16;
      unsigned int vni:24;
      unsigned int reserved2:8;
      unsigned long options[];
   } __rte_packed;

   struct geneve_option_hdr {
      unsigned int class:16;
      unsigned int type:8;
      unsigned int flags:3;
      unsigned int length:5;
      unsigned int data[];
   } __rte_packed;

* Match Geneve basic header

   .. code-block:: c
      :linenos:

      const struct geneve_hdr geneve_basic_header_spec = {
         .ver = 0,
         .opt_len = 0,
      };
      const struct geneve_hdr geneve_basic_header_mask = {
         .ver = 3,
         .opt_len = 0x3f,
      };

      const struct rte_flow_item_flex geneve_basic_header_flex_spec = {
         .handle = geneve_flex_handle,
         .length = sizeof(geneve_basic_header_spec),
         .pattern = &geneve_basic_header_spec
      };

      const struct rte_flow_item_flex geneve_basic_header_flex_mask = {
         .handle = geneve_flex_handle,
         .length = sizeof(geneve_basic_header_mask),
         .pattern = &geneve_basic_header_mask
      };

      const struct rte_flow_item geneve_basic_header_flow_item = {
         .type = RTE_FLOW_ITEM_TYPE_FLEX,
         .spec = (const void *)&geneve_basic_header_flex_spec,
         .maks = (const void *)&geneve_basic_header_flex_mask,
      };

* Match if the first option class is Open vSwitch

   .. code-block:: c
      :linenos:

      const struct geneve_option_hdr geneve_ovs_opt_spec = {
         .class = rte_cpu_to_be16(0x0101),
      };

      const struct geneve_option_hdr geneve_ovs_opt_mask = {
         .class = 0xffff,
      };

      const struct geneve_hdr geneve_hdr_with_ovs_spec = {
         .ver = 0,
         .options = (const unsigned long *)&geneve_ovs_opt_spec
      };

      const struct geneve_hdr geneve_hdr_with_ovs_mask = {
         .ver = 3,
         .options = (const unsigned long *)&geneve_ovs_opt_mask
      };

      const struct rte_flow_item_flex geneve_flex_spec = {
         .handle = geneve_flex_handle,
         .length = sizeof(geneve_hdr_with_ovs_spec) + sizeof(geneve_ovs_opt_spec),
         .pattern = &geneve_hdr_with_ovs_spec
      };

      const struct rte_flow_item_flex geneve_flex_mask = {
         .handle = geneve_flex_handle,
         .length = sizeof(geneve_hdr_with_ovs_mask) + sizeof(geneve_ovs_opt_mask),
         .pattern = &geneve_hdr_with_ovs_mask
      };

      const struct rte_flow_item geneve_vni_flow_item = {
         .type = RTE_FLOW_ITEM_TYPE_FLEX,
         .spec = (const void *)&geneve_flex_spec,
         .maks = (const void *)&geneve_flex_mask,
      };

Extended GRE packet header (RFC 2890)
-------------------------------------

This example shows how to configure flex item if protocol header length
depends on a bitmask.

Header structure
~~~~~~~~~~~~~~~~

::

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |C| |K|S| Reserved0       | Ver |         Protocol Type         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Checksum (optional)      |       Reserved1 (Optional)    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Key (optional)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Sequence Number (Optional)                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Flex item configuration
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c
   :linenos:

   #include <rte_flow.h>

   const struct rte_flow_item_flex_conf egre_flex_conf = {
      /* eGRE is tunnel protocol */
      .tunnel = FLEX_TUNNEL_MODE_TUNNEL,

      /*
       * Header size description.
       * Header calculation field_size + (bitcount([C|K|S]) & offset_mask) << offset_shift
       */
      .next_header = {
         .field_mode = FIELD_MODE_BITMASK,
         .field_size = sizeof(int) * CHAR_BIT,
         .offset_base = 0,
         .offset_mask = 3,
         .offset_shift = 2
      },

      /*
       * Samples for flow match.
       * Adjust samples for maximal header length.
       */
      .sample_data = {
         {
            .field_mode = FIELD_MODE_FIXED,
            .filed_size = 4 * sizeof(int) * CHAR_BIT,
            .field_base = 0
         }
      }
      .nb_samples = 1,

      /* eGRE follows IPv4 or IPv6 */
      .input_link = {
         {
            .item = {
               .type = RTE_FLOW_ITEM_TYPE_IPV4,
               .spec = &(struct rte_flow_item_ipv4) {
                  .hdr.next_proto_id = 47
               }
            }
         },
         {
            .item = {
               .type = RTE_FLOW_ITEM_TYPE_IPV6,
               .spec = &(struct rte_flow_item_ipv6) {
                  .hdr.proto = 47
               }
            }
         }
      },
      .nb_inputs = 2,

      .output_link = {
         {
            .item = { .type = RTE_FLOW_ITEM_TYPE_ETH },
            .next = rte_cpu_to_be_16(0x6558)
         },
         {
            .item = { .type = RTE_FLOW_ITEM_TYPE_IPv4 },
            .next = rte_cpu_to_be_16(0x0800)
         },
         {
            .item = { .type = RTE_FLOW_ITEM_TYPE_IPv6 },
            .next = rte_cpu_to_be_16(0x86dd)
         },
      },
      .nb_output = 3
   };

   struct rte_flow_item_flex_handle *egre_flex_handle;
   egre_flex_handle = rte_flow_flex_item_create(port_id, egre_flex_conf, error);

Flex flow item
~~~~~~~~~~~~~~

Application defined eGRE header structure:

.. code-block:: c
   :linenos:

   struct egre_hdr {
      unsigned int c:1;
      unsigned int reserved_bit:1;
      unsigned int k:1;
      unsigned int s:1;
      unsigned int reserved0:9;
      unsigned int ver:3;
      unsigned int protocol:16;
      unsigned int optional_cks[];
   };

* Match eGRE header

.. code-block:: c
   :linenos:

   const struct egre_hdr egre_hdr_spec = {
      .version = 0
   };

   const struct egre_hdr egre_hdr_mask = {
      .version = 7
   };

   const struct rte_flow_item_flex egre_flex_item_spec = {
         .handle = egre_flex_handle,
         .length = sizeof(egre_hdr_spec),
         .pattern = &egre_hdr_spec
   };

   const struct rte_flow_item_flex egre_flex_item_mask = {
         .handle = egre_flex_handle,
         .length = sizeof(egre_hdr_mask),
         .pattern = &egre_hdr_mask
   };

   const struct rte_flow_item egre_item_spec = {
      .type = RTE_FLOW_ITEM_TYPE_FLEX,
      .spec = (const void *)&egre_flex_item_spec,
      .mask = (const void *)&egre_flex_item_mask
   };

* Match key value

That example needs 2 flow rules - one flow rule to match eGRE header with both
C and K flags on and the second flow rule to match eGRE header with K flag only.

.. code-block:: c
   :linenos:

   unsigned int key_val;

   /* eGRE header with both C and K flags set */
   const struct egre_hdr_ck_spec = {
      .c = 1,
      .k = 1,
      .version = 0,
      .optional_cks[1] = ky_val;
   };

   const struct egre_hdr_ck_mask = {
      .c = 1,
      .k = 1,
      .version = 7,
      .optional_cks[1] = 0xffffffff;
   };

   /* eGRE header with K flag set only */
   const struct egre_hdr_k_spec = {
      .k = 1,
      .version = 0,
      .optional_cks[0] = ky_val;
   };

   const struct egre_hdr_k_mask = {
      .k = 1,
      .version = 7,
      .optional_cks[0] = 0xffffffff;
   };

   const struct rte_flow_item_flex egre_ck_flex_item_spec = {
         .handle = egre_hdr_ck_spec,
         .length = sizeof(egre_hdr_ck_spec) + 2 * sizeof(int),
         .pattern = &egre_hdr_ck_spec
   };

   const struct rte_flow_item_flex egre_ck_flex_item_mask = {
         .handle = egre_hdr_ck_spec,
         .length = sizeof(egre_hdr_ck_spec) + 2 * sizeof(int),
         .pattern = &egre_hdr_ck_mask
   };

   const struct rte_flow_item_flex egre_k_flex_item_spec = {
         .handle = egre_hdr_k_spec,
         .length = sizeof(egre_hdr_k_spec) + sizeof(int),
         .pattern = &egre_hdr_k_spec
   };

   const struct rte_flow_item_flex egre_k_flex_item_mask = {
         .handle = egre_hdr_k_spec,
         .length = sizeof(egre_hdr_k_spec) + sizeof(int),
         .pattern = &egre_hdr_k_mask
   };

   const struct rte_flow_item egre_ck_item_spec = {
      .type = RTE_FLOW_ITEM_TYPE_FLEX,
      .spec = (const void *)&egre_ck_flex_item_spec,
      .mask = (const void *)&egre_ck_flex_item_mask
   };

   const struct rte_flow_item egre_k_item_spec = {
      .type = RTE_FLOW_ITEM_TYPE_FLEX,
      .spec = (const void *)&egre_k_flex_item_spec,
      .mask = (const void *)&egre_k_flex_item_mask
   };

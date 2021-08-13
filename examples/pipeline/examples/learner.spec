; SPDX-License-Identifier: BSD-3-Clause
; Copyright(c) 2020 Intel Corporation

//
// Headers
//
struct ethernet_h {
	bit<48> dst_addr
	bit<48> src_addr
	bit<16> ethertype
}

struct ipv4_h {
	bit<8> ver_ihl
	bit<8> diffserv
	bit<16> total_len
	bit<16> identification
	bit<16> flags_offset
	bit<8> ttl
	bit<8> protocol
	bit<16> hdr_checksum
	bit<32> src_addr
	bit<32> dst_addr
}

header ethernet instanceof ethernet_h
header ipv4 instanceof ipv4_h

//
// Meta-data
//
struct metadata_t {
	bit<32> port_in
	bit<32> port_out

	// Arguments for the "fwd_action" action.
	bit<32> fwd_action_arg_port_out
}

metadata instanceof metadata_t

//
// Registers.
//
regarray counter size 1 initval 0

//
// Actions
//
struct fwd_action_args_t {
	bit<32> port_out
}

action fwd_action args instanceof fwd_action_args_t {
	mov m.port_out t.port_out
	return
}

action learn_action args none {
	// Read current counter value into m.fwd_action_arg_port_out.
	regrd m.fwd_action_arg_port_out counter 0

	// Increment the counter.
	regadd counter 0 1

	// Limit the values of m.fwd_action_arg_port_out to 0 .. 3.
	and m.fwd_action_arg_port_out 3

	// Add the current lookup key to the table. The associated action is fwd_action, with the
	// action parameters read from the packet meta-data starting with the
	// m.fwd_action_arg_port_out field.
	learn fwd_action

	// Send the current packet to the same output port.
	mov m.port_out m.fwd_action_arg_port_out

	return
}

//
// Tables.
//
learner fwd_table {
	key {
		h.ipv4.dst_addr
	}

	actions {
		fwd_action args m.fwd_action_arg_port_out
		learn_action args none
	}

	default_action learn_action args none
	size 1048576
	timeout 120
}

//
// Pipeline.
//
apply {
	rx m.port_in
	extract h.ethernet
	extract h.ipv4
	table fwd_table
	emit h.ethernet
	emit h.ipv4
	tx m.port_out
}

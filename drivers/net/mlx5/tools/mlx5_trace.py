#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 NVIDIA Corporation & Affiliates

'''
Analyzing the mlx5 PMD datapath tracings
'''
import sys
import argparse
import pathlib
import bt2

PFX_TX     = "pmd.net.mlx5.tx."
PFX_TX_LEN = len(PFX_TX)

tx_blst = {}                    # current Tx bursts per CPU
tx_qlst = {}                    # active Tx queues per port/queue
tx_wlst = {}                    # wait timestamp list per CPU

class mlx5_queue(object):
    def __init__(self):
        self.done_burst = []    # completed bursts
        self.wait_burst = []    # waiting for completion
        self.pq_id = 0

    def log(self):
        for txb in self.done_burst:
            txb.log()


class mlx5_mbuf(object):
    def __init__(self):
        self.wqe = 0            # wqe id
        self.ptr = None         # first packet mbuf pointer
        self.len = 0            # packet data length
        self.nseg = 0           # number of segments

    def log(self):
        out = "    %X: %u" % (self.ptr, self.len)
        if self.nseg != 1:
            out += " (%d segs)" % self.nseg
        print(out)


class mlx5_wqe(object):
    def __init__(self):
        self.mbuf = []          # list of mbufs in WQE
        self.wait_ts = 0        # preceding wait/push timestamp
        self.comp_ts = 0        # send/recv completion timestamp
        self.opcode = 0

    def log(self):
        id = (self.opcode >> 8) & 0xFFFF
        op = self.opcode & 0xFF
        fl = self.opcode >> 24
        out = "  %04X: " % id
        if op == 0xF:
            out += "WAIT"
        elif op == 0x29:
            out += "EMPW"
        elif op == 0xE:
            out += "TSO "
        elif op == 0xA:
            out += "SEND"
        else:
            out += "0x%02X" % op
        if self.comp_ts != 0:
            out += " (%d, %d)" % (self.wait_ts, self.comp_ts - self.wait_ts)
        else:
            out += " (%d)" % self.wait_ts
        print(out)
        for mbuf in self.mbuf:
            mbuf.log()

    # return 0 if WQE in not completed
    def comp(self, wqe_id, ts):
        if self.comp_ts != 0:
            return 1
        id = (self.opcode >> 8) & 0xFFFF
        if id > wqe_id:
            id -= wqe_id
            if id <= 0x8000:
                return 0
        else:
            id = wqe_id - id
            if id >= 0x8000:
                return 0
        self.comp_ts = ts
        return 1


class mlx5_burst(object):
    def __init__(self):
        self.wqes = []          # issued burst WQEs
        self.done = 0           # number of sent/recv packets
        self.req = 0            # requested number of packets
        self.call_ts = 0        # burst routine invocation
        self.done_ts = 0        # burst routine done
        self.queue = None

    def log(self):
        port = self.queue.pq_id >> 16
        queue = self.queue.pq_id & 0xFFFF
        if self.req == 0:
            print("%u: tx(p=%u, q=%u, %u/%u pkts (incomplete)" %
                  (self.call_ts, port, queue, self.done, self.req))
        else:
            print("%u: tx(p=%u, q=%u, %u/%u pkts in %u" %
                  (self.call_ts, port, queue, self.done, self.req,
                   self.done_ts - self.call_ts))
        for wqe in self.wqes:
            wqe.log()

    # return 0 if not all of WQEs in burst completed
    def comp(self, wqe_id, ts):
        wlen = len(self.wqes)
        if wlen == 0:
            return 0
        for wqe in self.wqes:
            if wqe.comp(wqe_id, ts) == 0:
                return 0
        return 1


def do_tx_entry(msg):
    event = msg.event
    cpu_id = event["cpu_id"]
    burst = tx_blst.get(cpu_id)
    if burst is not None:
        # continue existing burst after WAIT
        return
    # allocate the new burst and append to the queue
    burst = mlx5_burst()
    burst.call_ts = msg.default_clock_snapshot.ns_from_origin
    tx_blst[cpu_id] = burst
    pq_id = event["port_id"] << 16 | event["queue_id"]
    queue = tx_qlst.get(pq_id)
    if queue is None:
        # queue does not exist - allocate the new one
        queue = mlx5_queue();
        queue.pq_id = pq_id
        tx_qlst[pq_id] = queue
    burst.queue = queue
    queue.wait_burst.append(burst)


def do_tx_exit(msg):
    event = msg.event
    cpu_id = event["cpu_id"]
    burst = tx_blst.get(cpu_id)
    if burst is None:
        return
    burst.done_ts = msg.default_clock_snapshot.ns_from_origin
    burst.req = event["nb_req"]
    burst.done = event["nb_sent"]
    tx_blst.pop(cpu_id)


def do_tx_wqe(msg):
    event = msg.event
    cpu_id = event["cpu_id"]
    burst = tx_blst.get(cpu_id)
    if burst is None:
        return
    wqe = mlx5_wqe()
    wqe.wait_ts = tx_wlst.get(cpu_id)
    if wqe.wait_ts is None:
        wqe.wait_ts = msg.default_clock_snapshot.ns_from_origin
    wqe.opcode = event["opcode"]
    burst.wqes.append(wqe)


def do_tx_wait(msg):
    event = msg.event
    cpu_id = event["cpu_id"]
    tx_wlst[cpu_id] = event["ts"]


def do_tx_push(msg):
    event = msg.event
    cpu_id = event["cpu_id"]
    burst = tx_blst.get(cpu_id)
    if burst is None:
        return
    if not burst.wqes:
        return
    wqe = burst.wqes[-1]
    mbuf = mlx5_mbuf()
    mbuf.wqe = event["wqe_id"]
    mbuf.ptr = event["mbuf"]
    mbuf.len = event["mbuf_pkt_len"]
    mbuf.nseg = event["mbuf_nb_segs"]
    wqe.mbuf.append(mbuf)


def do_tx_complete(msg):
    event = msg.event
    pq_id = event["port_id"] << 16 | event["queue_id"]
    queue = tx_qlst.get(pq_id)
    if queue is None:
        return
    qlen = len(queue.wait_burst)
    if qlen == 0:
        return
    wqe_id = event["wqe_id"]
    ts = event["ts"]
    rmv = 0
    while rmv < qlen:
        burst = queue.wait_burst[rmv]
        if burst.comp(wqe_id, ts) == 0:
            break
        rmv += 1
    # mode completed burst to done list
    if rmv != 0:
        idx = 0
        while idx < rmv:
            queue.done_burst.append(burst)
            idx += 1
        del queue.wait_burst[0:rmv]


def do_tx(msg):
    name = msg.event.name[PFX_TX_LEN:]
    if name == "entry":
        do_tx_entry(msg)
    elif name == "exit":
        do_tx_exit(msg)
    elif name == "wqe":
        do_tx_wqe(msg)
    elif name == "wait":
        do_tx_wait(msg)
    elif name == "push":
        do_tx_push(msg)
    elif name == "complete":
        do_tx_complete(msg)
    else:
        print("Error: unrecognized Tx event name: %s" % msg.event.name)
        sys.exit(1)


def do_log(msg_it):
    for msg in msg_it:
        if type(msg) is not bt2._EventMessageConst:
            continue
        event = msg.event
        if event.name.startswith(PFX_TX):
            do_tx(msg)
        # Handling of other log event cathegories can be added here


def do_print():
    for pq_id in tx_qlst:
        queue = tx_qlst.get(pq_id)
        queue.log()


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("path",
                        nargs = 1,
                        type = str,
                        help = "input trace folder")
    args = parser.parse_args()

    msg_it = bt2.TraceCollectionMessageIterator(args.path)
    do_log(msg_it)
    do_print()
    exit(0)

if __name__ == "__main__":
    main(sys.argv)

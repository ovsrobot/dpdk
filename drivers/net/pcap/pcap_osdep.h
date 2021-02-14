/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Dmitry Kozlyuk
 */

#ifndef _RTE_PCAP_OSDEP_
#define _RTE_PCAP_OSDEP_

#include <rte_ether.h>
#include <rte_time.h>

/*
 * Interface manipulation is always OS-specific.
 */

int osdep_iface_index_get(const char *name);
int osdep_iface_mac_get(const char *name, struct rte_ether_addr *mac);

/*
 * On Windows, libpcap (npcap or WinPcap) exposes Win32 API which clashes
 * with some DPDK constructs. Trivial libpcap wrappers with "osdep_" prefix
 * are provided to isolate PMD code from Win32 API.
 */

#define OSDEP_DLT_EN10MB 1

#define OSDEP_PCAP_ERRBUF_SIZE 256

#define OSDEP_PCAP_TSTAMP_PRECISION_NANO 1

/** Handle for an open packet capture. */
typedef struct osdep_pcap_type osdep_pcap;

/** Handle for an open packet dump. */
typedef struct osdep_pcap_dumper_type osdep_pcap_dumper;

struct osdep_pcap_pkthdr {
	struct rte_time_us ts;
	uint32_t caplen;
	uint32_t len;
};

enum osdep_pcap_direction {
	OSDEP_PCAP_D_INOUT = 0,
	OSDEP_PCAP_D_IN,
	OSDEP_PCAP_D_OUT
};

osdep_pcap *osdep_pcap_open_live(const char *device, int snaplen,
	int promisc, int to_ms, char *errbuf);
osdep_pcap *osdep_pcap_open_offline(const char *fname, char *errbuf);
osdep_pcap *osdep_pcap_open_dead_with_tstamp_precision(int linktype,
	int snaplen, unsigned int precision);
const uint8_t *osdep_pcap_next(osdep_pcap *pcap,
	struct osdep_pcap_pkthdr *header);
int osdep_pcap_sendpacket(osdep_pcap *pcap, const uint8_t *buf, int size);
void osdep_pcap_close(osdep_pcap *pcap);

osdep_pcap_dumper *osdep_pcap_dump_open(osdep_pcap *pcap, const char *fname);
void osdep_pcap_dump(uint8_t *user, const struct osdep_pcap_pkthdr *header,
	const uint8_t *sp);
int osdep_pcap_dump_flush(osdep_pcap_dumper *p);
void osdep_pcap_dump_close(osdep_pcap_dumper *p);

int osdep_pcap_setdirection(osdep_pcap *pcap, enum osdep_pcap_direction dir);
const char *osdep_pcap_geterr(osdep_pcap *pcap);

#endif

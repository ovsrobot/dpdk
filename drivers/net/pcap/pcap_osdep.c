/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Dmitry Kozlyuk
 */

#include <pcap.h>

#include <rte_common.h>

#include "pcap_osdep.h"

static inline void
to_osdep_header(const struct pcap_pkthdr *in, struct osdep_pcap_pkthdr *out)
{
	out->ts.sec = in->ts.tv_sec;
	out->ts.usec = in->ts.tv_usec;
	out->caplen = in->caplen;
	out->len = in->len;
}

static inline void
to_pcap_header(const struct osdep_pcap_pkthdr *in, struct pcap_pkthdr *out)
{
	out->ts.tv_sec = in->ts.sec;
	out->ts.tv_usec = in->ts.usec;
	out->caplen = in->caplen;
	out->len = in->len;
}

osdep_pcap *
osdep_pcap_open_live(const char *device, int snaplen,
	int promisc, int to_ms, char *errbuf)
{
	RTE_BUILD_BUG_ON(OSDEP_PCAP_ERRBUF_SIZE != PCAP_ERRBUF_SIZE);

	return (osdep_pcap *)pcap_open_live(device, snaplen, promisc, to_ms,
		errbuf);
}

osdep_pcap *
osdep_pcap_open_offline(const char *fname, char *errbuf)
{
	return (osdep_pcap *)pcap_open_offline(fname, errbuf);
}

osdep_pcap *
osdep_pcap_open_dead_with_tstamp_precision(int linktype, int snaplen,
	unsigned int precision)
{
	RTE_BUILD_BUG_ON(OSDEP_DLT_EN10MB != DLT_EN10MB);
	RTE_BUILD_BUG_ON(OSDEP_PCAP_TSTAMP_PRECISION_NANO !=
			PCAP_TSTAMP_PRECISION_NANO);

	return (osdep_pcap *)pcap_open_dead_with_tstamp_precision(linktype,
		snaplen, precision);
}

const uint8_t *
osdep_pcap_next(osdep_pcap *pcap, struct osdep_pcap_pkthdr *header)
{
	const uint8_t *data;
	struct pcap_pkthdr pkthdr;

	data = pcap_next((pcap_t *)pcap, &pkthdr);
	to_osdep_header(&pkthdr, header);
	return data;
}

int
osdep_pcap_sendpacket(osdep_pcap *pcap, const uint8_t *buf, int size)
{
	return pcap_sendpacket((pcap_t *)pcap, buf, size);
}

void
osdep_pcap_close(osdep_pcap *pcap)
{
	pcap_close((pcap_t *)pcap);
}

osdep_pcap_dumper *
osdep_pcap_dump_open(osdep_pcap *pcap, const char *fname)
{
	return (osdep_pcap_dumper *)pcap_dump_open((pcap_t *)pcap, fname);
}

void
osdep_pcap_dump(uint8_t *user, const struct osdep_pcap_pkthdr *header,
	const uint8_t *sp)
{
	struct pcap_pkthdr pkthdr;

	to_pcap_header(header, &pkthdr);
	pcap_dump(user, &pkthdr, sp);
}

int
osdep_pcap_dump_flush(osdep_pcap_dumper *p)
{
	return pcap_dump_flush((pcap_dumper_t *)p);
}

void
osdep_pcap_dump_close(osdep_pcap_dumper *p)
{
	pcap_dump_close((pcap_dumper_t *)p);
}

int
osdep_pcap_setdirection(osdep_pcap *pcap, enum osdep_pcap_direction dir)
{
	RTE_BUILD_BUG_ON((int)OSDEP_PCAP_D_INOUT != (int)PCAP_D_INOUT);
	RTE_BUILD_BUG_ON((int)OSDEP_PCAP_D_IN != (int)PCAP_D_IN);
	RTE_BUILD_BUG_ON((int)OSDEP_PCAP_D_OUT != (int)PCAP_D_OUT);

	return pcap_setdirection((pcap_t *)pcap, (pcap_direction_t)dir);
}

const char *
osdep_pcap_geterr(osdep_pcap *pcap)
{
	return pcap_geterr((pcap_t *)pcap);
}

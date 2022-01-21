/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include "rte_gen.h"

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_hexdump.h>
#include <rte_log.h>

#include <rte_ether.h>

RTE_LOG_REGISTER(gen_logtype, lib.gen, NOTICE);

#define GEN_LOG(level, fmt, args...)				\
	rte_log(RTE_LOG_ ## level, gen_logtype, "%s(): " fmt,	\
		__func__, ## args)

/* Don't prefix with function name, breaks the Scapy style formatting. */
#define GEN_LOG_PROTOCOL(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, gen_logtype, fmt, ## args)

#define GEN_MAX_BURST 32
#define GEN_INIT_PKT_SIZE 64

/** Structure that represents a traffic generator. */
struct rte_gen {
	/* Mempool that buffers are retrieved from. */
	struct rte_mempool *mp;

	/* Packet template to send. */
	struct rte_mbuf *base_pkt;
};

/* Allocate and initialize a traffic generator instance. */
struct rte_gen *
rte_gen_create(struct rte_mempool *mempool)
{
	struct rte_gen *gen = rte_zmalloc(NULL, sizeof(*gen), 0);
	if (gen == NULL)
		return NULL;

	gen->mp = mempool;

	uint8_t data[GEN_INIT_PKT_SIZE];
	memset(data, 0, GEN_INIT_PKT_SIZE);
	int32_t err = rte_gen_packet_set_raw(gen, data, GEN_INIT_PKT_SIZE);
	if (err) {
		GEN_LOG(ERR, "Failed to set initial packet\n");
		rte_free(gen);
		return NULL;
	}

	return gen;
}

/* Free a traffic generator instance. */
void
rte_gen_destroy(struct rte_gen *gen)
{
	rte_pktmbuf_free(gen->base_pkt);
	rte_free(gen);
}

int32_t
rte_gen_packet_set_raw(struct rte_gen *gen,
		       const uint8_t *raw_data,
		       uint32_t raw_data_size)
{

	struct rte_mbuf *new_pkt = rte_pktmbuf_alloc(gen->mp);
	if (!new_pkt) {
		GEN_LOG(ERR, "Failed to retireve mbuf for parser\n");
		return -ENOMEM;
	}

	uint8_t *base_data = rte_pktmbuf_mtod(new_pkt, uint8_t *);
	new_pkt->pkt_len = raw_data_size;
	new_pkt->data_len = raw_data_size;
	rte_memcpy(base_data, raw_data, raw_data_size);

	/* If old packet exists, free it. */
	struct rte_mbuf *old_pkt = gen->base_pkt;
	gen->base_pkt = new_pkt;

	if (old_pkt)
		rte_pktmbuf_free(old_pkt);

	return 0;
}

uint16_t
rte_gen_rx_burst(struct rte_gen *gen,
		 struct rte_mbuf **rx_pkts,
		 const uint16_t nb_pkts)
{
	/* Get a bulk of nb_pkts from the mempool. */
	int err = rte_mempool_get_bulk(gen->mp, (void **)rx_pkts, nb_pkts);
	if (err)
		return 0;

	if (!gen->base_pkt)
		return 0;

	const uint32_t base_size = gen->base_pkt->pkt_len;
	const uint8_t *base_data = rte_pktmbuf_mtod(gen->base_pkt, uint8_t *);

	uint32_t i;
	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *m = rx_pkts[i];
		uint8_t *pkt_data = rte_pktmbuf_mtod(m, uint8_t *);

		rte_memcpy(pkt_data, base_data, base_size);
		m->pkt_len = base_size;
		m->data_len = base_size;
	}

	return nb_pkts;
}

uint16_t
rte_gen_tx_burst(struct rte_gen *gen,
		 struct rte_mbuf **tx_pkts,
		 uint64_t *pkt_latencies,
		 const uint16_t nb_pkts)
{
	RTE_SET_USED(gen);
	RTE_SET_USED(pkt_latencies);

	rte_pktmbuf_free_bulk(tx_pkts, nb_pkts);

	return nb_pkts;
}

enum GEN_PROTO {
	GEN_PROTO_INVALID,
	GEN_PROTO_ETHER,

	/* Must be last. */
	GEN_PROTO_COUNT,
};

typedef void (*gen_log_func)(void *data, const char *indent);

/* Structure for holding offset and function pointers for protocol. */
struct protocol_meta {
	/* Byte offset into packet where this protocol starts. */
	uint32_t offset;
	/* Function to call to log the packet's information. */
	gen_log_func log_func;
};

/* Allow up to 32 nexted '/' characters in the protocol string. */
#define GEN_PROTO_PARSE_MAX 16

/* Structure to hold state required while parsing. */
struct gen_parser {
	/* Mbuf the parsed data is being put into. */
	struct rte_mbuf *mbuf;
	uint8_t *mbuf_data;

	/* Offset into the packet data to parse to next. */
	uint32_t buf_write_offset;

	/* Parsing state. */
	uint8_t parse_iter;
	char indent_str[(GEN_PROTO_PARSE_MAX * 2) + 1];

	/* String being parsed. */
	char *parse_string;
	char *parse_strtok_save_ptr;

	/* Store metadata for parse/display of protocols.  */
	struct protocol_meta proto_meta[GEN_PROTO_PARSE_MAX];

	/* Per protocol hit counters. */
	uint32_t proto_hit_counters[GEN_PROTO_COUNT];
};

/* Forward declaration of recursive parsing function.
 * @param inner reports back the inner protocol that was handled. This is often
 * required for the outer protocol to indicate what the inner protocol is.
 */
static int32_t
gen_parser_parse_next(struct gen_parser *parser, enum GEN_PROTO *inner);

/* Return void pointer to the position in the data buffer to parse into. */
static inline void *
gen_parser_get_data_ptr(struct gen_parser *parser)
{
	return &parser->mbuf_data[parser->buf_write_offset];
}

/* Initialize a parser structure. */
static int32_t
gen_parser_init(struct gen_parser *parser, struct rte_gen *gen,
		const char *pkt_string)
{
	/* Initialize own memory to zero. */
	memset(parser, 0, sizeof(*parser));

	/* Duplicate string for tokenizing string. */
	parser->parse_string = strdup(pkt_string);
	if (!parser->parse_string)
		goto error;

	/* Allocate mbuf to parse packet into. */
	parser->mbuf = rte_pktmbuf_alloc(gen->mp);
	if (!parser->mbuf)
		goto error;

	parser->mbuf_data = rte_pktmbuf_mtod(parser->mbuf, uint8_t *);

	return 0;

error:
	free(parser->parse_string);
	return -ENOMEM;
}

static void
gen_log_ether(void *data, const char *indent)
{
	struct rte_ether_hdr *eth = data;
	char src[64];
	char dst[64];

	rte_ether_format_addr(src, 64, &eth->src_addr);
	rte_ether_format_addr(dst, 64, &eth->dst_addr);
	const char *type_str;
	switch (rte_be_to_cpu_16(eth->ether_type)) {
	case RTE_ETHER_TYPE_IPV4:
		type_str = "IPv4";
		break;
	default:
		type_str = "0x9000";
		break;
	};
	GEN_LOG_PROTOCOL(DEBUG,
		"###[ Ethernet ]###\n%sdst= %s\n%ssrc= %s\n%stype= %s\n",
		indent, dst, indent, src, indent, type_str);
}

/* Ether(...) string detected, supports parameters:
 * - dst : Destination MAC in 00:11:22:33:44:55 or 0011:2233:4455 forms.
 * - src : Source MAC in the same forms.
 * Note:
 * - type is set based on the next header
 */
static int32_t
gen_parse_ether(struct gen_parser *parser, char *protocol_str)
{
	struct rte_ether_hdr *eth = gen_parser_get_data_ptr(parser);

	char *dst_ptr = strstr(protocol_str, "dst=");
	if (dst_ptr) {
		char *dup = strdup(dst_ptr);
		rte_ether_unformat_addr(&dup[4], &eth->dst_addr);
		free(dup);
	} else
		rte_ether_unformat_addr("ff:ff:ff:ff:ff:ff", &eth->dst_addr);

	char *src_ptr = strstr(protocol_str, "src=");
	if (src_ptr)
		rte_ether_unformat_addr(&src_ptr[4], &eth->src_addr);
	else
		rte_ether_unformat_addr("00:00:00:00:00:00", &eth->src_addr);

	/* Move up write pointer in packet. */
	parser->buf_write_offset += sizeof(*eth);

	/* Recurse and handle inner protocol. */
	enum GEN_PROTO inner;
	int32_t err = gen_parser_parse_next(parser, &inner);
	if (err) {
		GEN_LOG(ERR, "parser parse next() error %d\n", err);
		return err;
	}

	switch (inner) {
	default:
		eth->ether_type = rte_cpu_to_be_16(0x9000);
		break;
	};
	return 0;
}

/* (Name, Function-pointer) pairs for supported parse types */
typedef int32_t (*gen_parse_func)(struct gen_parser *parser,
				char *protocol_str);

struct gen_parse_func_t {
	const char *name;
	enum GEN_PROTO proto;
	gen_parse_func parse_func;
	gen_log_func log_func;
};

/* Mapping from string to function to parse that protocol. */
static struct gen_parse_func_t gen_protocols[] = {
	{
		.name = "Ether(",
		.proto = GEN_PROTO_ETHER,
		.parse_func = gen_parse_ether,
		.log_func = gen_log_ether,
	}
};

/* Function to tokenize and parse each segment of a string.
 * @param outer indicates the protocol before this one.
 * @param inner returns the protocol that is parsed here/now.
 */
static int32_t
gen_parser_parse_next(struct gen_parser *parser,
			enum GEN_PROTO *inner_proto)
{
	/* Tokenize the input string based on '/' character. */
	char *tok_str = (parser->parse_iter == 0) ?
					parser->parse_string : NULL;
	parser->parse_string = strtok_r(tok_str, "/",
					&parser->parse_strtok_save_ptr);

	/* End protocol parsing recursion when parse_string is NULL, or max
	 * protocol recursion depth is reached.
	 */
	if (!parser->parse_string ||
			parser->parse_iter >= GEN_PROTO_PARSE_MAX) {
		struct rte_mbuf *mbuf = parser->mbuf;
		mbuf->data_len = parser->buf_write_offset;
		mbuf->pkt_len = parser->buf_write_offset;
		GEN_LOG(DEBUG, "packet length %d\n", mbuf->pkt_len);
		return 0;
	}

	uint32_t i;
	/* Loop over protocols, and identify the parse function to call. */
	for (i = 0; i < RTE_DIM(gen_protocols); i++) {
		const char *proto = gen_protocols[i].name;
		uint32_t proto_len = strlen(proto);
		if (strncmp(proto, parser->parse_string, proto_len))
			continue;

		/* Store the log function pointer to output later. */
		uint32_t iter = parser->parse_iter;
		parser->proto_hit_counters[i]++;
		struct protocol_meta *meta = &parser->proto_meta[iter];

		if (gen_protocols[i].log_func == NULL) {
			GEN_LOG(ERR, "Missing log function, failed to log %s\n",
									proto);
			return -1;
		}
		meta->log_func = gen_protocols[i].log_func;
		meta->offset = parser->buf_write_offset;

		if (gen_protocols[i].parse_func == NULL) {
			GEN_LOG(ERR, "Missing parse function, failed to parse %s\n"
								, proto);
			return -1;
		}
		/* Handle protocol recursively. */
		parser->parse_iter++;
		int err = gen_protocols[i].parse_func(parser,
							parser->parse_string);
		*inner_proto = gen_protocols[i].proto;

		return err;
	}

	GEN_LOG(ERR, "parser does not understand protocol %s\n",
		parser->parse_string);
	return -1;
}

int32_t
rte_gen_packet_parse_string(struct rte_gen *gen,
			    const char *pkt_string,
			    struct rte_mbuf **old_mbuf_to_user)
{
	struct gen_parser parser;
	int32_t err = gen_parser_init(&parser, gen, pkt_string);
	if (err) {
		GEN_LOG(ERR, "error with parser_init(), %d\n", err);
		return -1;
	};

	/* Recursively parse each protocol. */
	enum GEN_PROTO inner;
	err = gen_parser_parse_next(&parser, &inner);
	if (err) {
		GEN_LOG(ERR, "Error in parsing packet string. "
			"Set \"gen\" log level to debug for more info.\n");
		rte_pktmbuf_free(parser.mbuf);
		return -1;
	}

	uint32_t i;
	/* Iterate the per protocol stored metadata to log output. */
	for (i = 0; i < parser.parse_iter; i++) {
		snprintf(parser.indent_str, 2 + i * 2,
			"                               " /* 32 spaces. */);

		if (gen_protocols[i].log_func == NULL) {
			GEN_LOG(ERR, "Missing log function\n");
			return -1;
		}

		void *buf_off = parser.mbuf_data + parser.proto_meta[i].offset;
		parser.proto_meta[i].log_func(buf_off, parser.indent_str);
	}

	if (inner != GEN_PROTO_ETHER) {
		GEN_LOG(WARNING,
			"Outer protocol of frame is not Ethernet.\n");
	}

	/* Free the currently in use mbuf. */
	if (old_mbuf_to_user)
		*old_mbuf_to_user = gen->base_pkt;
	else
		rte_pktmbuf_free(gen->base_pkt);

	/* TODO: HVH design race-condition above vs rx/tx*/
	gen->base_pkt = parser.mbuf;
	return 0;
}

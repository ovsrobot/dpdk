#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include <rte_version.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_vxlan.h>
#include <rte_gre.h>
#ifdef RTE_ARCH_ARM64
#include <rte_cpuflags_64.h>
#elif defined(RTE_ARCH_ARM)
#include <rte_cpuflags_32.h>
#endif

#include "base/rnp_hw.h"
#include "rnp.h"
#include "rnp_rxtx.h"
#include "rnp_logs.h"

int
rnp_dev_rx_descriptor_status(void *rx_queue, uint16_t offset)
{
	RTE_SET_USED(rx_queue);
	RTE_SET_USED(offset);

	return 0;
}

int
rnp_dev_tx_descriptor_status(void *tx_queue, uint16_t offset)
{
	RTE_SET_USED(tx_queue);
	RTE_SET_USED(offset);

	return 0;
}

uint32_t
rnp_dev_rx_queue_count(void *rx_queue)
{
	RTE_SET_USED(rx_queue);

	return 0;
}

__rte_always_inline uint16_t
rnp_recv_pkts(void *_rxq,
	      struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	RTE_SET_USED(_rxq);
	RTE_SET_USED(rx_pkts);
	RTE_SET_USED(nb_pkts);

	return 0;
}

__rte_always_inline uint16_t
rnp_xmit_pkts(void *_txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	RTE_SET_USED(_txq);
	RTE_SET_USED(tx_pkts);
	RTE_SET_USED(nb_pkts);

	return 0;
}

uint16_t rnp_prep_pkts(void *tx_queue,
		       struct rte_mbuf **tx_pkts,
		       uint16_t nb_pkts)
{
	RTE_SET_USED(tx_queue);
	RTE_SET_USED(tx_pkts);
	RTE_SET_USED(nb_pkts);

	return 0;
}

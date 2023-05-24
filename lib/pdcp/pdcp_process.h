/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#ifndef PDCP_PROCESS_H
#define PDCP_PROCESS_H

#include <rte_pdcp.h>

#include <pdcp_entity.h>
#include <pdcp_cnt.h>

int
pdcp_process_func_set(struct rte_pdcp_entity *entity, const struct rte_pdcp_entity_conf *conf);

static inline void
pdcp_rx_deliv_set(const struct rte_pdcp_entity *entity, uint32_t rx_deliv)
{
	struct entity_priv_dl_part *dl = entity_dl_part_get(entity);
	struct entity_priv *en_priv = entity_priv_get(entity);

	pdcp_cnt_bitmap_range_clear(dl->bitmap, en_priv->state.rx_deliv, rx_deliv);
	en_priv->state.rx_deliv = rx_deliv;
}

#endif /* PDCP_PROCESS_H */

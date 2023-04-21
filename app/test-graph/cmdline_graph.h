/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#ifndef _CMDLINE_GRAPH_H_
#define _CMDLINE_GRAPH_H_

extern cmdline_parse_inst_t cmd_show_node_list;
extern cmdline_parse_inst_t cmd_set_lcore_config;

extern cmdline_parse_inst_t cmd_create_graph;
extern cmdline_parse_inst_t cmd_destroy_graph;

extern cmdline_parse_inst_t cmd_start_graph_walk;
extern cmdline_parse_inst_t cmd_stop_graph_walk;

extern cmdline_parse_inst_t cmd_show_graph_stats;

#endif /* _CMDLINE_GRAPH_H_ */

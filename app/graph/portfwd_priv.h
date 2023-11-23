/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef APP_GRAPH_PORTFWD_PRIV_H
#define APP_GRAPH_PORTFWD_PRIV_H

struct ethdev_fwd_cmd_tokens {
	cmdline_fixed_string_t cmd;
	cmdline_fixed_string_t fwd;
	cmdline_fixed_string_t tx_dev;
	cmdline_fixed_string_t rx_dev;
};
#endif

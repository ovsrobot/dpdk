/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_debug.h>

#include "commands.h"


int main(int argc, char **argv)
{
	struct cmdline *cl;
	int eal_init_ret;
	int ret;

	eal_init_ret = rte_eal_init(argc, argv);
	ret = opae_init(eal_init_ret);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	cl = cmdline_stdin_new(main_ctx, "opae> ");
	if (cl == NULL)
		rte_panic("Cannot create cmdline instance\n");
	cmdline_interact(cl);
	opae_cleanup();
	rte_eal_cleanup();
	cmdline_stdin_exit(cl);
	return 0;
}

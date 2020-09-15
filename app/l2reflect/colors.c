/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 */

#include "colors.h"

const struct color_palette *colors;

static const struct color_palette color_palette_default = {
	.red = "\x1b[01;31m",
	.green = "\x1b[01;32m",
	.yellow = "\x1b[01;33m",
	.blue = "\x1b[01;34m",
	.magenta = "\x1b[01;35m",
	.cyan = "\x1b[01;36m",
	.reset = "\x1b[0m"
};

static const struct color_palette color_palette_bw = { .red = "",
						       .green = "",
						       .yellow = "",
						       .blue = "",
						       .magenta = "",
						       .cyan = "",
						       .reset = "" };

void
enable_colors(int enable)
{
	if (enable)
		colors = &color_palette_default;
	else
		colors = &color_palette_bw;
}

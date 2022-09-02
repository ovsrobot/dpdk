/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 */
#ifndef _L2REFLECT_COLORS_H_
#define _L2REFLECT_COLORS_H_

/* posix terminal colors */
struct color_palette {
	const char *red, *green, *yellow, *blue, *magenta, *cyan, *reset;
};

/* ptr to the current tui color palette */
extern const struct color_palette *colors;

/* disable colored output */
void
enable_colors(int enable);

#endif /* _L2REFLECT_COLORS_H_ */

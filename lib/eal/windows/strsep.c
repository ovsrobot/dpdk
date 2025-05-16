/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 1990, 1993
 * The Regents of the University of California.  All rights reserved.
 */

#include <string.h>

#include "strsep.h"

/* Get next token from string *stringp, where tokens are possibly empty
 * strings separated by characters from delim.
 *
 * Writes NULLs into the string at *stringp to end tokens.
 * delim need not remain constant from call to call.
 * On return, *stringp points past the last NULL written (if there might
 * be further tokens), or is NULL (if there are definitely no more tokens).
 *
 * If *stringp is NULL, strsep returns NULL.
 */
char *
strsep(char **stringp, const char *delim)
{
	char *s;
	const char *spanp;
	int c, sc;
	char *tok;

	s = *stringp;
	if (s == NULL)
		return NULL;
	for (tok = s;;) {
		c = *s++;
		spanp = delim;
		do {
			sc = *spanp++;
			if (sc == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return tok;
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}

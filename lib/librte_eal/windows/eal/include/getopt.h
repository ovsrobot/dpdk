/* musl as a whole is licensed under the following standard MIT license:
 *
 * ----------------------------------------------------------------------
 * Copyright (c) 2005-2014 Rich Felker, et al.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _GETOPT_H
#define _GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

int getopt(int, char * const [], const char *);
extern char *optarg;
extern int optind, opterr, optopt, optreset;

struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};

void __getopt_msg(const char *a, const char *b, const char *c, size_t l);

int getopt_long(int argc, char **argv, const char *optstring,
	const struct option *longopts, int *idx);
int getopt_long_only(int argc, char **argv, const char *optstring,
	const struct option *longopts, int *idx);

#define no_argument        0
#define required_argument  1
#define optional_argument  2

#ifdef __cplusplus
}
#endif

#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/time.h>

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "test_cryptodev_asym_creator.h"

int atv_create_data(uint8_t *data, int len)
{
	struct timespec ts;
	struct timeval tv;
	int i;

	ts.tv_sec = 0;
	ts.tv_nsec = 10000000;
	nanosleep(&ts, NULL);

	gettimeofday(&tv, NULL);
	int seed = 1000000 * tv.tv_sec + tv.tv_usec;

	srand(seed);

	memset(data, 0, len);

	int *dt = (int *) data;
	int ln = len / sizeof(int);

	for (i = 0; i < ln; i++)
		dt[i] = rand();

	return 0;
}


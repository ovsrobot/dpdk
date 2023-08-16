/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTCONNECT_TEST_FILTER_H_
#define _NTCONNECT_TEST_FILTER_H_

/*
 * Create structures allocating the space to carry through ntconnect interface
 */

struct test_s {
	int number;
	int status;
	uint64_t test[];
};

#endif /* _NTCONNECT_TEST_FILTER_H_ */

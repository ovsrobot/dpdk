/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>

#include "test_cryptodev_asym_vectors.h"
#include "test_cryptodev_asym_rsa_creator.h"
#include "test_cryptodev_asym_vectors_rules.h"

void atv_free(void *vct)
{
	free(vct);
}

struct asym_test_rsa_vct *atv_rsa(int *vct_nb)
{
	struct asym_test_rsa_vct *vct = NULL;
	int i;

	*vct_nb = asym_test_rsa_rules_size;

	vct = calloc(*vct_nb, sizeof(struct asym_test_rsa_vct));

	if (vct)
		for (i = 0; i < *vct_nb; i++)
			atv_rsa_creator(&vct[i], &asym_test_rsa_rules[i]);

	return vct;
}

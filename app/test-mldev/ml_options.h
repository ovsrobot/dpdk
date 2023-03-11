/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#ifndef _ML_OPTIONS_
#define _ML_OPTIONS_

#include <stdbool.h>
#include <stdint.h>

#define ML_TEST_NAME_MAX_LEN 32
#define ML_TEST_MAX_MODELS   8

/* Options names */
#define ML_TEST	       ("test")
#define ML_DEVICE_ID   ("dev_id")
#define ML_SOCKET_ID   ("socket_id")
#define ML_MODELS      ("models")
#define ML_FILELIST    ("filelist")
#define ML_REPETITIONS ("repetitions")
#define ML_DEBUG       ("debug")
#define ML_HELP	       ("help")

struct ml_filelist {
	char model[PATH_MAX];
	char input[PATH_MAX];
	char output[PATH_MAX];
};

struct ml_options {
	char test_name[ML_TEST_NAME_MAX_LEN];
	int16_t dev_id;
	int socket_id;
	struct ml_filelist filelist[ML_TEST_MAX_MODELS];
	uint8_t nb_filelist;
	uint64_t repetitions;
	bool debug;
};

void ml_options_default(struct ml_options *opt);
int ml_options_parse(struct ml_options *opt, int argc, char **argv);
void ml_options_dump(struct ml_options *opt);

#endif /* _ML_OPTIONS_ */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Intel Corporation
 */

#include <glob.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <limits.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_telemetry.h>
#include <rte_string_fns.h>

#include "test.h"
#include "telemetry_data.h"

#define TELEMETRY_VERSION "v2"
#define REQUEST_CMD "/test"
#define BUF_SIZE 1024
#define TEST_OUTPUT(exp) test_output(__func__, exp)

static struct rte_tel_data response_data;
static int sock;

static int
test_cb(const char *cmd __rte_unused, const char *params __rte_unused,
		struct rte_tel_data *d)
{
	*d = response_data;
	return 0;
}

static int
test_output(const char *func_name, const char *expected)
{
	int bytes;
	char buf[BUF_SIZE * 16];
	if (write(sock, REQUEST_CMD, strlen(REQUEST_CMD)) < 0) {
		printf("%s: Error with socket write - %s\n", __func__,
				strerror(errno));
		return -1;
	}
	bytes = read(sock, buf, sizeof(buf));
	if (bytes < 0) {
		printf("%s: Error with socket read - %s\n", __func__,
				strerror(errno));
		return -1;
	}
	buf[bytes] = '\0';
	printf("%s: buf = '%s', expected = '%s'\n", func_name, buf, expected);
	return strncmp(expected, buf, sizeof(buf));
}

static int
test_dict_with_array_int_values(void)
{
	int i;

	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_INT_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_INT_VAL);

	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_dict(&response_data);

	for (i = 0; i < 5; i++) {
		rte_tel_data_add_array_int(child_data, i);
		rte_tel_data_add_array_int(child_data2, i);
	}

	rte_tel_data_add_dict_container(&response_data, "dict_0",
	 child_data, 0);
	rte_tel_data_add_dict_container(&response_data, "dict_1",
	 child_data2, 0);

	return TEST_OUTPUT("{\"/test\":{\"dict_0\":[0,1,2,3,4],\"dict_1\":[0,1,2,3,4]}}");
}

static int
test_array_with_array_int_values(void)
{
	int i;

	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_INT_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_INT_VAL);

	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_array(&response_data, RTE_TEL_CONTAINER);

	for (i = 0; i < 5; i++) {
		rte_tel_data_add_array_int(child_data, i);
		rte_tel_data_add_array_int(child_data2, i);
	}
	rte_tel_data_add_array_container(&response_data, child_data, 0);
	rte_tel_data_add_array_container(&response_data, child_data2, 0);

	return TEST_OUTPUT("{\"/test\":[[0,1,2,3,4],[0,1,2,3,4]]}");
}

static int
test_case_array_int(void)
{
	int i;
	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_array(&response_data, RTE_TEL_INT_VAL);
	for (i = 0; i < 5; i++)
		rte_tel_data_add_array_int(&response_data, i);
	return TEST_OUTPUT("{\"/test\":[0,1,2,3,4]}");
}

static int
test_case_add_dict_int(void)
{
	int i = 0;
	char name_of_value[8];

	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_dict(&response_data);

	for (i = 0; i < 5; i++) {
		sprintf(name_of_value, "dict_%d", i);
		rte_tel_data_add_dict_int(&response_data, name_of_value, i);
	}

	return TEST_OUTPUT("{\"/test\":{\"dict_0\":0,\"dict_1\":1,\"dict_2\":2,\"dict_3\":3,\"dict_4\":4}}");
}

static int
test_case_array_string(void)
{
	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_array(&response_data, RTE_TEL_STRING_VAL);
	rte_tel_data_add_array_string(&response_data, "aaaa");
	rte_tel_data_add_array_string(&response_data, "bbbb");
	rte_tel_data_add_array_string(&response_data, "cccc");
	rte_tel_data_add_array_string(&response_data, "dddd");
	rte_tel_data_add_array_string(&response_data, "eeee");

	return TEST_OUTPUT("{\"/test\":[\"aaaa\",\"bbbb\",\"cccc\",\"dddd\",\"eeee\"]}");
}

static int
test_case_add_dict_string(void)
{
	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_dict(&response_data);

	rte_tel_data_add_dict_string(&response_data, "dict_0", "aaaa");
	rte_tel_data_add_dict_string(&response_data, "dict_1", "bbbb");
	rte_tel_data_add_dict_string(&response_data, "dict_2", "cccc");
	rte_tel_data_add_dict_string(&response_data, "dict_3", "dddd");

	return TEST_OUTPUT("{\"/test\":{\"dict_0\":\"aaaa\",\"dict_1\":\"bbbb\",\"dict_2\":\"cccc\",\"dict_3\":\"dddd\"}}");
}


static int
test_dict_with_array_string_values(void)
{
	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_STRING_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_STRING_VAL);

	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_dict(&response_data);

	rte_tel_data_add_array_string(child_data, "aaaa");
	rte_tel_data_add_array_string(child_data2, "bbbb");

	rte_tel_data_add_dict_container(&response_data, "dict_0",
	 child_data, 0);
	rte_tel_data_add_dict_container(&response_data, "dict_1",
	 child_data2, 0);

	return TEST_OUTPUT("{\"/test\":{\"dict_0\":[\"aaaa\"],\"dict_1\":[\"bbbb\"]}}");
}

static int
test_array_with_array_string_values(void)
{
	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_STRING_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_STRING_VAL);

	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_array(&response_data, RTE_TEL_CONTAINER);

	rte_tel_data_add_array_string(child_data, "aaaa");
	rte_tel_data_add_array_string(child_data2, "bbbb");

	rte_tel_data_add_array_container(&response_data, child_data, 0);
	rte_tel_data_add_array_container(&response_data, child_data2, 0);

	return TEST_OUTPUT("{\"/test\":[[\"aaaa\"],[\"bbbb\"]]}");
}

static int
test_case_array_u64(void)
{
	int i;
	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_array(&response_data, RTE_TEL_U64_VAL);
	for (i = 0; i < 5; i++)
		rte_tel_data_add_array_u64(&response_data, i);
	return TEST_OUTPUT("{\"/test\":[0,1,2,3,4]}");
}

static int
test_case_add_dict_u64(void)
{
	int i = 0;
	char name_of_value[8];

	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_dict(&response_data);

	for (i = 0; i < 5; i++) {
		sprintf(name_of_value, "dict_%d", i);
		rte_tel_data_add_dict_u64(&response_data, name_of_value, i);
	}
	return TEST_OUTPUT("{\"/test\":{\"dict_0\":0,\"dict_1\":1,\"dict_2\":2,\"dict_3\":3,\"dict_4\":4}}");
}

static int
test_dict_with_array_u64_values(void)
{
	int i;

	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_U64_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_U64_VAL);

	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_dict(&response_data);

	for (i = 0; i < 10; i++) {
		rte_tel_data_add_array_u64(child_data, i);
		rte_tel_data_add_array_u64(child_data2, i);
	}

	rte_tel_data_add_dict_container(&response_data, "dict_0",
	 child_data, 0);
	rte_tel_data_add_dict_container(&response_data, "dict_1",
	 child_data2, 0);

	return TEST_OUTPUT("{\"/test\":{\"dict_0\":[0,1,2,3,4,5,6,7,8,9],\"dict_1\":[0,1,2,3,4,5,6,7,8,9]}}");
}

static int
test_array_with_array_u64_values(void)
{
	int i;

	struct rte_tel_data *child_data = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data, RTE_TEL_U64_VAL);

	struct rte_tel_data *child_data2 = rte_tel_data_alloc();
	rte_tel_data_start_array(child_data2, RTE_TEL_U64_VAL);

	memset(&response_data, 0, sizeof(response_data));
	rte_tel_data_start_array(&response_data, RTE_TEL_CONTAINER);

	for (i = 0; i < 5; i++) {
		rte_tel_data_add_array_u64(child_data, i);
		rte_tel_data_add_array_u64(child_data2, i);
	}
	rte_tel_data_add_array_container(&response_data, child_data, 0);
	rte_tel_data_add_array_container(&response_data, child_data2, 0);

	return TEST_OUTPUT("{\"/test\":[[0,1,2,3,4],[0,1,2,3,4]]}");
}

static int
connect_to_socket(void)
{
	char file_pattern[PATH_MAX];
	char buf[BUF_SIZE];
	glob_t globbuf;
	int sock, bytes;
	struct sockaddr_un telem_addr;

	snprintf(file_pattern, sizeof(file_pattern),
			"%s/dpdk_telemetry.%s",	rte_eal_get_runtime_dir(),
			TELEMETRY_VERSION);
	if (glob(file_pattern, 0, NULL, &globbuf) != 0) {
		printf("\n%s: Error finding socket file path: %s\n", __func__,
				strerror(errno));
		globfree(&globbuf);
		return -1;
	}

	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		printf("\n%s: Error creating socket: %s\n", __func__,
				strerror(errno));
		return -1;
	}
	telem_addr.sun_family = AF_UNIX;
	strlcpy(telem_addr.sun_path, globbuf.gl_pathv[0],
			sizeof(telem_addr.sun_path));
	if (connect(sock, &telem_addr, sizeof(telem_addr)) < 0)
		printf("\n%s: Error connecting to socket: %s\n", __func__,
				strerror(errno));

	bytes = read(sock, buf, sizeof(buf));
	if (bytes < 0) {
		printf("%s: Error with socket read - %s\n", __func__,
				strerror(errno));
		return -1;
	}
	buf[bytes] = '\0';
	printf("\n%s: %s\n", __func__, buf);
	globfree(&globbuf);
	return sock;
}

static int
test_telemetry_data(void)
{
	sock = connect_to_socket();
	if (sock <= 0)
		return -1;

	rte_telemetry_register_cmd(REQUEST_CMD, test_cb, "Test");
	if (test_case_array_string() != 0
	|| test_case_array_int() != 0
	|| test_case_array_u64() != 0
	|| test_case_add_dict_int() != 0
	|| test_case_add_dict_u64() != 0
	|| test_case_add_dict_string() != 0
	||  test_dict_with_array_int_values() != 0
	|| test_dict_with_array_u64_values() != 0
	|| test_dict_with_array_string_values() != 0
	|| test_array_with_array_int_values() != 0
	|| test_array_with_array_u64_values() != 0
	|| test_array_with_array_string_values() != 0) {
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

REGISTER_TEST_COMMAND(telemetry_data_autotest, test_telemetry_data);

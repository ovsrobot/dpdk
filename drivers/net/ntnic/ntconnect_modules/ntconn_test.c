/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <errno.h>
#include "ntnic_ethdev.h"
#include "ntconnect.h"
#include "ntos_system.h"
#include "ntconn_modules.h"
#include "ntconn_mod_helper.h"
#include "nt_util.h"
#include "ntlog.h"
#include "ntnic_vf_vdpa.h"

#include "ntconnect_api_test.h"

#define NTCONN_TEST_VERSION_MAJOR 0U
#define NTCONN_TEST_VERSION_MINOR 1U

#define this_module_name "ntconnect_test"

#define MAX_CLIENTS 32

#define UNUSED __rte_unused

static struct test_hdl_s {
	struct drv_s *drv;
} test_hdl[MAX_CLIENTS];

/*
 * Test functions
 */
static int func_test(void *hdl, int client_id, struct ntconn_header_s *hdr,
		     char **data, int *len);
static struct func_s adapter_entry_funcs[] = {
	{ "test", NULL, func_test },
	{ NULL, NULL, NULL },
};

static int func_test(void *hdl _unused, int client_id _unused,
		     struct ntconn_header_s *hdr, char **data, int *len)
{
	int status = 0;
	int number = 0;
	uint32_t size;
	struct test_s *test_cpy = (struct test_s *)&(*data)[hdr->len];

	if (hdr->blob_len < sizeof(struct test_s)) {
		NT_LOG(ERR, NTCONNECT, "Error in test data: to small");
		status = -1;
		goto TEST_ERROR;
	}

	number = test_cpy->number;
	size = sizeof(struct test_s) + sizeof(uint64_t) * number;

	if (hdr->blob_len != size) {
		NT_LOG(ERR, NTCONNECT, "Error in test data: wrong size");
		status = -1;
		goto TEST_ERROR;
	}

	{
		*data = malloc(sizeof(struct test_s) +
			       number * sizeof(uint64_t));
		if (!*data)
			goto TEST_ERROR_MALLOC;
		struct test_s *return_value = (struct test_s *)*data;
		*len = sizeof(struct test_s) + number * sizeof(uint64_t);
		for (int i = 0; i < number; i++)
			return_value->test[i] = test_cpy->test[i];
		return_value->status = 0;
		return_value->number = number;
		return REQUEST_OK;
	}

TEST_ERROR:

	{
		*data = malloc(sizeof(struct test_s));
		if (!*data)
			goto TEST_ERROR_MALLOC;
		struct test_s *return_value = (struct test_s *)*data;
		*len = sizeof(struct test_s);
		return_value->status = status;
		return_value->number = 0;
		return REQUEST_OK;
	}

TEST_ERROR_MALLOC:

	*len = 0;
	NT_LOG(ERR, NTCONNECT, "Not able to allocate memory %s", __func__);
	return REQUEST_ERR;
}

enum {
	FLOW_API_FUNC_CREATE,
	FLOW_API_FUNC_VALIDATE,
};

static int test_request(void *hdl, int client_id _unused,
			struct ntconn_header_s *hdr, char *function,
			char **data, int *len)
{
	return execute_function(this_module_name, hdl, client_id, hdr, function,
				adapter_entry_funcs, data, len, 0);
}

static void test_free_data(void *hdl _unused, char *data)
{
	if (data)
		free(data);
}

static void test_client_cleanup(void *hdl _unused, int client_id _unused)
{
	/* Nothing to do */
}

static const ntconnapi_t ntconn_test_op = { this_module_name,
					    NTCONN_TEST_VERSION_MAJOR,
					    NTCONN_TEST_VERSION_MINOR,
					    test_request,
					    test_free_data,
					    test_client_cleanup
					  };

int ntconn_test_register(struct drv_s *drv)
{
	int i;

	for (i = 0; i < MAX_CLIENTS; i++) {
		if (test_hdl[i].drv == NULL)
			break;
	}
	if (i == MAX_CLIENTS) {
		NT_LOG(ERR, NTCONNECT,
		       "Cannot register more adapters into NtConnect framework");
		return -1;
	}

	test_hdl[i].drv = drv;
	return register_ntconn_mod(&drv->p_dev->addr, (void *)&test_hdl[i],
				   &ntconn_test_op);
}

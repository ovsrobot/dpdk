/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Wind River Systems, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <rte_cfgfile.h>

#include "test.h"

#include "test_cfgfiles.h"

static int
test_cfgfile_init(char *filename, const char *data)
{
	size_t len = strlen(data);
	int fd;

	fd = mkstemps(filename, strlen(".ini"));
	if (fd < 0)
		return fd;

	if (write(fd, data, len) != (int)len) {
		close(fd);
		return -1;
	}
	return fd;
}


static int
_test_cfgfile_sample(struct rte_cfgfile *cfgfile)
{
	const char *value;
	int ret;

	ret = rte_cfgfile_num_sections(cfgfile, NULL, 0);
	TEST_ASSERT(ret == 2, "Unexpected number of sections: %d", ret);

	ret = rte_cfgfile_has_section(cfgfile, "section1");
	TEST_ASSERT(ret, "section1 section missing");

	ret = rte_cfgfile_section_num_entries(cfgfile, "section1");
	TEST_ASSERT(ret == 1, "section1 unexpected number of entries: %d", ret);

	value = rte_cfgfile_get_entry(cfgfile, "section1", "key1");
	TEST_ASSERT(strcmp("value1", value) == 0,
		    "key1 unexpected value: %s", value);

	ret = rte_cfgfile_has_section(cfgfile, "section2");
	TEST_ASSERT(ret, "section2 section missing");

	ret = rte_cfgfile_section_num_entries(cfgfile, "section2");
	TEST_ASSERT(ret == 2, "section2 unexpected number of entries: %d", ret);

	value = rte_cfgfile_get_entry(cfgfile, "section2", "key2");
	TEST_ASSERT(strcmp("value2", value) == 0,
		    "key2 unexpected value: %s", value);

	value = rte_cfgfile_get_entry(cfgfile, "section2", "key3");
	TEST_ASSERT(strcmp("value3", value) == 0,
		    "key3 unexpected value: %s", value);

	return 0;
}

static int
test_cfgfile_sample1(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[] = "/tmp/cfg_sample1_XXXXXX.ini";
	int fd, ret;

	fd = test_cfgfile_init(filename, sample1_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	close(fd);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to load config file");

	ret = _test_cfgfile_sample(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to validate sample file: %d", ret);

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	unlink(filename);

	return 0;
}

static int
test_cfgfile_sample2(void)
{
	struct rte_cfgfile_parameters params;
	struct rte_cfgfile *cfgfile;
	char filename[] = "/tmp/cfgile_sample2_XXXXXX.ini";
	int fd, ret;

	fd = test_cfgfile_init(filename, sample2_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	/* override comment character */
	memset(&params, 0, sizeof(params));
	params.comment_character = '#';

	cfgfile = rte_cfgfile_load_with_params(filename, 0, &params);
	close(fd);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to parse sample2.ini");

	ret = _test_cfgfile_sample(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to validate sample file: %d", ret);

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	unlink(filename);

	return 0;
}

static int
test_cfgfile_realloc_sections(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[] = "/tmp/cfg_realloc_XXXXXX.ini";
	int fd, ret;
	const char *value;

	fd = test_cfgfile_init(filename, realloc_sections_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	close(fd);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to load config file");

	ret = rte_cfgfile_num_sections(cfgfile, NULL, 0);
	TEST_ASSERT(ret == 9, "Unexpected number of sections: %d", ret);

	ret = rte_cfgfile_has_section(cfgfile, "section9");
	TEST_ASSERT(ret, "section9 missing");

	ret = rte_cfgfile_section_num_entries(cfgfile, "section3");
	TEST_ASSERT(ret == 21,
			"section3 unexpected number of entries: %d", ret);

	ret = rte_cfgfile_section_num_entries(cfgfile, "section9");
	TEST_ASSERT(ret == 8, "section9 unexpected number of entries: %d", ret);

	value = rte_cfgfile_get_entry(cfgfile, "section9", "key8");
	TEST_ASSERT(strcmp("value8_section9", value) == 0,
		    "key unexpected value: %s", value);

	ret = rte_cfgfile_save(cfgfile, "/tmp/cfg_save.ini");
	TEST_ASSERT_SUCCESS(ret, "Failed to save *.ini file");
	remove("/tmp/cfg_save.ini");

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	unlink(filename);

	return 0;
}

static int
test_cfgfile_invalid_section_header(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[] = "/tmp/cfg_invalid_section_XXXXXX.ini";
	int fd;

	fd = test_cfgfile_init(filename, invalid_section_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NULL(cfgfile, "Expected failure did not occur");

	close(fd);
	unlink(filename);
	return 0;
}

static int
test_cfgfile_invalid_comment(void)
{
	struct rte_cfgfile_parameters params;
	struct rte_cfgfile *cfgfile;
	char filename[] = "/tmp/cfg_sample2_XXXXXX.ini";
	int fd;

	/* override comment character with an invalid one */
	memset(&params, 0, sizeof(params));
	params.comment_character = '$';

	fd = test_cfgfile_init(filename, sample2_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load_with_params(filename, 0, &params);
	TEST_ASSERT_NULL(cfgfile, "Expected failure did not occur");

	close(fd);
	unlink(filename);
	return 0;
}

static int
test_cfgfile_invalid_key_value_pair(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[] = "/tmp/cfg_empty_key_XXXXXX.ini";
	int fd;

	fd = test_cfgfile_init(filename, empty_key_value_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	close(fd);
	TEST_ASSERT_NULL(cfgfile, "Expected failure did not occur");

	unlink(filename);
	return 0;
}

static int
test_cfgfile_empty_key_value_pair(void)
{
	struct rte_cfgfile *cfgfile;
	const char *value;
	char filename[] = "/tmp/cfg_empty_key_XXXXXX.ini";
	int fd, ret;

	fd = test_cfgfile_init(filename, empty_key_value_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, CFG_FLAG_EMPTY_VALUES);
	close(fd);

	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to parse empty_key_value.ini");

	ret = rte_cfgfile_num_sections(cfgfile, NULL, 0);
	TEST_ASSERT(ret == 1, "Unexpected number of sections: %d", ret);

	ret = rte_cfgfile_has_section(cfgfile, "section1");
	TEST_ASSERT(ret, "section1 missing");

	ret = rte_cfgfile_section_num_entries(cfgfile, "section1");
	TEST_ASSERT(ret == 1, "section1 unexpected number of entries: %d", ret);

	value = rte_cfgfile_get_entry(cfgfile, "section1", "key");
	TEST_ASSERT(strlen(value) == 0, "key unexpected value: %s", value);

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	unlink(filename);
	return 0;
}

static int
test_cfgfile_missing_section(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[] = "/tmp/cfg_missing_section_XXXXXX.ini";
	int fd;

	fd = test_cfgfile_init(filename, missing_section_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	close(fd);

	TEST_ASSERT_NULL(cfgfile, "Expected failure did not occur");
	unlink(filename);
	return 0;
}

static int
test_cfgfile_global_properties(void)
{
	struct rte_cfgfile *cfgfile;
	const char *value;
	char filename[] = "/tmp/cfg_missing_section_XXXXXX.ini";
	int fd, ret;

	fd = test_cfgfile_init(filename, missing_section_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, CFG_FLAG_GLOBAL_SECTION);
	close(fd);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to load config file");

	ret = rte_cfgfile_num_sections(cfgfile, NULL, 0);
	TEST_ASSERT(ret == 1, "Unexpected number of sections: %d", ret);

	ret = rte_cfgfile_has_section(cfgfile, "GLOBAL");
	TEST_ASSERT(ret, "global section missing");

	ret = rte_cfgfile_section_num_entries(cfgfile, "GLOBAL");
	TEST_ASSERT(ret == 1, "GLOBAL unexpected number of entries: %d", ret);

	value = rte_cfgfile_get_entry(cfgfile, "GLOBAL", "key");
	TEST_ASSERT(strcmp("value", value) == 0,
		    "key unexpected value: %s", value);

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	unlink(filename);
	return 0;
}

static int
test_cfgfile_empty_file(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[] = "/tmp/cfg_empty_XXXXXX.ini";
	int fd, ret;

	fd = test_cfgfile_init(filename, empty_ini);
	TEST_ASSERT(fd >= 0, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	close(fd);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to load config file");

	ret = rte_cfgfile_num_sections(cfgfile, NULL, 0);
	TEST_ASSERT(ret == 0, "Unexpected number of sections: %d", ret);

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	unlink(filename);
	return 0;
}

static int
test_cfgfile(void)
{
	if (test_cfgfile_sample1())
		return -1;

	if (test_cfgfile_sample2())
		return -1;

	if (test_cfgfile_realloc_sections())
		return -1;

	if (test_cfgfile_invalid_section_header())
		return -1;

	if (test_cfgfile_invalid_comment())
		return -1;

	if (test_cfgfile_invalid_key_value_pair())
		return -1;

	if (test_cfgfile_empty_key_value_pair())
		return -1;

	if (test_cfgfile_missing_section())
		return -1;

	if (test_cfgfile_global_properties())
		return -1;

	if (test_cfgfile_empty_file())
		return -1;

	return 0;
}

REGISTER_FAST_TEST(cfgfile_autotest, true, true, test_cfgfile);

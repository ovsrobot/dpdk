/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Wind River Systems, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#ifdef RTE_EXEC_ENV_WINDOWS
#include <io.h>
#endif

#include <rte_cfgfile.h>

#include "test.h"

#include "test_cfgfiles.h"

static int
make_tmp_file(char *filename, const char *prefix, const char *data)
{
	size_t len = strlen(data);
	size_t count;
	FILE *f;

#ifdef RTE_EXEC_ENV_WINDOWS
	char tempDirName[MAX_PATH - 14];

	if (GetTempPathA(sizeof(tempDirName), tempDirName) == 0)
		return -1;

	if (GetTempFileNameA(tempDirName, prefix, 0, filename) == 0)
		return -1;

	f = fopen(filename, "wt");
#else
	snprintf(filename, PATH_MAX, "/tmp/%s_XXXXXXX", prefix);

	int fd = mkstemp(filename);
	if (fd < 0)
		return -1;

	f = fdopen(fd, "w");
#endif
	if (f == NULL)
		return -1;

	count = fwrite(data, sizeof(char), len, f);
	fclose(f);

	return (count == len) ? 0 : -1;
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
	struct rte_cfgfile_entry entries[4];
	char filename[PATH_MAX];
	char sec0[CFG_NAME_LEN] = {0};
	char sec1[CFG_NAME_LEN] = {0};
	char sec2[CFG_NAME_LEN] = "sentinel_section_2";
	char sec3[CFG_NAME_LEN] = "sentinel_section_3";
	char index_sec[CFG_NAME_LEN] = {0};
	char *sections[] = { sec0, sec1, sec2, sec3 };
	int ret;

	ret = make_tmp_file(filename, "sample1", sample1_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to load config file");

	ret = _test_cfgfile_sample(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to validate sample file: %d", ret);

	ret = rte_cfgfile_num_sections(cfgfile, NULL, 0);
	TEST_ASSERT(ret == 2, "Unexpected number of sections: %d", ret);

	ret = rte_cfgfile_sections(cfgfile, sections, 4);
	TEST_ASSERT(ret == 2, "Unexpected listed sections: %d", ret);
	TEST_ASSERT(strcmp(sec0, "section1") == 0,
			"Unexpected section at index 0: %s", sec0);
	TEST_ASSERT(strcmp(sec1, "section2") == 0,
			"Unexpected section at index 1: %s", sec1);
	TEST_ASSERT(strcmp(sec2, "sentinel_section_2") == 0,
			"Unexpected write past listed sections at index 2: %s", sec2);
	TEST_ASSERT(strcmp(sec3, "sentinel_section_3") == 0,
			"Unexpected write past listed sections at index 3: %s", sec3);

	ret = rte_cfgfile_section_num_entries_by_index(cfgfile, index_sec, 0);
	TEST_ASSERT(ret == 1, "Unexpected entry count at index 0: %d", ret);
	TEST_ASSERT(strcmp(index_sec, "section1") == 0,
			"Unexpected section name at index 0: %s", index_sec);

	ret = rte_cfgfile_section_num_entries(cfgfile, "section2");
	TEST_ASSERT(ret == 2, "Unexpected section2 entry count: %d", ret);

	memset(entries, 0x5a, sizeof(entries));
	ret = rte_cfgfile_section_entries(cfgfile, "section2", entries, 4);
	TEST_ASSERT(ret == 2, "Unexpected section2 entry count: %d", ret);
	TEST_ASSERT(strcmp(entries[0].name, "key2") == 0,
			"Unexpected section2 first key: %s", entries[0].name);
	TEST_ASSERT(strcmp(entries[0].value, "value2") == 0,
			"Unexpected section2 first value: %s", entries[0].value);
	TEST_ASSERT(strcmp(entries[1].name, "key3") == 0,
			"Unexpected section2 second key: %s", entries[1].name);
	TEST_ASSERT(strcmp(entries[1].value, "value3") == 0,
			"Unexpected section2 second value: %s", entries[1].value);
	TEST_ASSERT((unsigned char)entries[2].name[0] == 0x5a,
			"Unexpected write past listed entries at index 2");
	TEST_ASSERT((unsigned char)entries[3].name[0] == 0x5a,
			"Unexpected write past listed entries at index 3");

	memset(entries, 0x5a, sizeof(entries));
	memset(index_sec, 0, sizeof(index_sec));
	ret = rte_cfgfile_section_entries_by_index(cfgfile, 1, index_sec, entries, 4);
	TEST_ASSERT(ret == 2,
			"Unexpected entry count for section at index 1: %d", ret);
	TEST_ASSERT(strcmp(index_sec, "section2") == 0,
			"Unexpected section name at index 1: %s", index_sec);

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_sample2(void)
{
	struct rte_cfgfile_parameters params;
	struct rte_cfgfile *cfgfile;
	char filename[PATH_MAX];
	int ret;

	ret = make_tmp_file(filename, "sample2", sample2_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	/* override comment character */
	memset(&params, 0, sizeof(params));
	params.comment_character = '#';

	cfgfile = rte_cfgfile_load_with_params(filename, 0, &params);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to parse sample2");

	ret = _test_cfgfile_sample(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to validate sample file: %d", ret);

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_create_add_save_reload(void)
{
	struct rte_cfgfile *cfgfile;
	struct rte_cfgfile *loaded;
	const char *value;
	char filename[PATH_MAX];
	int ret;

	cfgfile = rte_cfgfile_create(0);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to create cfgfile");

	ret = rte_cfgfile_add_section(cfgfile, "section1");
	TEST_ASSERT_SUCCESS(ret, "Failed to add section1");
	ret = rte_cfgfile_add_entry(cfgfile, "section1", "key1", "value1");
	TEST_ASSERT_SUCCESS(ret, "Failed to add section1 key1");
	ret = rte_cfgfile_add_entry(cfgfile, "section1", "key2", "value2");
	TEST_ASSERT_SUCCESS(ret, "Failed to add section1 key2");

	ret = rte_cfgfile_add_section(cfgfile, "section2");
	TEST_ASSERT_SUCCESS(ret, "Failed to add section2");
	ret = rte_cfgfile_add_entry(cfgfile, "section2", "key3", "value3");
	TEST_ASSERT_SUCCESS(ret, "Failed to add section2 key3");
	ret = rte_cfgfile_add_entry(cfgfile, "section2", "key4", "value4");
	TEST_ASSERT_SUCCESS(ret, "Failed to add section2 key4");

	ret = make_tmp_file(filename, "create_save", "");
	TEST_ASSERT_SUCCESS(ret, "Failed to make temporary output file");

	ret = rte_cfgfile_save(cfgfile, filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to save cfgfile");

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close created cfgfile");

	loaded = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NOT_NULL(loaded, "Failed to load saved cfgfile");

	ret = rte_cfgfile_num_sections(loaded, NULL, 0);
	TEST_ASSERT(ret == 2, "Unexpected number of sections: %d", ret);

	ret = rte_cfgfile_section_num_entries(loaded, "section1");
	TEST_ASSERT(ret == 2, "Unexpected section1 entries: %d", ret);
	ret = rte_cfgfile_section_num_entries(loaded, "section2");
	TEST_ASSERT(ret == 2, "Unexpected section2 entries: %d", ret);

	value = rte_cfgfile_get_entry(loaded, "section1", "key1");
	TEST_ASSERT(strcmp("value1", value) == 0,
			"section1 key1 unexpected value: %s", value);
	value = rte_cfgfile_get_entry(loaded, "section1", "key2");
	TEST_ASSERT(strcmp("value2", value) == 0,
			"section1 key2 unexpected value: %s", value);
	value = rte_cfgfile_get_entry(loaded, "section2", "key3");
	TEST_ASSERT(strcmp("value3", value) == 0,
			"section2 key3 unexpected value: %s", value);
	value = rte_cfgfile_get_entry(loaded, "section2", "key4");
	TEST_ASSERT(strcmp("value4", value) == 0,
			"section2 key4 unexpected value: %s", value);

	ret = rte_cfgfile_close(loaded);
	TEST_ASSERT_SUCCESS(ret, "Failed to close loaded cfgfile");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_realloc_sections(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[PATH_MAX];
	int ret;
	const char *value;

	ret = make_tmp_file(filename, "realloc", realloc_sections_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
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

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	ret = make_tmp_file(filename, "save", "");
	TEST_ASSERT(ret == 0, "Failed to make empty tmp filename for save");

	ret = rte_cfgfile_save(cfgfile, filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to save to %s", filename);

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	return 0;
}

static int
test_cfgfile_invalid_section_header(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[PATH_MAX];
	int ret;

	ret = make_tmp_file(filename, "invalid", invalid_section_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NULL(cfgfile, "Expected failure did not occur");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_invalid_comment(void)
{
	struct rte_cfgfile_parameters params;
	struct rte_cfgfile *cfgfile;
	char filename[PATH_MAX];
	int ret;

	/* override comment character with an invalid one */
	memset(&params, 0, sizeof(params));
	params.comment_character = '$';

	ret = make_tmp_file(filename, "sample2", sample2_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load_with_params(filename, 0, &params);
	TEST_ASSERT_NULL(cfgfile, "Expected failure did not occur");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_invalid_key_value_pair(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[PATH_MAX];
	int ret;

	ret = make_tmp_file(filename, "empty_key", empty_key_value_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NULL(cfgfile, "Expected failure did not occur");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_line_too_long(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[PATH_MAX];
	int ret;

	ret = make_tmp_file(filename, "line_too_long", line_too_long_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NULL(cfgfile, "Expected failure did not occur");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_empty_key_value_pair(void)
{
	struct rte_cfgfile *cfgfile;
	const char *value;
	char filename[PATH_MAX];
	int ret;

	ret = make_tmp_file(filename, "empty_key_value", empty_key_value_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, CFG_FLAG_EMPTY_VALUES);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to parse empty_key_value");

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

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_missing_section(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[PATH_MAX];
	int ret;

	ret = make_tmp_file(filename, "missing_section", missing_section_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NULL(cfgfile, "Expected failure did not occur");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_global_properties(void)
{
	struct rte_cfgfile *cfgfile;
	const char *value;
	char filename[PATH_MAX];
	int ret;

	ret = make_tmp_file(filename, "missing_section", missing_section_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, CFG_FLAG_GLOBAL_SECTION);
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

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_empty_file(void)
{
	struct rte_cfgfile *cfgfile;
	char filename[PATH_MAX];
	int ret;

	ret = make_tmp_file(filename, "empty", empty_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to load config file");

	ret = rte_cfgfile_num_sections(cfgfile, NULL, 0);
	TEST_ASSERT(ret == 0, "Unexpected number of sections: %d", ret);

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static int
test_cfgfile_modify_entry(void)
{
	struct rte_cfgfile *cfgfile;
	struct rte_cfgfile *loaded;
	const char *value;
	char filename[PATH_MAX];
	int ret;

	ret = make_tmp_file(filename, "sample1_set", sample1_ini);
	TEST_ASSERT_SUCCESS(ret, "Failed to setup temp file");

	cfgfile = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NOT_NULL(cfgfile, "Failed to load config file");

	ret = rte_cfgfile_has_entry(cfgfile, "section2", "key2");
	TEST_ASSERT(ret == 1, "section2 key2 entry missing");

	ret = rte_cfgfile_has_entry(cfgfile, "section2", "invalid_key");
	TEST_ASSERT(ret == 0, "section2 'invalid_key' entry should be missing");

	ret = rte_cfgfile_set_entry(cfgfile, "section2", "key2", "value_of_key2");
	TEST_ASSERT_SUCCESS(ret, "Failed to set section2 key2");

	/* check we can't set a nonexistent key */
	ret = rte_cfgfile_set_entry(cfgfile, "section2", "invalid_key", "value_of_key4");
	TEST_ASSERT(ret < 0, "Error, unexpectedly able to set nonexistent 'invalid_key'");

	/* check we can't add an existing key */
	ret = rte_cfgfile_add_entry(cfgfile, "section2", "key2", "value_of_key2");
	TEST_ASSERT(ret < 0, "Error, unexpectedly able to add existing key2");

	ret = rte_cfgfile_save(cfgfile, filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to save cfgfile");

	ret = rte_cfgfile_close(cfgfile);
	TEST_ASSERT_SUCCESS(ret, "Failed to close cfgfile");

	loaded = rte_cfgfile_load(filename, 0);
	TEST_ASSERT_NOT_NULL(loaded, "Failed to reload saved cfgfile");

	value = rte_cfgfile_get_entry(loaded, "section2", "key2");
	TEST_ASSERT(strcmp("value_of_key2", value) == 0,
			"Unexpected section2 key2 value: %s", value);

	ret = rte_cfgfile_close(loaded);
	TEST_ASSERT_SUCCESS(ret, "Failed to close reloaded cfgfile");

	ret = remove(filename);
	TEST_ASSERT_SUCCESS(ret, "Failed to remove file");

	return 0;
}

static struct
unit_test_suite test_cfgfile_suite  = {
	.suite_name = "Test Cfgfile Unit Test Suite",
	.unit_test_cases = {
		TEST_CASE(test_cfgfile_sample1),
		TEST_CASE(test_cfgfile_sample2),
		TEST_CASE(test_cfgfile_realloc_sections),
		TEST_CASE(test_cfgfile_invalid_section_header),
		TEST_CASE(test_cfgfile_invalid_comment),
		TEST_CASE(test_cfgfile_invalid_key_value_pair),
		TEST_CASE(test_cfgfile_line_too_long),
		TEST_CASE(test_cfgfile_empty_key_value_pair),
		TEST_CASE(test_cfgfile_missing_section),
		TEST_CASE(test_cfgfile_global_properties),
		TEST_CASE(test_cfgfile_empty_file),
		TEST_CASE(test_cfgfile_create_add_save_reload),
		TEST_CASE(test_cfgfile_modify_entry),

		TEST_CASES_END()
	}
};

static int
test_cfgfile(void)
{
	return unit_test_suite_runner(&test_cfgfile_suite);
}

REGISTER_FAST_TEST(cfgfile_autotest, NOHUGE_OK, ASAN_OK, test_cfgfile);

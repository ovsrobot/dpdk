/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include "test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#ifndef RTE_EXEC_ENV_LINUX
static int
test_eal_fs(void)
{
	printf("sysfs is only available on Linux, skipping test\n");
	return TEST_SKIPPED;
}

#else

#include <rte_sysfs.h>

static int
test_parse_sysfs_value(void)
{
	char filename[PATH_MAX] = "";
	char proc_path[PATH_MAX];
	char file_template[] = "/tmp/eal_test_XXXXXX";
	int tmp_file_handle = -1;
	FILE *fd = NULL;
	unsigned valid_number;
	unsigned long retval = 0;
	char strval[64];
	long sretval = 0;

	printf("Testing sysfs value functions\n");

	/* get a temporary filename to use for all tests - create temp file handle and then
	 * use /proc to get the actual file that we can open */
	tmp_file_handle = mkstemp(file_template);
	if (tmp_file_handle == -1) {
		perror("mkstemp() failure");
		goto error;
	}
	snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", tmp_file_handle);
	if (readlink(proc_path, filename, sizeof(filename)) < 0) {
		perror("readlink() failure");
		goto error;
	}
	printf("Temporary file is: %s\n", filename);

	/* test we get an error value if we use file before it's created */
	printf("Test reading a missing file ...\n");
	if (rte_sysfs_parse_uint(&retval, "/dev/not-quite-null") == 0) {
		printf("rte_sysfs_parse_uint() returned success on a missing file - test failed\n");
		goto error;
	}
	printf("Confirmed return error when reading empty file\n");

	/* test reading a valid number value with "\n" on the end */
	printf("Test reading valid values ...\n");
	valid_number = 15;
	fd = fopen(filename,"w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fprintf(fd,"%u\n", valid_number);
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_uint(&retval, "%s", filename) < 0) {
		printf("rte_sysfs_parse_uint() returned error - test failed\n");
		goto error;
	}
	if (retval != valid_number) {
		printf("Invalid value read by rte_sysfs_parse_uint() - test failed\n");
		goto error;
	}
	printf("Read '%u\\n' ok\n", valid_number);

	/* test reading a valid hex number value with "\n" on the end */
	valid_number = 25;
	fd = fopen(filename,"w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fprintf(fd,"0x%x\n", valid_number);
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_uint(&retval, "%s", filename) < 0) {
		printf("rte_sysfs_parse_uint() returned error - test failed\n");
		goto error;
	}
	if (retval != valid_number) {
		printf("Invalid value read by rte_sysfs_parse_uint() - test failed\n");
		goto error;
	}
	printf("Read '0x%x\\n' ok\n", valid_number);

	/* a value without a trailing newline is accepted */
	valid_number = 3;
	fd = fopen(filename, "w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fprintf(fd, "%u", valid_number);
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_uint(&retval, "%s", filename) < 0 || retval != valid_number) {
		printf("rte_sysfs_parse_uint() failed without trailing newline - test failed\n");
		goto error;
	}
	printf("Read '%u' (no newline) ok\n", valid_number);

	/* a negative value is rejected by the unsigned variant ... */
	fd = fopen(filename, "w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fprintf(fd, "-1\n");
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_uint(&retval, "%s", filename) == 0) {
		printf("rte_sysfs_parse_uint() accepted a negative value - test failed\n");
		goto error;
	}

	/* ... and read correctly by the signed one, as for numa_node */
	if (rte_sysfs_parse_int(&sretval, "%s", filename) < 0 || sretval != -1) {
		printf("rte_sysfs_parse_int() failed to read -1 - test failed\n");
		goto error;
	}
	printf("Read '-1' as signed ok\n");

	/* string read strips the trailing newline */
	fd = fopen(filename, "w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fprintf(fd, "performance\n");
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_string(strval, sizeof(strval), "%s", filename) < 0 ||
			strcmp(strval, "performance") != 0) {
		printf("rte_sysfs_parse_string() returned '%s' - test failed\n", strval);
		goto error;
	}
	printf("Read 'performance' ok\n");

	/* write it back and read it again */
	if (rte_sysfs_write_string("powersave", "%s", filename) < 0) {
		printf("rte_sysfs_write_string() returned error - test failed\n");
		goto error;
	}
	if (rte_sysfs_parse_string(strval, sizeof(strval), "%s", filename) < 0 ||
			strcmp(strval, "powersave") != 0) {
		printf("read back '%s' after write - test failed\n", strval);
		goto error;
	}
	printf("Wrote and read back 'powersave' ok\n");

	printf("Test reading invalid values ...\n");

	/* test reading an empty file - expect failure!*/
	fd = fopen(filename,"w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_uint(&retval, "%s", filename) == 0) {
		printf("rte_sysfs_parse_uint() read invalid value  - test failed\n");
		goto error;
	}

	/* test reading a valid number value followed by string - expect failure!*/
	valid_number = 3;
	fd = fopen(filename,"w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fprintf(fd,"%uJ\n", valid_number);
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_uint(&retval, "%s", filename) == 0) {
		printf("rte_sysfs_parse_uint() read invalid value  - test failed\n");
		goto error;
	}

	/* test reading a non-numeric value - expect failure!*/
	fd = fopen(filename,"w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fprintf(fd,"error\n");
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_uint(&retval, "%s", filename) == 0) {
		printf("rte_sysfs_parse_uint() read invalid value  - test failed\n");
		goto error;
	}

	/* test reading a negative value as unsigned - expect failure! */
	fd = fopen(filename, "w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fprintf(fd, "-1\n");
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_uint(&retval, "%s", filename) == 0) {
		printf("rte_sysfs_parse_uint() read negative value  - test failed\n");
		goto error;
	}

	/*
	 * Same, but with leading whitespace: strtoul() skips it before it
	 * negates, so the sign has to be looked for past the whitespace.
	 */
	fd = fopen(filename, "w");
	if (fd == NULL) {
		printf("line %d, Error opening %s: %s\n", __LINE__, filename, strerror(errno));
		goto error;
	}
	fprintf(fd, " -1\n");
	fclose(fd);
	fd = NULL;
	if (rte_sysfs_parse_uint(&retval, "%s", filename) == 0) {
		printf("rte_sysfs_parse_uint() read negative value  - test failed\n");
		goto error;
	}

	close(tmp_file_handle);
	unlink(filename);
	printf("sysfs value functions - OK\n");
	return 0;

error:
	if (fd)
		fclose(fd);
	if (tmp_file_handle > 0)
		close(tmp_file_handle);
	if (filename[0] != '\0')
		unlink(filename);
	return -1;
}

static int
test_eal_fs(void)
{
	if (test_parse_sysfs_value() < 0)
		return -1;
	return 0;
}

#endif /* RTE_EXEC_ENV_LINUX */

REGISTER_FAST_TEST(eal_fs_autotest, NOHUGE_OK, ASAN_OK, test_eal_fs);

# SPDX-License-Identifier: BSD-3-Clause

test_cfgfiles = files(
    'etc/empty.ini',
    'etc/empty_key_value.ini',
    'etc/invalid_section.ini',
    'etc/line_too_long.ini',
    'etc/missing_section.ini',
    'etc/realloc_sections.ini',
    'etc/sample1.ini',
    'etc/sample2.ini',
)

# generate the header file used in cfgfile test
test_cfgfile_h = custom_target('test_cfgfile',
                          output: 'test_cfgfiles.h',
                          input: test_cfgfiles,
                          capture: true,
                          command: [ header_gen_cmd, '@INPUT@'])

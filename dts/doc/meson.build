# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 PANTHEON.tech s.r.o.

sphinx = find_program('sphinx-build')
sphinx_apidoc = find_program('sphinx-apidoc')

if not sphinx.found() or not sphinx_apidoc.found()
    subdir_done()
endif

dts_api_framework_dir = join_paths(dts_dir, 'framework')
dts_api_build_dir = join_paths(doc_api_build_dir, 'dts')
dts_api_src = custom_target('dts_api_src',
        output: 'modules.rst',
        command: ['SPHINX_APIDOC_OPTIONS=members,show-inheritance',
            sphinx_apidoc, '--append-syspath', '--force',
            '--module-first', '--separate', '-V', meson.project_version(),
            '--output-dir', dts_api_build_dir, '--no-toc', '--implicit-namespaces',
            dts_api_framework_dir],
        build_by_default: false)
doc_targets += dts_api_src
doc_target_names += 'DTS_API_sphinx_sources'

cp = find_program('cp')
cp_index = custom_target('cp_index',
        input: ['index.rst', 'conf_yaml_schema.json'],
        output: 'index.rst',
        depends: dts_api_src,
        command: [cp, '--dereference', '@INPUT@', dts_api_build_dir],
        build_by_default: false)
doc_targets += cp_index
doc_target_names += 'DTS_API_sphinx_index'

extra_sphinx_args = ['-E', '-c', doc_guides_source_dir, '--dts-root', dts_dir]
if get_option('werror')
    extra_sphinx_args += '-W'
endif

htmldir = join_paths(get_option('datadir'), 'doc', 'dpdk')
dts_api_html = custom_target('dts_api_html',
        output: 'html',
        depends: cp_index,
        command: [sphinx_wrapper, sphinx, meson.project_version(),
            dts_api_build_dir, dts_api_build_dir, extra_sphinx_args],
        build_by_default: false,
        install: false,
        install_dir: htmldir)
doc_targets += dts_api_html
doc_target_names += 'DTS_API_HTML'

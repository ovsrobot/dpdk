# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023 PANTHEON.tech s.r.o.

sphinx = find_program('sphinx-build', required: false)
sphinx_apidoc = find_program('sphinx-apidoc', required: false)

if not sphinx.found() or not sphinx_apidoc.found()
    subdir_done()
endif

dts_doc_api_build_dir = join_paths(doc_api_build_dir, 'dts')

extra_sphinx_args = ['-E', '-c', doc_guides_source_dir, '--dts-root', dts_dir]
if get_option('werror')
    extra_sphinx_args += '-W'
endif

htmldir = join_paths(get_option('datadir'), 'doc', 'dpdk', 'dts')
dts_api_html = custom_target('dts_api_html',
        output: 'html',
        command: [sphinx_wrapper, sphinx, meson.project_version(),
            meson.current_source_dir(), dts_doc_api_build_dir, extra_sphinx_args],
        build_by_default: false,
        install: get_option('enable_docs'),
        install_dir: htmldir)
doc_targets += dts_api_html
doc_target_names += 'DTS_API_HTML'

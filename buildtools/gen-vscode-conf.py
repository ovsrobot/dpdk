#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation
#

"""Visual Studio Code configuration generator script."""

# This script is meant to be run by meson build system to generate build and
# launch commands for a specific build directory for Visual Studio Code IDE.
#
# Even though this script will generate settings/tasks/launch/code analysis
# configuration for VSCode, we can't actually just regenerate the files,
# because we want to support multiple build directories, as well as not
# destroy any configuration user has created between runs of this script.
# Therefore, we need some config file handling infrastructure. Luckily, VSCode
# configs are all JSON, so we can just use json module to handle them. Of
# course, we will lose any user comments in the files, but that's a small price
# to pay for this sort of automation.
#
# Since this script will be run by meson, we can forego any parsing or anything
# to do with the build system, and just rely on the fact that we get all of our
# configuration from command-line.

import argparse
import ast
import json
import os
import shutil
from collections import OrderedDict
from sys import stderr, exit as _exit
from typing import List, Dict, Any


class ConfigCtx:
    """POD class to keep data associated with config."""
    def __init__(self, build_dir: str, source_dir: str, launch: List[str]):
        self.build_dir = build_dir
        self.source_dir = source_dir
        self.config_dir = os.path.join(source_dir, '.vscode')
        # we don't have any mechanism to label things, so we're just going to
        # use build dir basename as the label, and hope user doesn't create
        # different build directories with the same name
        self.label = os.path.basename(build_dir)
        self.builddir_var = f'{self.label}.builddir'
        self.launch = launch

        settings_fname = 'settings.json'
        tasks_fname = 'tasks.json'
        launch_fname = 'launch.json'
        analysis_fname = 'c_cpp_properties.json'
        settings_tmp_fname = f'.{settings_fname}.{self.label}.tmp'
        tasks_tmp_fname = f'.{tasks_fname}.{self.label}.tmp'
        launch_tmp_fname = f'.{launch_fname}.{self.label}.tmp'
        analysis_tmp_fname = f'.{analysis_fname}.{self.label}.tmp'

        self.settings_path = os.path.join(self.config_dir, settings_fname)
        self.tasks_path = os.path.join(self.config_dir, tasks_fname)
        self.launch_path = os.path.join(self.config_dir, launch_fname)
        self.analysis_path = os.path.join(self.config_dir, analysis_fname)

        # we want to write into temporary files at first
        self.settings_tmp = os.path.join(self.config_dir, settings_tmp_fname)
        self.tasks_tmp = os.path.join(self.config_dir, tasks_tmp_fname)
        self.launch_tmp = os.path.join(self.config_dir, launch_tmp_fname)
        self.analysis_tmp = os.path.join(self.config_dir, analysis_tmp_fname)

        # we don't want to mess with files if we didn't change anything
        self.settings_changed = False
        self.tasks_changed = False
        self.launch_changed = False
        self.analysis_changed = False


class Boolifier(ast.NodeTransformer):
    """Replace JSON "true" with Python "True"."""
    def visit_Name(self, node: ast.Name) -> ast.Constant:
        """Visitor for Name nodes."""
        if node.id == 'true':
            return ast.Constant(value=True)
        elif node.id == 'false':
            return ast.Constant(value=False)
        return node


def _parse_eval(data: str) -> Dict[str, Any]:
    """Use AST and literal_eval to parse JSON."""
    # JSON syntax is, for the most part, valid Python dictionary literal, aside
    # from a small issue of capitalized booleans. so, we will try to parse
    # JSON into an AST, replace "true"/"false" with "True"/"False", and then
    # reparse the AST into a Python object
    parsed = ast.parse(data)
    unparsed = ast.unparse(Boolifier().visit(parsed))
    # we parsed AST, now walk it and replace ast.Name nodes with booleans for
    # actual AST boolean literals of type ast.Boolean
    ast_data = ast.literal_eval(unparsed)
    return ast_data


def _load_json(file: str) -> Dict[str, Any]:
    """Load JSON file."""
    with open(file, 'r', encoding='utf-8') as f:
        data = f.read()
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            # Python's JSON parser doesn't like trailing commas but VSCode's
            # JSON parser does not consider them to be syntax errors, so they
            # may be present in user's configuration files. we can try to parse
            # JSON as Python dictionary literal, and see if it works. if it
            # doesn't, there's probably a syntax error anyway, so re-raise.
            try:
                return _parse_eval(data)
            except (ValueError, TypeError, SyntaxError,
                    MemoryError, RecursionError):
                pass
            raise


def _dump_json(file: str, obj: Dict[str, Any]) -> None:
    """Write JSON file."""
    with open(file, 'w') as f:
        json.dump(obj, f, indent=4)


def _overwrite(src: str, dst: str) -> None:
    """Overwrite dst file with src file."""
    shutil.copyfile(src, dst)
    # unlink src
    os.unlink(src)


def _gen_sorter(order: List[str]) -> Any:
    """Sort dictionary by order."""

    # JSON doesn't have sort order, but we want to be user friendly and display
    # certain properties above others as they're more important. This function
    # will return a closure that can be used to re-sort a specific object using
    # OrderedDict and an ordered list of properties.
    def _sorter(obj: Dict[str, Any]) -> OrderedDict[str, Any]:
        d = OrderedDict()
        # step 1: go through all properties in order and re-add them
        for prop in order:
            if prop in obj:
                d[prop] = obj[prop]
        # step 2: get all properties of the object, remove those that we have
        #         already added, and sort them alphabetically
        for prop in sorted(set(obj.keys()) - set(order)):
            d[prop] = obj[prop]
        # we're done: now all objects will have vaguely constant sort order
        return d
    return _sorter


def _add_to_obj_list(obj_list: List[Dict[str, Any]],
                     key: str, obj: Dict[str, Any]) -> bool:
    """Add object to list if it doesn't already exist."""
    for o in obj_list:
        if o[key] == obj[key]:
            return False
    obj_list.append(obj)
    return True


def _process_settings(ctx: ConfigCtx) -> Dict[str, Any]:
    """Update settings.json."""
    try:
        settings_obj = _load_json(ctx.settings_path)
    except FileNotFoundError:
        settings_obj = {}

    # add build to settings if it doesn't exist
    if ctx.builddir_var not in settings_obj:
        ctx.settings_changed = True
    settings_obj.setdefault(ctx.builddir_var, ctx.build_dir)

    # add path ignore setting if it's inside the source dir
    cpath = os.path.commonpath([ctx.source_dir, ctx.build_dir])
    if cpath == ctx.source_dir:
        # find path within source tree
        relpath = os.path.relpath(ctx.build_dir, ctx.source_dir) + os.sep

        # note if we need to change anything
        if 'files.exclude' not in settings_obj:
            ctx.settings_changed = True
        elif relpath not in settings_obj['files.exclude']:
            ctx.settings_changed = True

        exclude = settings_obj.setdefault('files.exclude', {})
        exclude.setdefault(relpath, True)
        settings_obj['files.exclude'] = exclude

    return settings_obj


def _process_tasks(ctx: ConfigCtx) -> Dict[str, Any]:
    """Update tasks.json."""
    try:
        outer_tasks_obj = _load_json(ctx.tasks_path)
    except FileNotFoundError:
        outer_tasks_obj = {
            "version": "2.0.0",
            "tasks": [],
            "inputs": []
        }
    inner_tasks_obj = outer_tasks_obj.setdefault('tasks', [])
    inputs_obj = outer_tasks_obj.setdefault('inputs', [])

    # generate task object sorter
    _sort_task = _gen_sorter(['label', 'detail', 'type', 'command', 'args',
                              'options', 'problemMatcher', 'group'])

    # generate our would-be configuration

    # first, we need a build task
    build_task = {
        "label": f"[{ctx.label}] Compile",
        "detail": f"Run `ninja` command for {ctx.label}",
        "type": "shell",
        "command": "meson compile",
        "options": {
            "cwd": f'${{config:{ctx.builddir_var}}}'
        },
        "problemMatcher": {
            "base": "$gcc",
            "fileLocation": ["relative", f"${{config:{ctx.builddir_var}}}"]
        },
        "group": "build"
    }
    # we also need a meson configure task with input
    configure_task = {
        "label": f"[{ctx.label}] Configure",
        "detail": f"Run `meson configure` command for {ctx.label}",
        "type": "shell",
        "command": "meson configure ${input:mesonConfigureArg}",
        "options": {
            "cwd": f'${{config:{ctx.builddir_var}}}'
        },
        "problemMatcher": [],
        "group": "build"
    }
    # finally, add input object
    input_arg = {
        "id": "mesonConfigureArg",
        "type": "promptString",
        "description": "Enter meson configure arguments",
        "default": ""
    }

    # sort our tasks
    build_task = _sort_task(build_task)
    configure_task = _sort_task(configure_task)

    # add only if task doesn't already exist
    ctx.tasks_changed |= _add_to_obj_list(inner_tasks_obj, 'label',
                                          build_task)
    ctx.tasks_changed |= _add_to_obj_list(inner_tasks_obj, 'label',
                                          configure_task)
    ctx.tasks_changed |= _add_to_obj_list(inputs_obj, 'id', input_arg)

    # replace nodes
    outer_tasks_obj['tasks'] = inner_tasks_obj
    outer_tasks_obj['inputs'] = inputs_obj

    # we're ready
    return outer_tasks_obj


def _process_launch(ctx: ConfigCtx) -> Dict[str, Any]:
    """Update launch.json."""
    try:
        launch_obj = _load_json(ctx.launch_path)
    except FileNotFoundError:
        launch_obj = {
            "version": "0.2.0",
            "configurations": []
        }
    configurations_obj = launch_obj.setdefault('configurations', [])

    # generate launch task sorter
    _sort_launch = _gen_sorter(['name', 'type', 'request', 'program', 'cwd',
                                'preLaunchTask', 'environment', 'args',
                                'MIMode', 'miDebuggerPath', 'setupCommands'])

    gdb_path = shutil.which('gdb')
    for target in ctx.launch:
        # target will be a full path, we need to get relative to build path
        exe_path = os.path.relpath(target, ctx.build_dir)
        name = f"[{ctx.label}] Launch {exe_path}"
        # generate config from template
        launch_config = {
            "name": name,
            "type": "cppdbg",
            "request": "launch",
            "program": f"${{config:{ctx.builddir_var}}}/{exe_path}",
            "args": [],
            "cwd": "${workspaceFolder}",
            "environment": [],
            "MIMode": "gdb",
            "miDebuggerPath": gdb_path,
            "preLaunchTask": f"[{ctx.label}] Compile",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-gdb-set print pretty on",
                    "ignoreFailures": True
                }
            ],
        }
        # sort keys
        launch_config = _sort_launch(launch_config)
        # add to configurations
        ctx.launch_changed |= _add_to_obj_list(configurations_obj, 'name',
                                               launch_config)

    # replace the configuration object
    launch_obj['configurations'] = configurations_obj

    # we're ready
    return launch_obj


def _process_analysis(ctx: ConfigCtx) -> Dict[str, Any]:
    """Update c_cpp_properties.json."""
    try:
        analysis_obj = _load_json(ctx.analysis_path)
    except FileNotFoundError:
        analysis_obj = {
            "version": 4,
            "configurations": []
        }
    configurations_obj = analysis_obj.setdefault('configurations', [])

    # generate analysis config sorter
    _sort_analysis = _gen_sorter(['name', 'includePath', 'compilerPath',
                                  'cStandard', 'cppStandard',
                                  'intelliSenseMode', 'compileCommands'])

    # TODO: pick up more configuration from meson (e.g. OS, platform, compiler)

    config_obj = {
        "name": "Linux",
        "includePath": [
                f"${{config:{ctx.builddir_var}}}/",
                # hardcode everything to x86/Linux for now
                "${workspaceFolder}/lib/eal/x86",
                "${workspaceFolder}/lib/eal/linux",
                "${workspaceFolder}/**"
        ],
        "compilerPath": "/usr/bin/gcc",
        "cStandard": "c99",
        "cppStandard": "c++17",
        "intelliSenseMode": "${default}",
        "compileCommands":
        f"${{config:{ctx.builddir_var}}}/compile_commands.json"
    }
    # sort configuration
    config_obj = _sort_analysis(config_obj)

    # add it to config obj
    ctx.analysis_changed |= _add_to_obj_list(configurations_obj, 'name',
                                             config_obj)

    # we're done
    analysis_obj['configurations'] = configurations_obj

    return analysis_obj


def _gen_config(ctx: ConfigCtx) -> None:
    """Generate all config files."""
    # ensure config dir exists
    os.makedirs(ctx.config_dir, exist_ok=True)

    # generate all JSON objects and write them to temp files
    settings_obj = _process_settings(ctx)
    _dump_json(ctx.settings_tmp, settings_obj)

    tasks_obj = _process_tasks(ctx)
    _dump_json(ctx.tasks_tmp, tasks_obj)

    launch_obj = _process_launch(ctx)
    _dump_json(ctx.launch_tmp, launch_obj)

    analysis_obj = _process_analysis(ctx)
    _dump_json(ctx.analysis_tmp, analysis_obj)


def _main() -> int:
    parser = argparse.ArgumentParser(
        description='Generate VSCode configuration')
    # where we are being called from
    parser.add_argument('--build-dir', required=True, help='Build directory')
    # where the sources are
    parser.add_argument('--source-dir', required=True, help='Source directory')
    # launch configuration item, can be multiple
    parser.add_argument('--launch', action='append',
                        help='Launch path for executable')
    parser.epilog = "This script is not meant to be run manually."
    # parse arguments
    args = parser.parse_args()

    # canonicalize all paths
    build_dir = os.path.realpath(args.build_dir)
    source_dir = os.path.realpath(args.source_dir)
    if args.launch:
        launch = [os.path.realpath(lp) for lp in args.launch]
    else:
        launch = []

    ctx = ConfigCtx(build_dir, source_dir, launch)

    try:
        _gen_config(ctx)
        # we finished configuration successfully, update if needed
        update_dict = {
            ctx.settings_path: (ctx.settings_tmp, ctx.settings_changed),
            ctx.tasks_path: (ctx.tasks_tmp, ctx.tasks_changed),
            ctx.launch_path: (ctx.launch_tmp, ctx.launch_changed),
            ctx.analysis_path: (ctx.analysis_tmp, ctx.analysis_changed)
        }
        for path, t in update_dict.items():
            tmp_path, changed = t
            if changed:
                _overwrite(tmp_path, path)
            else:
                os.unlink(tmp_path)

        return 0
    except json.JSONDecodeError as e:
        # remove all temporary files we may have created
        for tmp in [ctx.settings_tmp, ctx.tasks_tmp, ctx.launch_tmp,
                    ctx.analysis_tmp]:
            if os.path.exists(tmp):
                os.unlink(tmp)
        # if we fail to load JSON, output error
        print(f"Error: {e}", file=stderr)

        return 1


if __name__ == '__main__':
    _exit(_main())

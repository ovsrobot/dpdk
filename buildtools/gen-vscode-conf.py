#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Intel Corporation
#

"""Visual Studio Code configuration generator script."""

# This script is meant to be run by meson build system to generate build and launch commands for a
# specific build directory for Visual Studio Code IDE.
#
# Even though this script will generate settings/tasks/launch/code analysis configuration for
# VSCode, we can't actually just regenerate the files, because we want to support multiple build
# directories, as well as not destroy any configuration user has created between runs of this
# script. Therefore, we need some config file handling infrastructure. Luckily, VSCode configs are
# all JSON, so we can just use json module to handle them. Of course, we will lose any user
# comments in the files, but that's a small price to pay for this sort of automation.
#
# Since this script will be run by meson, we can forego any parsing or anything to do with the
# build system, and just rely on the fact that we get all of our configuration from command-line.

import argparse
import json
import os
import shutil
from collections import OrderedDict
from sys import stderr, exit as _exit
import typing as T

# if this variable is defined, we will not generate any configuration files
ENV_DISABLE = "DPDK_DISABLE_VSCODE_CONFIG"


def _preprocess_json(data: str) -> str:
    """Preprocess JSON to remove trailing commas, whitespace, and comments."""
    preprocessed_data: T.List[str] = []
    # simple state machine
    in_comment = False
    in_string = False
    escape = False
    comma = False
    maybe_comment = False
    for c in data:
        _fwdslash = c == "/"
        _newline = c == "\n"
        _comma = c == ","
        _obj_end = c in ["}", "]"]
        _space = c.isspace()
        _backslash = c == "\\"
        _quote = c == '"'

        # are we looking to start a comment?
        if maybe_comment:
            maybe_comment = False
            if _fwdslash:
                in_comment = True
                continue
            # slash is illegal JSON but this is not our job
            preprocessed_data.append("/")
            # c will receive further processing
        # are we inside a comment?
        if in_comment:
            if _newline:
                in_comment = False
            # eat everything
            continue
        # do we have a trailing comma?
        if comma:
            # there may be whitespace after the comma
            if _space:
                continue
            comma = False
            if _obj_end:
                # throw away trailing comma
                preprocessed_data.append(c)
                continue
            # comma was needed
            preprocessed_data.append(",")
            # c needs further processing
        # are we inside a string?
        if in_string:
            # are we in an escape?
            if escape:
                escape = False
            # are we trying to escape?
            elif _backslash:
                escape = True
            # are we ending the string?
            elif _quote:
                in_string = False
            # we're inside a string
            preprocessed_data.append(c)
            continue
        # are we looking to start a string?
        if _quote:
            in_string = True
            preprocessed_data.append(c)
            continue
        # are we looking to start a comment?
        elif _fwdslash:
            maybe_comment = True
            continue
        # are we looking at a comma?
        elif _comma:
            comma = True
            continue
        # are we looking at whitespace?
        elif _space:
            continue
        # this is a regular character, just add it
        preprocessed_data.append(c)

    return "".join(preprocessed_data)


def _load_json(file: str) -> T.Dict[str, T.Any]:
    """Load JSON file."""
    with open(file, "r", encoding="utf-8") as f:
        # Python's JSON parser doesn't like trailing commas, but VSCode's JSON parser does not
        # consider them to be syntax errors, so they may be present in user's configuration files.
        # remove them from the file before processing.
        data = _preprocess_json(f.read())
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            print(f"Error parsing {os.path.basename(file)}: {e}", file=stderr)
            raise


def _save_json(file: str, obj: T.Dict[str, T.Any]) -> None:
    """Write JSON file."""
    with open(file, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent="\t")


class ConfigCtx:
    """Data associated with config processing."""

    def __init__(
        self,
        build_dir: str,
        source_dir: str,
        launch: T.List[str],
        exec_env: str,
        arch: str,
    ):
        self.build_dir = build_dir
        self.source_dir = source_dir
        self.config_dir = os.path.join(source_dir, ".vscode")
        self.exec_env = exec_env
        self.arch = arch
        # we don't have any mechanism to label things, so we're just going to
        # use build dir basename as the label, and hope user doesn't create
        # different build directories with the same name
        self.label = os.path.basename(build_dir)
        self.builddir_var = f"{self.label}-builddir"
        # default to gdb
        self.dbg_path_var = f"{self.label}-dbg-path"
        self.launch_dbg_path = shutil.which("gdb")
        self.dbg_mode_var = f"{self.label}-dbg-mode"
        self.dbg_mode = "gdb"
        self.launch = launch
        self.compile_task = f"[{self.label}] Compile"

        # filenames for configs
        self.settings_fname = "settings.json"
        self.tasks_fname = "tasks.json"
        self.launch_fname = "launch.json"
        self.analysis_fname = "c_cpp_properties.json"

        # temporary filenames to avoid touching user's configuration until last moment
        self._tmp_fnames = {
            self.settings_fname: f".{self.settings_fname}.{self.label}.tmp",
            self.tasks_fname: f".{self.tasks_fname}.{self.label}.tmp",
            self.launch_fname: f".{self.launch_fname}.{self.label}.tmp",
            self.analysis_fname: f".{self.analysis_fname}.{self.label}.tmp",
        }
        # when there is no user configuration, use these templates
        self._templates: T.Dict[str, T.Dict[str, T.Any]] = {
            self.settings_fname: {},
            self.tasks_fname: {"version": "2.0.0", "tasks": [], "inputs": []},
            self.launch_fname: {"version": "0.2.0", "configurations": []},
            self.analysis_fname: {"version": 4, "configurations": []},
        }

    def _get_fname(self, fname: str) -> str:
        """Get filename for configuration."""
        if fname not in self._tmp_fnames:
            raise ValueError(f"Unknown configuration file {fname}")
        return os.path.join(self.config_dir, self._tmp_fnames[fname])

    def load(self, fname: str) -> T.Dict[str, T.Any]:
        """Load or generate JSON data from template."""
        path = self._get_fname(fname)
        try:
            return _load_json(path)
        except FileNotFoundError:
            return self._templates[fname]

    def save(self, fname: str, obj: T.Dict[str, T.Any]) -> None:
        """Save JSON data to temporary file."""
        path = self._get_fname(fname)
        _save_json(path, obj)

    def commit(self):
        """Commit previously saved settings to configuration."""
        for dst, tmp in self._tmp_fnames.items():
            fp_tmp = os.path.join(self.config_dir, tmp)
            fp_dst = os.path.join(self.config_dir, dst)
            if os.path.exists(fp_tmp):
                shutil.copyfile(fp_tmp, fp_dst)

    def cleanup(self):
        """Cleanup any temporary files."""
        for tmp in self._tmp_fnames.values():
            fp_tmp = os.path.join(self.config_dir, tmp)
            if os.path.exists(fp_tmp):
                os.unlink(fp_tmp)


def _gen_sorter(order: T.List[str]) -> T.Any:
    """Sort dictionary by order."""

    # JSON doesn't have sort order, but we want to be user friendly and display certain properties
    # above others as they're more important. This function will return a closure that can be used
    # to re-sort a specific object using OrderedDict and an ordered list of properties.
    def _sorter(obj: T.Dict[str, T.Any]) -> OrderedDict[str, T.Any]:
        d: OrderedDict[str, T.Any] = OrderedDict()
        # step 1: go through all properties in order and re-add them
        for prop in order:
            if prop in obj:
                d[prop] = obj[prop]
        # step 2: get all properties of the object, remove those that we have already added, and
        #         sort them alphabetically
        for prop in sorted(set(obj.keys()) - set(order)):
            d[prop] = obj[prop]
        # we're done: now all objects will have vaguely constant sort order
        return d

    return _sorter


def _add_obj_to_list(
    obj_list: T.List[T.Dict[str, T.Any]], key: str, obj: T.Dict[str, T.Any]
) -> bool:
    """Add object to list if it doesn't already exist."""
    for o in obj_list:
        if o[key] == obj[key]:
            return False
    obj_list.append(obj)
    return True


def _add_var_to_obj(obj: T.Dict[str, T.Any], var: str, value: T.Any) -> bool:
    """Add variable to object if it doesn't exist."""
    if var in obj:
        return False
    obj[var] = value
    return True


def _update_settings(ctx: ConfigCtx) -> T.Optional[T.Dict[str, T.Any]]:
    """Update settings.json."""
    settings_obj = ctx.load(ctx.settings_fname)
    dirty = False

    ttos_tasks = "triggerTaskOnSave.tasks"
    ttos_on = "triggerTaskOnSave.on"
    default_vars: T.Dict[str, T.Any] = {
        # store build dir
        ctx.builddir_var: ctx.build_dir,
        # store debug configuration
        ctx.dbg_path_var: ctx.launch_dbg_path,
        ctx.dbg_mode_var: ctx.dbg_mode,
        # store dbg mode and path
        # trigger build on save
        ttos_tasks: {},
        ttos_on: True,
        # improve responsiveness by disabling auto-detection of tasks
        "npm.autoDetect": "off",
        "gulp.autoDetect": "off",
        "jake.autoDetect": "off",
        "grunt.autoDetect": "off",
        "typescript.tsc.autoDetect": "off",
        "task.autoDetect": "off",
    }

    for var, value in default_vars.items():
        dirty |= _add_var_to_obj(settings_obj, var, value)

    # add path ignore setting if it's inside the source dir
    cpath = os.path.commonpath([ctx.source_dir, ctx.build_dir])
    if cpath == ctx.source_dir:
        # find path within source tree
        relpath = os.path.relpath(ctx.build_dir, ctx.source_dir) + os.sep

        # note if we need to change anything
        if "files.exclude" not in settings_obj:
            dirty = True
        elif relpath not in settings_obj["files.exclude"]:
            dirty = True

        exclude = settings_obj.setdefault("files.exclude", {})
        exclude.setdefault(relpath, True)
        settings_obj["files.exclude"] = exclude

    # if user has installed "Trigger Task On Save" extension (extension id:
    # Gruntfuggly.triggertaskonsave), this will enable build-on-save by default
    if ctx.compile_task not in settings_obj[ttos_tasks]:
        dirty = True
    # trigger build on save for all files
    settings_obj[ttos_tasks][ctx.compile_task] = ["**/*"]

    return settings_obj if dirty else None


def _update_tasks(ctx: ConfigCtx) -> T.Optional[T.Dict[str, T.Any]]:
    """Update tasks.json."""
    outer_tasks_obj = ctx.load(ctx.tasks_fname)
    inner_tasks_obj = outer_tasks_obj.setdefault("tasks", [])
    inputs_obj = outer_tasks_obj.setdefault("inputs", [])
    dirty = False

    # generate task object sorter
    _sort_task = _gen_sorter(
        [
            "label",
            "detail",
            "type",
            "command",
            "args",
            "options",
            "problemMatcher",
            "group",
        ]
    )

    # generate our would-be configuration

    # first, we need a build task
    build_task: T.Dict[str, T.Any] = {
        "label": ctx.compile_task,
        "detail": f"Run `meson compile` command for {ctx.label}",
        "type": "shell",
        "command": "meson compile",
        "options": {"cwd": f"${{config:{ctx.builddir_var}}}"},
        "problemMatcher": {
            "base": "$gcc",
            "fileLocation": ["relative", f"${{config:{ctx.builddir_var}}}"],
        },
        "group": "build",
    }
    # we also need a meson configure task with input
    configure_task: T.Dict[str, T.Any] = {
        "label": f"[{ctx.label}] Configure",
        "detail": f"Run `meson configure` command for {ctx.label}",
        "type": "shell",
        "command": "meson configure ${input:mesonConfigureArg}",
        "options": {"cwd": f"${{config:{ctx.builddir_var}}}"},
        "problemMatcher": [],
        "group": "build",
    }
    # finally, add input object
    input_arg: T.Dict[str, T.Any] = {
        "id": "mesonConfigureArg",
        "type": "promptString",
        "description": "Enter meson configure arguments",
        "default": "",
    }

    # sort our tasks
    build_task = _sort_task(build_task)
    configure_task = _sort_task(configure_task)

    # add only if task doesn't already exist
    dirty |= _add_obj_to_list(inner_tasks_obj, "label", build_task)
    dirty |= _add_obj_to_list(inner_tasks_obj, "label", configure_task)
    dirty |= _add_obj_to_list(inputs_obj, "id", input_arg)

    # replace nodes
    outer_tasks_obj["tasks"] = inner_tasks_obj
    outer_tasks_obj["inputs"] = inputs_obj

    # we're ready
    return outer_tasks_obj if dirty else None


def _update_launch(ctx: ConfigCtx) -> T.Optional[T.Dict[str, T.Any]]:
    """Update launch.json."""
    launch_obj = ctx.load(ctx.launch_fname)
    configurations_obj = launch_obj.setdefault("configurations", [])
    dirty = False

    # generate launch task sorter
    _sort_launch = _gen_sorter(
        [
            "name",
            "type",
            "request",
            "program",
            "cwd",
            "preLaunchTask",
            "environment",
            "args",
            "MIMode",
            "miDebuggerPath",
            "setupCommands",
        ]
    )

    for target in ctx.launch:
        # target will be a full path, we need to get relative to build path
        exe_path = os.path.relpath(target, ctx.build_dir)
        name = f"[{ctx.label}] Launch {exe_path}"
        # generate config from template
        launch_config: T.Dict[str, T.Any] = {
            "name": name,
            "type": "cppdbg",
            "request": "launch",
            "program": f"${{config:{ctx.builddir_var}}}/{exe_path}",
            "args": [],
            "cwd": "${workspaceFolder}",
            "environment": [],
            "MIMode": f"${{config:{ctx.dbg_mode_var}",
            "miDebuggerPath": f"${{config:{ctx.dbg_path_var}",
            "preLaunchTask": ctx.compile_task,
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-gdb-set print pretty on",
                    "ignoreFailures": True,
                }
            ],
        }
        # sort keys
        launch_config = _sort_launch(launch_config)
        # add to configurations
        dirty |= _add_obj_to_list(configurations_obj, "name", launch_config)

    # replace the configuration object
    launch_obj["configurations"] = configurations_obj

    # we're ready
    return launch_obj if dirty else None


def _update_analysis(ctx: ConfigCtx) -> T.Optional[T.Dict[str, T.Any]]:
    """Update c_cpp_properties.json."""
    analysis_obj = ctx.load(ctx.analysis_fname)
    configurations_obj = analysis_obj.setdefault("configurations", [])
    dirty = False

    # generate analysis config sorter
    _sort_analysis = _gen_sorter(
        [
            "name",
            "includePath",
            "compilerPath",
            "cStandard",
            "cppStandard",
            "intelliSenseMode",
            "compileCommands",
        ]
    )

    config_obj: T.Dict[str, T.Any] = {
        "name": ctx.exec_env.capitalize(),
        "includePath": [
            f"${{config:{ctx.builddir_var}}}/",
            # hardcode everything to x86/Linux for now
            f"${{workspaceFolder}}/lib/eal/{ctx.arch}/include",
            f"${{workspaceFolder}}/lib/eal/{ctx.exec_env}/include",
            "${workspaceFolder}/**",
        ],
        "compilerPath": "/usr/bin/gcc",
        "cStandard": "c99",
        "cppStandard": "c++17",
        "intelliSenseMode": "${default}",
        "compileCommands": f"${{config:{ctx.builddir_var}}}/compile_commands.json",
    }
    # sort configuration
    config_obj = _sort_analysis(config_obj)

    # add it to config obj
    dirty |= _add_obj_to_list(configurations_obj, "name", config_obj)

    # we're done
    analysis_obj["configurations"] = configurations_obj

    return analysis_obj if dirty else None


def _gen_config(ctx: ConfigCtx) -> None:
    """Generate all config files."""

    # generate all JSON objects and save them if we changed anything about them
    settings_obj = _update_settings(ctx)
    tasks_obj = _update_tasks(ctx)
    launch_obj = _update_launch(ctx)
    analysis_obj = _update_analysis(ctx)

    if settings_obj is not None:
        ctx.save(ctx.settings_fname, settings_obj)
    if tasks_obj is not None:
        ctx.save(ctx.tasks_fname, tasks_obj)
    if launch_obj is not None:
        ctx.save(ctx.launch_fname, launch_obj)
    if analysis_obj is not None:
        ctx.save(ctx.analysis_fname, analysis_obj)

    # the above saves only saved to temporary files, now overwrite real files
    ctx.commit()


def _main() -> int:
    if os.environ.get(ENV_DISABLE, "") == "1":
        print(
            "Visual Studio Code configuration generation "
            f"disabled by environment variable {ENV_DISABLE}=1"
        )
        return 0
    parser = argparse.ArgumentParser(description="Generate VSCode configuration")
    # where we are being called from
    parser.add_argument("--build-dir", required=True, help="Build directory")
    # where the sources are
    parser.add_argument("--source-dir", required=True, help="Source directory")
    # exec-env - Windows, Linux etc.
    parser.add_argument("--exec-env", required=True, help="Execution environment")
    # arch - x86, arm etc.
    parser.add_argument("--arch", required=True, help="Architecture")
    # launch configuration item, can be multiple
    parser.add_argument("--launch", action="append", help="Launch path for executable")
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
    exec_env = args.exec_env
    arch = args.arch

    ctx = ConfigCtx(build_dir, source_dir, launch, exec_env, arch)

    try:
        # ensure config dir exists
        os.makedirs(ctx.config_dir, exist_ok=True)

        _gen_config(ctx)

        ret = 0
    except json.JSONDecodeError as e:
        # if we fail to load JSON, output error
        print(f"Error: {e}", file=stderr)
        ret = 1
    except OSError as e:
        # if we fail to write to disk, output error
        print(f"Error: {e}", file=stderr)
        ret = 1

    # remove any temporary files
    ctx.cleanup()
    return ret


if __name__ == "__main__":
    _exit(_main())

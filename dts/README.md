# Poetry

The typical style of python dependency management, requirements.txt, has a few
issues. The advantages of Poetry include specifying what python version is required and
forcing you to specify versions, enforced by a lockfile, both of which help prevent
broken dependencies. Another benefit is the use of pyproject.toml, which has become the
standard config file for python projects, improving project organization.

# Python Version

The Python Version required by DTS is specified in
[DTS python config file](./pyproject.toml) in the **[tool.poetry.dependencies]**
section. Poetry doesn't install Python, so you may need to satisfy this requirement if
your Python is not up to date. A tool such as [Pyenv](https://github.com/pyenv/pyenv)
is a good way to get Python, though not the only one. However, DTS includes a
development environment in the form of a Docker image.

# Expected Environment

The expected execution and development environments for DTS are the same,
the container defined by [Dockerfile](./Dockerfile). Using a container for the
development environment helps with a few things.

1. It helps enforce the boundary between the tester and the traffic
   generator/sut, something which has experienced issues in the past.
2. It makes creating containers to run DTS inside automated tooling
   much easier, since they can be based off of a known-working environment
   that will be updated as DTS is.
3. It abstracts DTS from the server it is running on. This means that the
   bare-metal os can be whatever corporate policy or your personal preferences
   dictate, and DTS does not have to try to support all 15 distros that
   are supported by DPDK CI.
4. It makes automated testing for DTS easier, since new dependencies can be
   sent in with the patches.
5. It fixes the issue of undocumented dependencies, where some test suites
   require python libraries that are not installed.
6. Allows everyone to use the same python version easily, even if they are
   using an LTS distro or Windows.
7. Allows you to run the tester on Windows while developing via Docker for
   Windows.

## Tips for setting up a development environment

### Getting a docker shell

These commands will give you a bash shell inside the container with all the python
dependencies installed. This will place you inside a python virtual
environment. DTS is mounted via a volume, which is essentially a symlink
from the host to the container. This enables you to edit and run inside the container
and then delete the container when you are done, keeping your work.

```shell
docker build --target dev -t dpdk-dts .
docker run -v $(pwd):/dts -it dpdk-dts bash
$ poetry install
$ poetry shell
```

### Vim/Emacs

Any editor in the ubuntu repos should be easy to use. You can add your normal
config files as a volume, enabling you to use your preferred settings.

```shell
apt install vim
apt install emacs
```

### Visual Studio Code

VSCode has first-class support for developing with containers. You may need to run the
non-docker setup commands in the integrated terminal. DTS contains a .devcontainer
config, so if you open the folder in vscode it should prompt you to use the dev
container assuming you have the plugin installed. Please refer to
[VS Development Containers Docs](https://code.visualstudio.com/docs/remote/containers)
to set it all up.

### Other

Searching for '$IDE dev containers' will probably lead you in the right
direction.

# Python Formatting

The tools used to format Python code in DTS are Black and Isort. There's a shell
script, function.sh, which runs the formatters. Poetry will install these tools,
so once you have that set up, you should run it before submitting patches.

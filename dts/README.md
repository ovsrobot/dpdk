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
is a good way to get Python, though not the only one.

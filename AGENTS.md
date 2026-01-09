# AGENTS.md - DPDK Code Review Guidelines for AI Tools

This document provides guidelines for AI-powered code review tools when reviewing contributions to the Data Plane Development Kit (DPDK). It is derived from the official DPDK contributor guidelines.

## Overview

DPDK follows a development process modeled on the Linux Kernel. All patches are reviewed publicly on the mailing list before being merged. AI review tools should verify compliance with the standards outlined below.

---

## Source License Requirements

### SPDX License Identifiers

- **Every file must begin with an SPDX license identifier** on the first line (or second line for `#!` scripts)
- Core libraries and drivers use `BSD-3-Clause`
- Kernel components use `GPL-2.0`
- Dual-licensed code uses: `(BSD-3-Clause OR GPL-2.0)`

```c
/* Correct */
/* SPDX-License-Identifier: BSD-3-Clause */

/* Incorrect - no boilerplate license text should follow */
```

- A blank line must follow the license header before any other content

---

## Commit Message Requirements

### Subject Line (First Line)

- **Must capture the area and impact** of the change
- **~50 characters** recommended length
- **Lowercase** except for acronyms
- **Prefixed with component name** (check `git log` for existing components)
- Use **imperative mood** (instructions to the codebase)
- **No trailing period** (causes double periods in patch filenames)

```
# Good examples
ixgbe: fix offload config option name
config: increase max queues per port
net/mlx5: add support for flow counters

# Bad examples
Fixed the offload config option.    # past tense, has period
IXGBE: Fix Offload Config           # uppercase
```

### Commit Body

- Describe the issue being fixed or feature being added
- Provide enough context for reviewers to understand the purpose
- Wrap text at **72 characters**
- **Must end with** `Signed-off-by:` line (real name, not alias)
- When fixing regressions, include:
  ```
  Fixes: abcdefgh1234 ("original commit subject")
  Cc: original_author@example.com
  ```

### Required Tags

```
# For Coverity issues:
Coverity issue: 12345

# For Bugzilla issues:
Bugzilla ID: 12345

# For stable release backport candidates:
Cc: stable@dpdk.org

# For patch dependencies:
Depends-on: series-NNNNN ("Title of the series")
```

### Tag Order

```
Coverity issue:
Bugzilla ID:
Fixes:
Cc:

Reported-by:
Suggested-by:
Signed-off-by:
Acked-by:
Reviewed-by:
Tested-by:
```

Note: Empty line between the first group and `Reported-by:`

---

## C Coding Style

### General Formatting

- **Line length**: Recommended ≤80 characters, acceptable up to 100
- **Tab width**: 8 characters (hard tabs for indentation, spaces for alignment)
- **No trailing whitespace** on lines or at end of files
- Code style must be consistent within each file

### Comments

```c
/* Most single-line comments look like this. */

/*
 * VERY important single-line comments look like this.
 */

/*
 * Multi-line comments look like this. Make them real sentences. Fill
 * them so they look like real paragraphs.
 */
```

### Header File Organization

Include order (each group separated by blank line):
1. System/libc includes
2. DPDK EAL includes
3. DPDK misc library includes
4. Application-specific includes

```c
#include <stdio.h>
#include <stdlib.h>

#include <rte_eal.h>

#include <rte_ring.h>
#include <rte_mempool.h>

#include "application.h"
```

### Header Guards

```c
#ifndef _FILE_H_
#define _FILE_H_

/* Code */

#endif /* _FILE_H_ */
```

### Naming Conventions

- **All external symbols** must have `RTE_` or `rte_` prefix
- **Macros**: ALL_UPPERCASE
- **Functions**: lowercase with underscores only (no CamelCase)
- **Variables**: lowercase with underscores only
- **Enum values**: ALL_UPPERCASE with `RTE_<ENUM>_` prefix
- **Struct types**: prefer `struct name` over typedefs

#### Prohibited Terminology

Do not use:
- `master/slave` → Use: primary/secondary, controller/worker, leader/follower
- `blacklist/whitelist` → Use: denylist/allowlist, blocklist/passlist

### Indentation and Braces

```c
/* Control statements - no braces for single statements */
if (val != NULL)
        val = realloc(val, newsize);

/* Braces on same line as else */
if (test)
        stmt;
else if (bar) {
        stmt;
        stmt;
} else
        stmt;

/* Switch statements - don't indent case */
switch (ch) {
case 'a':
        aflag = 1;
        /* FALLTHROUGH */
case 'b':
        bflag = 1;
        break;
default:
        usage();
}

/* Long conditions - double indent continuation */
if (really_long_variable_name_1 == really_long_variable_name_2 &&
                var3 == var4) {
        x = y + z;
}
```

### Function Definitions

```c
/* Return type on its own line, opening brace on its own line */
static char *
function(int a1, int a2, float fl, int a4)
{
        /* body */
}
```

### Variable Declarations

```c
int *x;         /* no space after asterisk */
int * const x;  /* space before type qualifier */

/* Multiple initializers - one per line */
char a = 0;
char b = 0;

/* Or only last variable initialized */
float x, y = 0.0;
```

### Pointer and NULL Comparisons

```c
/* Good */
if (p == NULL)
if (*p == '\0')

/* Bad */
if (!p)           /* don't use ! on pointers */
```

### Return Values

- Object creation/allocation: return pointer, NULL on error, set `rte_errno`
- Packet burst functions: return number of packets handled
- Other int-returning functions: 0 on success, -1 on error (or `-errno`)
- No-error functions: use `void` return type
- Don't cast `void *` return values
- Don't parenthesize return values

### Macros

```c
/* Wrap compound statements in do-while(0) */
#define MACRO(x, y) do {                                        \
        variable = (x) + (y);                                   \
        (y) += 2;                                               \
} while (0)
```

Prefer enums and inline functions over macros when possible.

### Structure Layout

- Order members by: use, then size (largest to smallest), then alphabetically
- New additions to existing structures go at the end (ABI compatibility)
- Align member names with spaces
- Avoid `bool` in structures (unclear size, wastes space)

```c
struct foo {
        struct foo      *next;          /* List of active foo. */
        struct mumble   amumble;        /* Comment for mumble. */
        int             bar;            /* Try to align the comments. */
};
```

---

## Code Quality Requirements

### Compilation

- Each commit must compile independently (for `git bisect`)
- No forward dependencies within a patchset
- Test with multiple targets, compilers, and options
- Use `devtools/test-meson-builds.sh`

### Testing

- Add tests to `app/test` unit test framework
- New API functions must be used in `/app` test directory
- New device APIs require at least one driver implementation

### Documentation

- Add Doxygen comments for public APIs
- Update release notes in `doc/guides/rel_notes/` for important changes
- Code and documentation must be updated atomically in same patch

### ABI Compatibility

- New external functions must be exported properly
- Follow ABI policy and versioning guidelines
- Enable ABI checks with `DPDK_ABI_REF_VERSION` environment variable

---

## Patch Validation Checklist

AI review tools should verify:

### Commit Message
- [ ] Subject line ~50 chars, lowercase (except acronyms)
- [ ] Component prefix present and valid
- [ ] Imperative mood used
- [ ] No trailing period on subject
- [ ] Body wrapped at 72 characters
- [ ] `Signed-off-by:` present with real name
- [ ] `Fixes:` tag present for bug fixes with 12-char SHA
- [ ] Tags in correct order

### License
- [ ] SPDX identifier on first line (or second for scripts)
- [ ] Appropriate license for file type
- [ ] Blank line after license header

### Code Style
- [ ] Lines ≤100 characters (prefer ≤80)
- [ ] Hard tabs for indentation
- [ ] No trailing whitespace
- [ ] Proper include order
- [ ] Header guards present
- [ ] `rte_`/`RTE_` prefix on external symbols
- [ ] No prohibited terminology
- [ ] Proper brace style
- [ ] Function return type on own line
- [ ] NULL comparisons use `== NULL`

### Structure
- [ ] Each commit compiles independently
- [ ] Code and docs updated together
- [ ] Tests added/updated as needed
- [ ] Release notes updated for significant changes

---

## Meson Build Files

### Style Requirements

- 4-space indentation (no tabs)
- Line continuations double-indented
- Lists alphabetically ordered
- Short lists (≤3 items): single line, no trailing comma
- Long lists: one item per line, trailing comma on last item

```python
# Short list
sources = files('file1.c', 'file2.c')

# Long list
headers = files(
        'header1.h',
        'header2.h',
        'header3.h',
)
```

---

## Python Code

- Must comply with PEP8
- Line length acceptable up to 100 characters
- Use `pep8` tool for validation

---

## Review Process Notes

### For AI Review Tools

When providing feedback:
- Reference specific line numbers
- Cite the relevant guideline section
- Suggest concrete fixes
- Prioritize: errors > warnings > style suggestions
- Flag potential ABI breaks
- Check for missing documentation updates
- Verify test coverage for new functionality

### Severity Levels

**Error** (must fix):
- Missing SPDX license
- Missing Signed-off-by
- Compilation failures
- ABI breaks without proper versioning

**Warning** (should fix):
- Style violations
- Missing Fixes tag for bug fixes
- Documentation gaps
- Missing tests

**Info** (consider):
- Minor style preferences
- Optimization suggestions
- Alternative approaches

# AGENTS.md - DPDK Code Review Guidelines for AI Tools

This document provides guidelines for AI-powered code review tools when reviewing contributions to the Data Plane Development Kit (DPDK). It is derived from the official DPDK contributor guidelines and validation scripts.

## Overview

DPDK follows a development process modeled on the Linux Kernel. All patches are reviewed publicly on the mailing list before being merged. AI review tools should verify compliance with the standards outlined below.

---

## Source License Requirements

### SPDX License Identifiers

Every source file must begin with an SPDX license identifier, followed by the copyright notice, then a blank line before other content.

- SPDX tag on first line (or second line for `#!` scripts)
- Copyright line immediately follows
- Blank line after copyright before any code/includes
- Core libraries and drivers use `BSD-3-Clause`
- Kernel components use `GPL-2.0`
- Dual-licensed code uses: `(BSD-3-Clause OR GPL-2.0)`

```c
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ExampleCorp
 */

#include <stdio.h>
```

For scripts:
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 ExampleCorp

import sys
```

**Do not include boilerplate license text** - the SPDX identifier is sufficient.

---

## Commit Message Requirements

### Subject Line (First Line)

| Rule | Limit |
|------|-------|
| Maximum length | **60 characters** |
| Format | `component: lowercase description` |
| Case | Lowercase except acronyms |
| Mood | Imperative (instructions to codebase) |
| Punctuation | **No trailing period** |

```
# Good examples
net/ixgbe: fix offload config option name
config: increase max queues per port
net/mlx5: add support for flow counters
app/testpmd: fix memory leak in flow create

# Bad examples
Fixed the offload config option.    # past tense, has period, no prefix
net/ixgbe: Fix Offload Config       # uppercase after colon
ixgbe: fix something                # wrong prefix, should be net/ixgbe
lib/ethdev: add new feature         # wrong prefix, should be ethdev:
```

#### Headline Format Errors (from check-git-log.sh)

The following are flagged as errors:
- Tab characters in subject
- Leading or trailing spaces
- Trailing period (`.`)
- Punctuation marks: `, ; ! ? & |`
- Underscores after the colon (indicates code in subject)
- Missing colon separator
- No space after colon
- Space before colon

#### Common Prefix Mistakes

| Wrong | Correct |
|-------|---------|
| `ixgbe:` | `net/ixgbe:` |
| `lib/ethdev:` | `ethdev:` |
| `example:` | `examples/foo:` |
| `apps/` | `app/name:` |
| `testpmd:` | `app/testpmd:` |
| `test-pmd:` | `app/testpmd:` |
| `bond:` | `net/bonding:` |

#### Case-Sensitive Terms

These terms must use exact capitalization (from `devtools/words-case.txt`):
- `Rx`, `Tx` (not `RX`, `TX`, `rx`, `tx`)
- `VF`, `PF` (not `vf`, `pf`)
- `MAC`, `VLAN`, `RSS`, `API`
- `Linux`, `Windows`, `FreeBSD`
- Check `devtools/words-case.txt` for complete list

### Commit Body

| Rule | Limit |
|------|-------|
| Line wrap | **75 characters** |
| Exception | `Fixes:` lines may exceed 75 chars |

Body guidelines:
- Describe the issue being fixed or feature being added
- Provide enough context for reviewers
- **Do not start the commit message body with "It"**
- **Must end with** `Signed-off-by:` line (real name, not alias)

### Fixes Tag

When fixing regressions, use the `Fixes:` tag with a 12-character abbreviated SHA:

```
Fixes: abcdefgh1234 ("original commit subject")
```

The hash must reference a commit in the current branch, and the subject must match exactly.

**Finding maintainers**: Use `devtools/get-maintainer.sh` to identify the current subsystem maintainer from the `MAINTAINERS` file, rather than CC'ing the original author:

```bash
git send-email --to-cmd ./devtools/get-maintainer.sh --cc dev@dpdk.org 000*.patch
```

### Required Tags

```
# For Coverity issues (required if "coverity" mentioned in body):
Coverity issue: 12345

# For Bugzilla issues (required if "bugzilla" mentioned in body):
Bugzilla ID: 12345

# For stable release backport candidates:
Cc: stable@dpdk.org

# For patch dependencies (in commit notes after ---):
Depends-on: series-NNNNN ("Title of the series")
```

### Tag Order

Tags must appear in this order:

```
Coverity issue:
Bugzilla ID:
Fixes:
Cc:
                          <-- blank line required here
Reported-by:
Suggested-by:
Signed-off-by:
Acked-by:
Reviewed-by:
Tested-by:
```

**Tag format**: `Tag-name: Full Name <email@domain.com>`

---

## C Coding Style

### Line Length

| Context | Limit |
|---------|-------|
| Source code | **100 characters** |
| Commit body | **75 characters** |

### General Formatting

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
- **Macros**: ALL_UPPERCASE with `RTE_` prefix
- **Functions**: lowercase with underscores only (no CamelCase)
- **Variables**: lowercase with underscores only
- **Enum values**: ALL_UPPERCASE with `RTE_<ENUM>_` prefix

**Exception**: Driver base directories (`drivers/*/base/`) may use different naming conventions when sharing code across platforms or with upstream vendor code.

#### Prohibited Terminology

Do not use:
- `master/slave` → Use: primary/secondary, controller/worker, leader/follower
- `blacklist/whitelist` → Use: denylist/allowlist, blocklist/passlist

### Comparisons and Boolean Logic

```c
/* Pointers - compare explicitly with NULL */
if (p == NULL)      /* Good */
if (p != NULL)      /* Good */
if (!p)             /* Bad - don't use ! on pointers */

/* Integers - compare explicitly with zero */
if (a == 0)         /* Good */
if (a != 0)         /* Good */
if (!a)             /* Bad - don't use ! on integers */

/* Characters - compare with character constant */
if (*p == '\0')     /* Good */

/* Booleans - direct test is acceptable */
if (flag)           /* Good for actual bool types */
if (!flag)          /* Good for actual bool types */
```

### Boolean Usage

- Using `bool` type is allowed
- Prefer `bool` over `int` when a variable or field is only used as a boolean
- For structure fields, consider if the size/alignment impact is acceptable

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

```c
struct foo {
        struct foo      *next;          /* List of active foo. */
        struct mumble   amumble;        /* Comment for mumble. */
        int             bar;            /* Try to align the comments. */
        bool            is_valid;       /* Boolean field is acceptable. */
};
```

---

## Forbidden Tokens (from checkpatches.sh)

### Logging

| Forbidden | Preferred | Context |
|-----------|-----------|---------|
| `RTE_LOG()` | `RTE_LOG_LINE()` | lib/, drivers/ |
| `RTE_LOG_DP()` | `RTE_LOG_DP_LINE()` | drivers/ |
| `rte_log()` | `RTE_LOG_LINE()` | drivers/ |
| `printf()` | Use RTE logging | lib/, drivers/ |
| `fprintf(stdout,...)` | Use RTE logging | lib/, drivers/ |
| `fprintf(stderr,...)` | Use RTE logging | lib/, drivers/ |
| `RTE_LOG_REGISTER` | `RTE_LOG_REGISTER_DEFAULT` or `RTE_LOG_REGISTER_SUFFIX` | lib/, drivers/ |

### Error Handling

| Forbidden | Preferred | Context |
|-----------|-----------|---------|
| `rte_panic()` | Return error codes | lib/, drivers/ |
| `rte_exit()` | Return error codes | lib/, drivers/ |

### Atomics and Memory Barriers

| Forbidden | Preferred |
|-----------|-----------|
| `rte_atomic16/32/64_xxx()` | C11 atomics via `rte_atomic_xxx()` |
| `rte_smp_mb()` | `rte_atomic_thread_fence()` |
| `rte_smp_rmb()` | `rte_atomic_thread_fence()` |
| `rte_smp_wmb()` | `rte_atomic_thread_fence()` |
| `__sync_xxx()` | `rte_atomic_xxx()` |
| `__atomic_xxx()` | `rte_atomic_xxx()` |
| `__ATOMIC_RELAXED` etc. | `rte_memory_order_xxx` |
| `__rte_atomic_thread_fence()` | `rte_atomic_thread_fence()` |

### Threading

| Forbidden | Preferred |
|-----------|-----------|
| `pthread_create()` | `rte_thread_create()` |
| `pthread_join()` | `rte_thread_join()` |
| `pthread_detach()` | EAL thread functions |
| `pthread_setaffinity_np()` | `rte_thread_set_affinity()` |
| `rte_thread_set_name()` | `rte_thread_set_prefixed_name()` |
| `rte_thread_create_control()` | `rte_thread_create_internal_control()` |

### Compiler Built-ins and Attributes

| Forbidden | Preferred | Notes |
|-----------|-----------|-------|
| `__attribute__` | RTE macros in `rte_common.h` | Except in `lib/eal/include/rte_common.h` |
| `__alignof__` | C11 `alignof` | |
| `__typeof__` | `typeof` | |
| `__builtin_*` | EAL macros | Except in `lib/eal/` and `drivers/*/base/` |
| `__reserved` | Different name | Reserved in Windows headers |
| `#pragma` / `_Pragma` | Avoid | Except in `rte_common.h` |

### Format Specifiers

| Forbidden | Preferred |
|-----------|-----------|
| `%lld`, `%llu`, `%llx` | `%PRId64`, `%PRIu64`, `%PRIx64` |

### Headers and Build

| Forbidden | Preferred | Context |
|-----------|-----------|---------|
| `#include <linux/pci_regs.h>` | `#include <rte_pci.h>` | |
| `install_headers()` | Meson `headers` variable | meson.build |
| `-DALLOW_EXPERIMENTAL_API` | Not in lib/drivers/app | Build flags |
| `allow_experimental_apis` | Not in lib/drivers/app | Meson |
| `#undef XXX` | `// XXX is not set` | config/rte_config.h |
| Driver headers (`*_driver.h`, `*_pmd.h`) | Public API headers | app/, examples/ |

### Testing

| Forbidden | Preferred |
|-----------|-----------|
| `REGISTER_TEST_COMMAND` | `REGISTER_<suite_name>_TEST` |

### Documentation

| Forbidden | Preferred |
|-----------|-----------|
| `http://...dpdk.org` | `https://...dpdk.org` |
| `//doc.dpdk.org/guides/...` | `:ref:` or `:doc:` Sphinx references |
| `::  file.svg` | `::  file.*` (wildcard extension) |

---

## API Tag Requirements

### `__rte_experimental`

- Must appear **alone on the line** immediately preceding the return type
- Only allowed in **header files** (not `.c` files)

```c
/* Correct */
__rte_experimental
int
rte_new_feature(void);

/* Wrong - not alone on line */
__rte_experimental int rte_new_feature(void);

/* Wrong - in .c file */
```

### `__rte_internal`

- Must appear **alone on the line** immediately preceding the return type
- Only allowed in **header files** (not `.c` files)

```c
/* Correct */
__rte_internal
int
internal_function(void);
```

### Alignment Attributes

`__rte_aligned`, `__rte_cache_aligned`, `__rte_cache_min_aligned` may only be used with `struct` or `union` types:

```c
/* Correct */
struct __rte_cache_aligned my_struct {
        /* ... */
};

/* Wrong */
int __rte_cache_aligned my_variable;
```

### Packed Attributes

- `__rte_packed_begin` must follow `struct`, `union`, or alignment attributes
- `__rte_packed_begin` and `__rte_packed_end` must be used in pairs
- Cannot use `__rte_packed_begin` with `enum`

```c
/* Correct */
struct __rte_packed_begin my_packed_struct {
        /* ... */
} __rte_packed_end;

/* Wrong - with enum */
enum __rte_packed_begin my_enum {
        /* ... */
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
- Only update the **current release** notes file

### ABI Compatibility

- New external functions must be exported properly
- Follow ABI policy and versioning guidelines
- Enable ABI checks with `DPDK_ABI_REF_VERSION` environment variable

---

## Patch Validation Checklist

### Commit Message

- [ ] Subject line ≤60 characters
- [ ] Subject is lowercase (except acronyms from words-case.txt)
- [ ] Correct component prefix (e.g., `net/ixgbe:` not `ixgbe:`)
- [ ] No `lib/` prefix for libraries
- [ ] Imperative mood, no trailing period
- [ ] No tabs, leading/trailing spaces, or punctuation marks
- [ ] Body wrapped at 75 characters
- [ ] Body does not start with "It"
- [ ] `Signed-off-by:` present with real name and valid email
- [ ] `Fixes:` tag present for bug fixes with 12-char SHA and exact subject
- [ ] `Coverity issue:` tag present if Coverity mentioned
- [ ] `Bugzilla ID:` tag present if Bugzilla mentioned
- [ ] `Cc: stable@dpdk.org` for stable backport candidates
- [ ] Tags in correct order with blank line separator

### License

- [ ] SPDX identifier on first line (or second for scripts)
- [ ] Copyright line follows SPDX
- [ ] Blank line after copyright before code
- [ ] Appropriate license for file type

### Code Style

- [ ] Lines ≤100 characters
- [ ] Hard tabs for indentation, spaces for alignment
- [ ] No trailing whitespace
- [ ] Proper include order
- [ ] Header guards present
- [ ] `rte_`/`RTE_` prefix on external symbols
- [ ] No prohibited terminology
- [ ] Proper brace style
- [ ] Function return type on own line
- [ ] Explicit comparisons: `== NULL`, `== 0`, `!= NULL`, `!= 0`
- [ ] No forbidden tokens (see table above)

### API Tags

- [ ] `__rte_experimental` alone on line, only in headers
- [ ] `__rte_internal` alone on line, only in headers
- [ ] Alignment attributes only on struct/union
- [ ] Packed attributes properly paired

### Structure

- [ ] Each commit compiles independently
- [ ] Code and docs updated together
- [ ] Tests added/updated as needed
- [ ] Current release notes updated for significant changes

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

- Must comply with formatting standards
- Use **`black`** for code formatting validation
- Line length acceptable up to 100 characters

---

## Validation Tools

Run these before submitting:

```bash
# Check commit messages
devtools/check-git-log.sh -n1

# Check patch format and forbidden tokens
devtools/checkpatches.sh -n1

# Check maintainers coverage
devtools/check-maintainers.sh

# Build validation
devtools/test-meson-builds.sh

# Find maintainers for your patch
devtools/get-maintainer.sh <patch-file>
```

---

## Severity Levels for AI Review

**Error** (must fix):
- Missing or malformed SPDX license
- Missing Signed-off-by
- Subject line over 60 characters
- Body lines over 75 characters
- Wrong tag order or format
- Missing required tags (Fixes, Coverity issue, Bugzilla ID)
- Forbidden tokens in code
- `__rte_experimental`/`__rte_internal` in .c files or not alone on line
- Compilation failures
- ABI breaks without proper versioning

**Warning** (should fix):
- Subject line style issues (case, punctuation)
- Wrong component prefix
- Missing Cc: stable@dpdk.org for fixes
- Documentation gaps
- Missing tests
- Implicit comparisons (`!ptr` instead of `ptr == NULL`)

**Info** (consider):
- Minor style preferences
- Optimization suggestions
- Alternative approaches

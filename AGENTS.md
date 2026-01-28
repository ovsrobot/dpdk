# AGENTS.md - DPDK Code Review Guidelines for AI Tools

This document provides guidelines for AI-powered code review tools
when reviewing contributions to the Data Plane Development Kit
(DPDK). It is derived from the official DPDK contributor guidelines
and validation scripts.

## Overview

DPDK follows a development process modeled on the Linux Kernel. All
patches are reviewed publicly on the mailing list before being
merged. AI review tools should verify compliance with the standards
outlined below.

## Review Philosophy
- Only comment when you have HIGH CONFIDENCE (>80%) that an issue exists
- Be concise: one sentence per comment when possible
- Focus on actionable feedback, not observations
- When reviewing text, only comment on clarity issues if the text is genuinely
  confusing or could lead to errors.

## Priority Areas (Review These)

### Security & Safety
- Unsafe code blocks without justification
- Command injection risks (shell commands, user input)
- Path traversal vulnerabilities
- Credential exposure or hard coded secrets
- Missing input validation on external data
- Improper error handling that could leak sensitive info

### Correctness Issues
- Logic errors that could cause panics or incorrect behavior
- Buffer overflows
- Race conditions
- Resource leaks (files, connections, memory)
- Off-by-one errors or boundary conditions
- Incorrect error propagation
- Changes to API without release notes
- Changes to ABI on non-LTS release
- Overly defensive code that adds unnecessary checks
- Unnecessary comments that just restate what the code already shows (remove them)

### Architecture & Patterns
- Code that violates existing patterns in the code base
- Missing error handling
- Code that is not safe against signals

---

## Source License Requirements

### SPDX License Identifiers

Every source file must begin with an SPDX license identifier, followed
by the copyright notice, then a blank line before other content.

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
| `app/test:` | `test:` |
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
- Files must end with a new line
- Code style should be consistent within each file


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

**Exception**: Driver base directories (`drivers/*/base/`) may use different
naming conventions when sharing code across platforms or with upstream vendor code.

#### Symbol Naming for Static Linking

Drivers and libraries must not expose global variables that could
clash when statically linked with other DPDK components or
applications. Use consistent and unique prefixes for all exported
symbols to avoid namespace collisions.

**Good practice**: Use a driver-specific or library-specific prefix for all global variables:

```c
/* Good - virtio driver uses consistent "virtio_" prefix */
const struct virtio_ops virtio_legacy_ops = {
	.read = virtio_legacy_read,
	.write = virtio_legacy_write,
	.configure = virtio_legacy_configure,
};

const struct virtio_ops virtio_modern_ops = {
	.read = virtio_modern_read,
	.write = virtio_modern_write,
	.configure = virtio_modern_configure,
};

/* Good - mlx5 driver uses consistent "mlx5_" prefix */
struct mlx5_flow_driver_ops mlx5_flow_dv_ops;
```

**Bad practice**: Generic names that may clash:

```c
/* Bad - "ops" is too generic, will clash with other drivers */
const struct virtio_ops ops = { ... };

/* Bad - "legacy_ops" could clash with other legacy implementations */
const struct virtio_ops legacy_ops = { ... };

/* Bad - "driver_config" is not unique */
struct driver_config config;
```

**Guidelines**:
- Prefix all global variables with the driver or library name (e.g., `virtio_`, `mlx5_`, `ixgbe_`)
- Prefix all global functions similarly unless they use the `rte_` namespace
- Internal static variables do not require prefixes as they have file scope
- Consider using the `RTE_` or `rte_` prefix only for symbols that are part of the public DPDK API

#### Prohibited Terminology

Do not use non-inclusive naming including:
- `master/slave` → Use: primary/secondary, controller/worker, leader/follower
- `blacklist/whitelist` → Use: denylist/allowlist, blocklist/passlist
- `cripple` → Use: impacted, degraded, restricted, immobolized
- `tribe` → Use: team, squad
- `sanity check` → Use: coherence check, test, verification


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
		really_long_variable_name_3 == really_long_variable_name_4)
	stmt;
```

### Variable Declarations

- Prefer declaring variables inside the basic block where they are used
- Variables may be declared either at the start of the block, or at point of first use (C99 style)
- Both declaration styles are acceptable; consistency within a function is preferred
- Initialize variables only when a meaningful value exists at declaration time
- Use C99 designated initializers for structures

```c
/* Good - declaration at start of block */
int ret;
ret = some_function();

/* Also good - declaration at point of use (C99 style) */
for (int i = 0; i < count; i++)
	process(i);

/* Good - declaration in inner block where variable is used */
if (condition) {
	int local_val = compute();
	use(local_val);
}

/* Bad - unnecessary initialization defeats compiler warnings */
int ret = 0;
ret = some_function();    /* Compiler won't warn if assignment removed */
```

### Function Format

- Return type on its own line
- Opening brace on its own line
- Place an empty line between declarations and statements

```c
static char *
function(int a1, int b1)
{
	char *p;

	p = do_something(a1, b1);
	return p;
}
```

---

## Unnecessary Code Patterns

The following patterns add unnecessary code, hide bugs, or reduce performance. Avoid them.

### Unnecessary Variable Initialization

Do not initialize variables that will be assigned before use. This defeats the compiler's uninitialized variable warnings, hiding potential bugs.

```c
/* Bad - initialization defeats -Wuninitialized */
int ret = 0;
if (condition)
	ret = func_a();
else
	ret = func_b();

/* Good - compiler will warn if any path misses assignment */
int ret;
if (condition)
	ret = func_a();
else
	ret = func_b();

/* Good - meaningful initial value */
int count = 0;
for (i = 0; i < n; i++)
	if (test(i))
		count++;
```

### Unnecessary Casts of void *

In C, `void *` converts implicitly to any pointer type. Casting the result of `malloc()`, `calloc()`, `rte_malloc()`, or similar functions is unnecessary and can hide the error of a missing `#include <stdlib.h>`.

```c
/* Bad - unnecessary cast */
struct foo *p = (struct foo *)malloc(sizeof(*p));
struct bar *q = (struct bar *)rte_malloc(NULL, sizeof(*q), 0);

/* Good - no cast needed in C */
struct foo *p = malloc(sizeof(*p));
struct bar *q = rte_malloc(NULL, sizeof(*q), 0);
```

Note: Casts are required in C++ but DPDK is a C project.

### Zero-Length Arrays vs Variable-Length Arrays

Zero-length arrays (`int arr[0]`) are a GCC extension. Use C99 flexible array members instead.

```c
/* Bad - GCC extension */
struct msg {
	int len;
	char data[0];
};

/* Good - C99 flexible array member */
struct msg {
	int len;
	char data[];
};
```

### Unnecessary NULL Checks Before free()

Functions like `free()`, `rte_free()`, and similar deallocation functions accept NULL pointers safely. Do not add redundant NULL checks.

```c
/* Bad - unnecessary check */
if (ptr != NULL)
	free(ptr);

if (rte_ptr != NULL)
	rte_free(rte_ptr);

/* Good - free handles NULL */
free(ptr);
rte_free(rte_ptr);
```

### memset Before free()

Do not call `memset()` to zero memory before freeing it. The compiler may optimize away the `memset()` as a dead store. For security-sensitive data, use `rte_free_sensitive()` which ensures memory is cleared.

```c
/* Bad - compiler may eliminate memset */
memset(secret_key, 0, sizeof(secret_key));
free(secret_key);

/* Good - for non-sensitive data, just free */
free(ptr);

/* Good - for sensitive data, use secure free */
rte_free_sensitive(secret_key);
```

### Appropriate Use of rte_malloc()

`rte_malloc()` allocates from hugepage memory. Use it only when required:

- Memory that will be accessed by DMA (NIC descriptors, packet buffers)
- Memory shared between primary and secondary DPDK processes
- Memory requiring specific NUMA node placement

For general allocations, use standard `malloc()` which is faster and does not consume limited hugepage resources.

```c
/* Bad - rte_malloc for ordinary data structure */
struct config *cfg = rte_malloc(NULL, sizeof(*cfg), 0);

/* Good - standard malloc for control structures */
struct config *cfg = malloc(sizeof(*cfg));

/* Good - rte_malloc for DMA-accessible memory */
struct rte_mbuf *mbufs = rte_malloc(NULL, n * sizeof(*mbufs), RTE_CACHE_LINE_SIZE);
```

### Appropriate Use of rte_memcpy()

`rte_memcpy()` is optimized for bulk data transfer in the fast path. For general use, standard `memcpy()` is preferred because:

- Modern compilers optimize `memcpy()` effectively
- `memcpy()` includes bounds checking with `_FORTIFY_SOURCE`
- `memcpy()` handles small fixed-size copies efficiently

```c
/* Bad - rte_memcpy in control path */
rte_memcpy(&config, &default_config, sizeof(config));

/* Good - standard memcpy for control path */
memcpy(&config, &default_config, sizeof(config));

/* Good - rte_memcpy for packet data in fast path */
rte_memcpy(rte_pktmbuf_mtod(m, void *), payload, len);
```

---

## Forbidden Tokens

### Functions

| Forbidden | Preferred | Context |
|-----------|-----------|---------|
| `rte_panic()` | Return error codes | lib/, drivers/ |
| `rte_exit()` | Return error codes | lib/, drivers/ |
| `perror()` | `RTE_LOG()` with `strerror(errno)` | lib/, drivers/ (allowed in examples/, app/test/) |
| `printf()` | `RTE_LOG()` | lib/, drivers/ (allowed in examples/, app/test/) |
| `fprintf()` | `RTE_LOG()` | lib/, drivers/ (allowed in examples/, app/test/) |

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

#### Functional Test Infrastructure

Standalone functional tests should use the `TEST_ASSERT` macros and `unit_test_suite_runner` infrastructure for consistency and proper integration with the DPDK test framework.

```c
#include <rte_test.h>

static int
test_feature_basic(void)
{
	int ret;

	ret = rte_feature_init();
	TEST_ASSERT_SUCCESS(ret, "Failed to initialize feature");

	ret = rte_feature_operation();
	TEST_ASSERT_EQUAL(ret, 0, "Operation returned unexpected value");

	TEST_ASSERT_NOT_NULL(rte_feature_get_ptr(),
		"Feature pointer should not be NULL");

	return TEST_SUCCESS;
}

static struct unit_test_suite feature_testsuite = {
	.suite_name = "feature_autotest",
	.setup = test_feature_setup,
	.teardown = test_feature_teardown,
	.unit_test_cases = {
		TEST_CASE(test_feature_basic),
		TEST_CASE(test_feature_advanced),
		TEST_CASES_END()
	}
};

static int
test_feature(void)
{
	return unit_test_suite_runner(&feature_testsuite);
}

REGISTER_FAST_TEST(feature_autotest, true, true, test_feature);
```

Common `TEST_ASSERT` macros:
- `TEST_ASSERT(cond, msg, ...)` - Assert condition is true
- `TEST_ASSERT_SUCCESS(val, msg, ...)` - Assert value equals 0
- `TEST_ASSERT_FAIL(val, msg, ...)` - Assert value is non-zero
- `TEST_ASSERT_EQUAL(a, b, msg, ...)` - Assert two values are equal
- `TEST_ASSERT_NOT_EQUAL(a, b, msg, ...)` - Assert two values differ
- `TEST_ASSERT_NULL(val, msg, ...)` - Assert value is NULL
- `TEST_ASSERT_NOT_NULL(val, msg, ...)` - Assert value is not NULL

### Documentation

- Add Doxygen comments for public APIs
- Update release notes in `doc/guides/rel_notes/` for important changes
- Code and documentation must be updated atomically in same patch
- Only update the **current release** notes file
- Documentation must match the code
- PMD features must match the features matrix in `doc/guides/nics/features/`
- Documentation must match device operations (see `doc/guides/nics/features.rst` for the mapping between features, `eth_dev_ops`, and related APIs)

### API and Driver Changes

- New APIs must be marked as `__rte_experimental`
- New APIs must have hooks in `app/testpmd` and tests in the functional test suite
- Changes to existing APIs require release notes
- New drivers or subsystems must have release notes

### ABI Compatibility and Symbol Exports

**IMPORTANT**: DPDK uses automatic symbol map generation. Do **NOT** recommend
manually editing `version.map` files - they are auto-generated from source code
annotations.

#### Symbol Export Macros

New public functions must be annotated with export macros (defined in
`rte_export.h`). Place the macro on the line immediately before the function
definition in the `.c` file:

```c
/* For stable ABI symbols */
RTE_EXPORT_SYMBOL(rte_foo_create)
int
rte_foo_create(struct rte_foo_config *config)
{
    /* ... */
}

/* For experimental symbols (include version when first added) */
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_foo_new_feature, 25.03)
__rte_experimental
int
rte_foo_new_feature(void)
{
    /* ... */
}

/* For internal symbols (shared between DPDK components only) */
RTE_EXPORT_INTERNAL_SYMBOL(rte_foo_internal_helper)
int
rte_foo_internal_helper(void)
{
    /* ... */
}
```

#### Symbol Export Rules

- `RTE_EXPORT_SYMBOL` - Use for stable ABI functions
- `RTE_EXPORT_EXPERIMENTAL_SYMBOL(name, ver)` - Use for new experimental APIs
  (version is the DPDK release, e.g., `25.03`)
- `RTE_EXPORT_INTERNAL_SYMBOL` - Use for functions shared between DPDK libs/drivers
  but not part of public API
- Export macros go in `.c` files, not headers
- The build system generates linker version maps automatically

#### What NOT to Review

- Do **NOT** flag missing `version.map` updates - maps are auto-generated
- Do **NOT** suggest adding symbols to `lib/*/version.map` files

#### ABI Versioning for Changed Functions

When changing the signature of an existing stable function, use versioning macros
from `rte_function_versioning.h`:

- `RTE_VERSION_SYMBOL` - Create versioned symbol for backward compatibility
- `RTE_DEFAULT_SYMBOL` - Mark the new default version

Follow ABI policy and versioning guidelines in the contributor documentation.
Enable ABI checks with `DPDK_ABI_REF_VERSION` environment variable.

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
- [ ] Driver/library global variables use unique prefixes (e.g., `virtio_`, `mlx5_`)
- [ ] No prohibited terminology
- [ ] Proper brace style
- [ ] Function return type on own line
- [ ] Explicit comparisons: `== NULL`, `== 0`, `!= NULL`, `!= 0`
- [ ] No forbidden tokens (see table above)
- [ ] No unnecessary code patterns (see section above)

### API Tags

- [ ] `__rte_experimental` alone on line, only in headers
- [ ] `__rte_internal` alone on line, only in headers
- [ ] Alignment attributes only on struct/union
- [ ] Packed attributes properly paired
- [ ] New public functions have `RTE_EXPORT_*` macro in `.c` file
- [ ] Experimental functions use `RTE_EXPORT_EXPERIMENTAL_SYMBOL(name, version)`

### Structure

- [ ] Each commit compiles independently
- [ ] Code and docs updated together
- [ ] Documentation matches code behavior
- [ ] PMD features match `doc/guides/nics/features/` matrix
- [ ] Device operations match documentation (per `features.rst` mappings)
- [ ] Tests added/updated as needed
- [ ] Functional tests use TEST_ASSERT macros and unit_test_suite_runner
- [ ] New APIs marked as `__rte_experimental`
- [ ] New APIs have testpmd hooks and functional tests
- [ ] Current release notes updated for significant changes
- [ ] Release notes updated for API changes
- [ ] Release notes updated for new drivers or subsystems

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
- Documentation does not match code behavior
- PMD features missing from `doc/guides/nics/features/` matrix
- Device operations not documented per `features.rst` mappings
- Missing tests
- Functional tests not using TEST_ASSERT macros or unit_test_suite_runner
- New API not marked as `__rte_experimental`
- New API without testpmd hooks or functional tests
- New public function missing `RTE_EXPORT_*` macro
- API changes without release notes
- New drivers or subsystems without release notes
- Implicit comparisons (`!ptr` instead of `ptr == NULL`)
- Unnecessary variable initialization
- Unnecessary casts of `void *`
- Unnecessary NULL checks before free
- Inappropriate use of `rte_malloc()` or `rte_memcpy()`
- Use of `perror()`, `printf()`, `fprintf()` in libraries or drivers (allowed in examples and test code)
- Driver/library global variables without unique prefixes (static linking clash risk)

**Do NOT flag** (common false positives):
- Missing `version.map` updates (maps are auto-generated from `RTE_EXPORT_*` macros)
- Suggesting manual edits to any `version.map` file

**Info** (consider):
- Minor style preferences
- Optimization suggestions
- Alternative approaches

---

# Response Format

When you identify an issue:
1. **State the problem** (1 sentence)
2. **Why it matters** (1 sentence, only if not obvious)
3. **Suggested fix** (code snippet or specific action)

Example:
This could panic if the string is NULL.

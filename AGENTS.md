# AGENTS.md - DPDK Code Review Guidelines for AI Tools

## CRITICAL INSTRUCTION - READ FIRST

**NEVER list an item under "Errors" or "Warnings" if you conclude it is correct.**

Before outputting ANY error or warning, verify it is actually wrong. If your analysis concludes with phrases like:
- "there's no issue here"
- "which is fine"
- "appears correct"
- "is acceptable"
- "this is actually correct"

Then DO NOT INCLUDE IT IN YOUR OUTPUT AT ALL. Delete it. Omit it entirely.

The "Errors" section is ONLY for actual errors. If something is not an error, it must not appear there.

---

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

**BEFORE OUTPUTTING YOUR REVIEW**: Re-read each item. If ANY item contains phrases like "is fine", "no issue", "appears correct", "is acceptable", "actually correct" - DELETE THAT ITEM. Do not include it.

- Only comment when you have HIGH CONFIDENCE (>80%) that an issue exists
- Be concise: one sentence per comment when possible
- Focus on actionable feedback, not observations
- When reviewing text, only comment on clarity issues if the text is genuinely
  confusing or could lead to errors.
- Do NOT comment on copyright years unless outside valid range (2013 to current year)
- Do NOT report an issue then contradict yourself - if something is acceptable, do not mention it at all
- Do NOT include items in Errors/Warnings that you then say are "acceptable" or "correct"
- Do NOT mention things that are correct or "not an issue" - only report actual problems
- Do NOT speculate about contributor circumstances (employment, company policies, etc.)
- Before adding any item to your review, ask: "Is this actually wrong?" If no, omit it entirely.
- VERIFY before reporting: For subject line length, COUNT the characters first. If ≤60, do not mention it.
- NEVER write "(Correction: ...)" - if you need to correct yourself, simply omit the item entirely
- Do NOT add vague suggestions like "should be verified" or "should be checked" - either it's wrong or don't mention it
- Do NOT flag something as an Error then say "which is correct" in the same item
- Do NOT say "no issue here" or "this is actually correct" - if there's no issue, do not include it in your review
- Do NOT call the standard DPDK SPDX/copyright format "different style" - it is THE standard
- Do NOT analyze cross-patch dependencies or compilation order - you cannot reliably determine this from patch review
- Do NOT claim a patch "would cause compilation failure" based on symbols used in other patches in the series
- Review each patch individually for its own correctness; assume the patch author ordered them correctly

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
- Usage of deprecated APIs when replacements exist
- Overly defensive code that adds unnecessary checks
- Unnecessary comments that just restate what the code already shows (remove them)
- **Process-shared synchronization errors** (pthread mutexes in shared memory without `PTHREAD_PROCESS_SHARED`)

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
 * Copyright(c) 2024 John Smith
 */

#include <stdio.h>
```

For scripts:
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Jane Doe

import sys
```

**Do not include boilerplate license text** - the SPDX identifier is sufficient.

**Do NOT flag copyright years** - Copyright years reflect when code was written. Valid years range from 2013 (DPDK's first release) through the current year. Only flag years outside this range (e.g., years before 2013 or future years beyond the current date).

**Copyright holders can be individuals or organizations** - Both are equally valid. NEVER comment on, question, or speculate about copyright holders. Do not mention employer policies, company resources, or suggest copyright "should" be assigned differently. The copyright holder's choice is not subject to review.

**The following SPDX/copyright format is correct** - do NOT flag it or comment on it:
```c
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */
```
This is the standard DPDK format. Do not say it is "different" or "unusual" - it is correct.
Do not suggest the copyright year "should be verified" - if it's in the valid range (2013-current year), it's fine.
If SPDX is on line 1 and copyright follows, this is CORRECT - do not include it in Errors.

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

**Before flagging subject line length**: Actually count the characters. Only flag if >60. Do not flag then correct yourself.

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

#### Case-Sensitive Terms (Commit Messages Only)

These terms must use exact capitalization **in commit messages** (from `devtools/words-case.txt`):
- `Rx`, `Tx` (not `RX`, `TX`, `rx`, `tx`)
- `VF`, `PF` (not `vf`, `pf`)
- `MAC`, `VLAN`, `RSS`, `API`
- `Linux`, `Windows`, `FreeBSD`
- Check `devtools/words-case.txt` for complete list

**Note**: These rules apply to commit messages only, NOT to code comments or documentation.

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

**Do NOT flag Fixes tags** asking for verification that the commit "exists in the tree" or "cannot verify" - you cannot verify this from a patch review. If the format is correct (12-char SHA, quoted subject), accept it. NEVER say "cannot verify this exists".

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

Tags must appear in this order, with a blank line separating the two groups:

**Group 1** (optional tags, no blank lines within this group):
- Coverity issue:
- Bugzilla ID:
- Fixes:
- Cc:

**Blank line required here** (only if Group 1 tags are present)

**Group 2** (no blank lines within this group):
- Reported-by:
- Suggested-by:
- Signed-off-by:
- Acked-by:
- Reviewed-by:
- Tested-by:

**Correct examples:**

Simple patch with no Group 1 tags (most common):
```
The info_get callback doesn't need to check its args
since already done by ethdev.

Signed-off-by: John Smith <john@example.com>
```

Patch with Fixes and Cc tags:
```
Fixes: c743e50c475f ("null: new poll mode driver")
Cc: stable@dpdk.org

Signed-off-by: John Smith <john@example.com>
```

Patch with only Fixes tag:
```
Fixes: abcd1234abcd ("component: original commit")

Signed-off-by: Jane Doe <jane@example.com>
```

**What is correct (do NOT flag):**
- Signed-off-by directly after commit body when there are no Group 1 tags - this is CORRECT
- No blank line between `Fixes:` and `Cc:` - this is CORRECT
- Blank line between `Cc:` (or last tag in Group 1) and `Signed-off-by:` - this is CORRECT

**What is wrong (DO flag):**
- Missing blank line between Group 1 tags and Group 2 tags (when Group 1 tags exist)

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
if (likely(p != NULL))   /* Good - likely/unlikely don't change this */
if (unlikely(p == NULL)) /* Good - likely/unlikely don't change this */
if (!p)             /* Bad - don't use ! on pointers */

/* Integers - compare explicitly with zero */
if (a == 0)         /* Good */
if (a != 0)         /* Good */
if (errno != 0)     /* Good - this IS explicit */
if (likely(a != 0)) /* Good - likely/unlikely don't change this */
if (!a)             /* Bad - don't use ! on integers */
if (a)              /* Bad - implicit, should be a != 0 */

/* Characters - compare with character constant */
if (*p == '\0')     /* Good */

/* Booleans - direct test is acceptable */
if (flag)           /* Good for actual bool types */
if (!flag)          /* Good for actual bool types */
```

**Explicit comparison** means using `==` or `!=` operators (e.g., `x != 0`, `p == NULL`).
**Implicit comparison** means relying on truthiness without an operator (e.g., `if (x)`, `if (!p)`).
**Note**: `likely()` and `unlikely()` macros do NOT affect whether a comparison is explicit or implicit.

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

### Process-Shared Synchronization

When placing synchronization primitives in shared memory (memory accessible by multiple processes, such as DPDK primary/secondary processes or `mmap`'d regions), they **must** be initialized with process-shared attributes. Failure to do so causes **undefined behavior** that may appear to work in testing but fail unpredictably in production.

#### pthread Mutexes in Shared Memory

**This is an error** - mutex in shared memory without `PTHREAD_PROCESS_SHARED`:

```c
/* BAD - undefined behavior when used across processes */
struct shared_data {
	pthread_mutex_t lock;
	int counter;
};

void init_shared(struct shared_data *shm) {
	pthread_mutex_init(&shm->lock, NULL);  /* ERROR: missing pshared attribute */
}
```

**Correct implementation**:

```c
/* GOOD - properly initialized for cross-process use */
struct shared_data {
	pthread_mutex_t lock;
	int counter;
};

int init_shared(struct shared_data *shm) {
	pthread_mutexattr_t attr;
	int ret;

	ret = pthread_mutexattr_init(&attr);
	if (ret != 0)
		return -ret;

	ret = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	if (ret != 0) {
		pthread_mutexattr_destroy(&attr);
		return -ret;
	}

	ret = pthread_mutex_init(&shm->lock, &attr);
	pthread_mutexattr_destroy(&attr);

	return -ret;
}
```

#### pthread Condition Variables in Shared Memory

Condition variables also require the process-shared attribute:

```c
/* BAD - will not work correctly across processes */
pthread_cond_init(&shm->cond, NULL);

/* GOOD */
pthread_condattr_t cattr;
pthread_condattr_init(&cattr);
pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
pthread_cond_init(&shm->cond, &cattr);
pthread_condattr_destroy(&cattr);
```

#### pthread Read-Write Locks in Shared Memory

```c
/* BAD */
pthread_rwlock_init(&shm->rwlock, NULL);

/* GOOD */
pthread_rwlockattr_t rwattr;
pthread_rwlockattr_init(&rwattr);
pthread_rwlockattr_setpshared(&rwattr, PTHREAD_PROCESS_SHARED);
pthread_rwlock_init(&shm->rwlock, &rwattr);
pthread_rwlockattr_destroy(&rwattr);
```

#### When to Flag This Issue

Flag as an **Error** when ALL of the following are true:
1. A `pthread_mutex_t`, `pthread_cond_t`, `pthread_rwlock_t`, or `pthread_barrier_t` is initialized
2. The primitive is stored in shared memory (identified by context such as: structure in `rte_malloc`/`rte_memzone`, `mmap`'d memory, memory passed to secondary processes, or structures documented as shared)
3. The initialization uses `NULL` attributes or attributes without `PTHREAD_PROCESS_SHARED`

**Do NOT flag** when:
- The mutex is in thread-local or process-private heap memory (`malloc`)
- The mutex is a local/static variable not in shared memory
- The code already uses `pthread_mutexattr_setpshared()` with `PTHREAD_PROCESS_SHARED`
- The synchronization uses DPDK primitives (`rte_spinlock_t`, `rte_rwlock_t`) which are designed for shared memory

#### Preferred Alternatives

For DPDK code, prefer DPDK's own synchronization primitives which are designed for shared memory:

| pthread Primitive | DPDK Alternative |
|-------------------|------------------|
| `pthread_mutex_t` | `rte_spinlock_t` (busy-wait) or properly initialized pthread mutex |
| `pthread_rwlock_t` | `rte_rwlock_t` |
| `pthread_spinlock_t` | `rte_spinlock_t` |

Note: `rte_spinlock_t` and `rte_rwlock_t` work correctly in shared memory without special initialization, but they are spinning locks unsuitable for long wait times.

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

## Deprecated API Usage

New patches must not introduce usage of deprecated APIs, macros, or functions.
Deprecated items are marked with `RTE_DEPRECATED` or documented in the
deprecation notices section of the release notes.

### Rules for New Code

- Do not call functions marked with `RTE_DEPRECATED` or `__rte_deprecated`
- Do not use macros that have been superseded by newer alternatives
- Do not use data structures or enum values marked as deprecated
- Check `doc/guides/rel_notes/deprecation.rst` for planned deprecations
- When a deprecated API has a replacement, use the replacement

### Deprecating APIs

A patch may mark an API as deprecated provided:

- No remaining usages exist in the current DPDK codebase
- The deprecation is documented in the release notes
- A migration path or replacement API is documented
- The `RTE_DEPRECATED` macro is used to generate compiler warnings

```c
/* Marking a function as deprecated */
__rte_deprecated
int
rte_old_function(void);

/* With a message pointing to the replacement */
__rte_deprecated_msg("use rte_new_function() instead")
int
rte_old_function(void);
```

### Common Deprecated Patterns

| Deprecated | Replacement | Notes |
|-----------|-------------|-------|
| `rte_atomic*_t` types | C11 atomics | Use `rte_atomic_xxx()` wrappers |
| `rte_smp_*mb()` barriers | `rte_atomic_thread_fence()` | See Atomics section |
| `pthread_*()` in portable code | `rte_thread_*()` | See Threading section |

When reviewing patches that add new code, flag any usage of deprecated APIs
as requiring change to use the modern replacement.

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

**Note for AI reviewers**: You cannot verify compilation order or cross-patch dependencies from patch review alone. Do NOT flag patches claiming they "would fail to compile" based on symbols used in other patches in the series. Assume the patch author has ordered them correctly.

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

REGISTER_FAST_TEST(feature_autotest, NOHUGE_OK, ASAN_OK, test_feature);
```

The `REGISTER_FAST_TEST` macro parameters are:
- Test name (e.g., `feature_autotest`)
- `NOHUGE_OK` or `HUGEPAGES_REQUIRED` - whether test can run without hugepages
- `ASAN_OK` or `ASAN_FAILS` - whether test is compatible with Address Sanitizer
- Test function name

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
- Release notes are NOT required for:
  - Test-only changes (unit tests, functional tests)
  - Internal APIs and helper functions (not exported to applications)
  - Internal implementation changes that don't affect public API

### API and Driver Changes

- New APIs must be marked as `__rte_experimental`
- New APIs must have hooks in `app/testpmd` and tests in the functional test suite
- Changes to existing APIs require release notes
- New drivers or subsystems must have release notes
- Internal APIs (used only within DPDK, not exported to applications) do NOT require release notes

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
- [ ] No usage of deprecated APIs, macros, or functions
- [ ] Process-shared primitives in shared memory use `PTHREAD_PROCESS_SHARED`

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
- No strict line length limit for meson files; lines under 100 characters are acceptable

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
- pthread mutex/cond/rwlock in shared memory without `PTHREAD_PROCESS_SHARED`

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
- Usage of deprecated APIs, macros, or functions in new code

**Do NOT flag** (common false positives):
- Missing `version.map` updates (maps are auto-generated from `RTE_EXPORT_*` macros)
- Suggesting manual edits to any `version.map` file
- Copyright years within valid range (2013 to current year)
- Copyright held by individuals (never speculate about employers, company policies, or who "should" hold copyright)
- SPDX/copyright format that matches the standard DPDK format (do not call it "different" or "unusual")
- Meson file lines under 100 characters
- Case-sensitive term violations in code comments (words-case.txt applies to commit messages only)
- Comparisons using `== 0`, `!= 0`, `== NULL`, `!= NULL` as "implicit" (these ARE explicit)
- Comparisons wrapped in `likely()` or `unlikely()` macros - these are still explicit if using == or !=
- Anything you determine is correct (do not mention non-issues or say "No issue here")
- `REGISTER_FAST_TEST` using `NOHUGE_OK`/`ASAN_OK` macros (this is the correct current format)
- Tag ordering: Signed-off-by directly after commit body (when no Fixes/Cc tags) is CORRECT
- Tag ordering: no blank line between Fixes/Cc, blank line before Signed-off-by (when Fixes/Cc present) is CORRECT
- Missing release notes for test-only changes (unit tests do not require release notes)
- Missing release notes for internal APIs or helper functions (only public APIs need release notes)
- Subject lines that are within the 60 character limit (count first, do not guess)
- Any item you later correct with "(Correction: ...)" or "actually acceptable" - just omit it
- Vague concerns ("should be verified", "should be checked") - if you're not sure it's wrong, don't flag it
- Items where you say "which is correct" or "this is correct" - if it's correct, don't mention it at all
- Fixes tags with correct format (12-char SHA, quoted subject) - NEVER ask for verification that commit exists
- Items where you conclude "no issue here" or "this is actually correct" - omit these entirely
- Cross-patch compilation dependencies - you cannot determine patch ordering correctness from review
- Claims that a symbol "was removed in patch N" causing issues in patch M - assume author ordered correctly
- Any speculation about whether patches will compile when applied in sequence
- Mutexes/locks in process-private memory (standard `malloc`, stack, static non-shared) - these don't need `PTHREAD_PROCESS_SHARED`
- Use of `rte_spinlock_t` or `rte_rwlock_t` in shared memory (these work correctly without special init)

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

---

## FINAL CHECK BEFORE SUBMITTING REVIEW

Before outputting your review, scan through each item in your Errors and Warnings sections.
For EACH item, ask: "Did I conclude this is actually fine/correct/acceptable/no issue?"

If YES → DELETE THAT ITEM. It should not be in your output.

An item that says "X is wrong... actually this is correct" is a FALSE POSITIVE and must be removed.

**If your Errors section would be empty after this check, that's fine - it means the patches are good.**

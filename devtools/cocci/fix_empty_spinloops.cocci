// SPDX-License-Identifier: BSD-3-Clause
// Find and fix empty spin loops that should call rte_pause()
//
// Empty spin loops waste CPU cycles and can cause performance issues.
// This script finds various forms of busy-wait loops and adds rte_pause()
// to give hints to the CPU and reduce power consumption.

// Rule 1: Handle rte_atomic*_read() variants
@fix_atomic_read@
expression ptr, val;
@@

(
- while (rte_atomic16_read(ptr) == val);
+ while (rte_atomic16_read(ptr) == val)
+     rte_pause();
|
- while (rte_atomic16_read(ptr) != val);
+ while (rte_atomic16_read(ptr) != val)
+     rte_pause();
|
- while (rte_atomic32_read(ptr) == val);
+ while (rte_atomic32_read(ptr) == val)
+     rte_pause();
|
- while (rte_atomic32_read(ptr) != val);
+ while (rte_atomic32_read(ptr) != val)
+     rte_pause();
|
- while (rte_atomic64_read(ptr) == val);
+ while (rte_atomic64_read(ptr) == val)
+     rte_pause();
|
- while (rte_atomic64_read(ptr) != val);
+ while (rte_atomic64_read(ptr) != val)
+     rte_pause();
)

// Rule 2: Handle rte_atomic*_read() with comparison operators
@fix_atomic_cmp@
expression ptr, val;
@@

(
- while (rte_atomic16_read(ptr) < val);
+ while (rte_atomic16_read(ptr) < val)
+     rte_pause();
|
- while (rte_atomic16_read(ptr) > val);
+ while (rte_atomic16_read(ptr) > val)
+     rte_pause();
|
- while (rte_atomic32_read(ptr) < val);
+ while (rte_atomic32_read(ptr) < val)
+     rte_pause();
|
- while (rte_atomic32_read(ptr) > val);
+ while (rte_atomic32_read(ptr) > val)
+     rte_pause();
|
- while (rte_atomic64_read(ptr) < val);
+ while (rte_atomic64_read(ptr) < val)
+     rte_pause();
|
- while (rte_atomic64_read(ptr) > val);
+ while (rte_atomic64_read(ptr) > val)
+     rte_pause();
)

// Rule 3: Handle C11 atomics with rte_atomic_load_explicit()
@fix_c11_atomic@
expression ptr, order, val;
@@

(
- while (rte_atomic_load_explicit(ptr, order) == val);
+ while (rte_atomic_load_explicit(ptr, order) == val)
+     rte_pause();
|
- while (rte_atomic_load_explicit(ptr, order) != val);
+ while (rte_atomic_load_explicit(ptr, order) != val)
+     rte_pause();
|
- while (rte_atomic_load_explicit(ptr, order) < val);
+ while (rte_atomic_load_explicit(ptr, order) < val)
+     rte_pause();
|
- while (rte_atomic_load_explicit(ptr, order) > val);
+ while (rte_atomic_load_explicit(ptr, order) > val)
+     rte_pause();
)

// Rule 4: Handle __atomic_load_n() directly
@fix_gcc_atomic@
expression ptr, order, val;
@@

(
- while (__atomic_load_n(ptr, order) == val);
+ while (__atomic_load_n(ptr, order) == val)
+     rte_pause();
|
- while (__atomic_load_n(ptr, order) != val);
+ while (__atomic_load_n(ptr, order) != val)
+     rte_pause();
|
- while (__atomic_load_n(ptr, order) < val);
+ while (__atomic_load_n(ptr, order) < val)
+     rte_pause();
|
- while (__atomic_load_n(ptr, order) > val);
+ while (__atomic_load_n(ptr, order) > val)
+     rte_pause();
)

// Rule 5: Handle volatile variable reads (simple dereference)
@fix_volatile@
expression E;
identifier v;
@@

(
- while (*v == E);
+ while (*v == E)
+     rte_pause();
|
- while (*v != E);
+ while (*v != E)
+     rte_pause();
|
- while (*v < E);
+ while (*v < E)
+     rte_pause();
|
- while (*v > E);
+ while (*v > E)
+     rte_pause();
|
- while (v == E);
+ while (v == E)
+     rte_pause();
|
- while (v != E);
+ while (v != E)
+     rte_pause();
)

// Rule 6: Handle negated conditions
@fix_negated@
expression ptr, val;
@@

(
- while (!rte_atomic32_read(ptr));
+ while (!rte_atomic32_read(ptr))
+     rte_pause();
|
- while (!rte_atomic64_read(ptr));
+ while (!rte_atomic64_read(ptr))
+     rte_pause();
|
- while (!rte_atomic_load_explicit(ptr, val));
+ while (!rte_atomic_load_explicit(ptr, val))
+     rte_pause();
)

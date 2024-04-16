// SPDX-License-Identifier: BSD-3-Clause
// Use RTE_DIM macro instead of dividing sizeof array with sizeof an elmemnt
//
// Based of Linux kernela array_size.cocci
//
@@
type T;
T[] E;
@@
(
|
- (sizeof(E)/sizeof(E[...]))
+ RTE_DIM(E)
|
- (sizeof(E)/sizeof(*E))
+ RTE_DIM(E)
|
- (sizeof(E)/sizeof(T))
+ RTE_DIM(E)
|
- RTE_DIM((E))
+ RTE_DIM(E)
)

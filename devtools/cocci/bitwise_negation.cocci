//
// The bitwise negation operation is easy to be mistakenly written as a boolean
// negation operation, this script is used to find this kind of problem.
//
// Note: If it is confirmed to be a boolean negation operation, it is recommended
// that change & to && to avoid false positives.
//
@@ expression E; constant C; @@
(
  !E & !C
|
- !E & C
+ !(E & C)
|
- E & !C
+ E & ~C
)


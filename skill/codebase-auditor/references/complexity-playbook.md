# Complexity Playbook

Use this reference when scanner findings point to algorithmic, rendering, or backend performance risk.

## Review Priorities

1. Prove the data shape and cardinality before recommending a rewrite.
2. Prefer a smaller data-structure change over a broad refactor when it preserves behavior.
3. Separate true complexity risk from constant-factor cleanup.
4. Keep confidence low when a heuristic cannot see call frequency, input size, or framework semantics.

## Complexity Rule

When an outer collection of size `n` repeatedly performs a linear lookup over another collection of size `m`, the path is usually `O(n*m)`. Common examples include `.find`, `.filter`, `.includes`, manual inner loops, query calls, or API calls inside `map`, `filter`, `for`, `while`, or render paths. If both collections are the same size, this is often `O(n^2)`.

A precomputed `Map`, dictionary, or `Set` can reduce repeated in-memory lookups to average `O(1)`, changing the overall path to `O(n+m)` for index construction plus lookup. This is preferable only when it preserves the original semantics.

Do not apply this rewrite blindly:

- Use `Map` or dictionary lookup only when key equality matches the original comparison.
- Use `Map<Key, Value>` only when duplicate keys do not matter; use `Map<Key, Value[]>` or grouping when duplicates must be preserved.
- Use `Set` only when membership matters and counts, order, and duplicate occurrences do not.
- Preserve first-match versus last-match behavior from `.find` or manual loops.
- Do not move index construction across mutations that change the source collection.
- Do not batch query/API calls unless authorization scope, ordering, pagination, rate limits, errors, and retries remain correct.
- Skip the rewrite when collections are known to be tiny and the added memory or complexity is not worth it.

## High-Value Patterns

- Replace repeated linear lookup in `map`, `filter`, loops, or render paths with a precomputed `Map`, dictionary, or `Set` when equality semantics are stable.
- Batch query/API calls found inside loops, or move them behind a loader/cache layer when ordering and error handling can be preserved.
- Move `sort`, expensive parsing, serialization, and aggregation out of loops when the input is loop-invariant.
- Memoize render-path derived data only when dependencies are explicit and recomputation is measurable.
- Replace recursive traversal with an explicit stack when depth is unbounded or stack overflow is plausible.

## Frontend Leads

- Chained array transforms in render can be acceptable for small lists; escalate only for large or repeated render paths.
- Inline object/function creation matters when it crosses memoized component boundaries or high-frequency updates.
- Hydration and bundle concerns require build artifacts or profiler evidence before firm conclusions.

## Backend Leads

- Treat query-in-loop and API-in-loop findings as high-priority leads.
- Verify transaction boundaries, authorization scope, pagination, ordering, and error behavior before batching.
- Prefer indexing recommendations only when the filtered columns and query workload are clear.

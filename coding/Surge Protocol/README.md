![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />       <font size="10">Surge Protocol</font>

​        23<sup>rd</sup> April 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=red>Hard</font>


# Synopsis

Surge Protocol is a hard coding challenge requiring the player to implement a segment tree with lazy propagation that supports range-add updates and range-maximum queries, both in O(log N) time. Naive approaches that scan the range on every operation will time out on the largest inputs.

## Skills Required

- Binary tree data structures
- Understanding of range query problems
- Recursive divide-and-conquer thinking

## Skills Learned

- Segment tree construction and range queries
- Lazy propagation for deferred range updates
- The push-down pattern and why it is essential for correctness

## Description

```
Anika's sensor grid covers every major relay in the coalition's infrastructure.
Each burst of operations either escalates a range of sensors by a fixed urgency
amount, or queries a range for its peak value. With up to 500,000 sensors and
200,000 operations, the structure must support both in O(log N) per operation.
```

## Technical Description

```
Surge Protocol
N sensors with initial values. Q operations: range-add or range-max-query.
Output the sum of all query answers.

Line 1: N Q
Line 2: N initial values
Next Q lines: U l r v  (add v to [l,r]) or  Q l r  (max in [l,r])

1 <= N <= 500000
1 <= Q <= 200000

Example Input:
8 5
10 20 30 40 50 60 70 80
U 1 4 5
U 3 6 10
Q 2 5
U 0 7 2
Q 0 3

Expected output:
127
```

## Solving the challenge

### Step 1: Why a naive approach fails

A direct simulation — store the array, update by looping over the range, query by scanning the range — costs O(N) per operation. With N=500,000 and Q=200,000, this is 10^11 operations in the worst case. It cannot pass within the time limit.

The key observation is that both operations have a range structure. We need a data structure that decomposes ranges into O(log N) segments and processes each segment in O(1).

### Step 2: Segment tree structure

A segment tree is a complete binary tree built over the array. Each node covers a contiguous subrange `[s, e]`:

- **Leaf nodes** (`s == e`) store the value of a single element.
- **Internal nodes** store the maximum of their entire range, derived from their two children.

With N elements, the tree has at most 4N nodes and depth O(log N).

Build the tree bottom-up: leaves first, then each internal node takes the max of its children.

```python
def build(arr, node, s, e):
    if s == e:
        tree[node] = arr[s]
        return
    mid = (s + e) // 2
    build(arr, 2*node, s, mid)
    build(arr, 2*node+1, mid+1, e)
    tree[node] = max(tree[2*node], tree[2*node+1])
```

### Step 3: Range query without updates

A range query `[l, r]` recurses down the tree. At each node covering `[s, e]`:

- If `[s, e]` is entirely outside `[l, r]`: return 0 (identity for max).
- If `[s, e]` is entirely inside `[l, r]`: return `tree[node]` directly.
- Otherwise: split at the midpoint and combine results from both children.

This visits O(log N) nodes per query.

### Step 4: The problem with naive range updates

A naive range update — recurse to every leaf in the range and propagate maximums back up — also costs O(N) in the worst case. We need a way to update entire subtrees in O(1) each.

The insight: if node `[s, e]` is entirely inside the update range `[l, r]`, we can record the pending addition as a **lazy tag** on that node, rather than propagating it immediately to its children. The node's stored maximum is updated immediately (since every element in the range increases by `v`, the maximum increases by `v` too), but the children are left unchanged for now.

### Step 5: Lazy propagation — the push-down operation

Before descending into a node's children (for either an update or a query), any pending lazy tag must be pushed down to those children. This ensures children have correct values before we examine or update them.

```python
def push_down(node):
    if lazy[node] != 0:
        for child in (2*node, 2*node+1):
            tree[child] += lazy[node]
            lazy[child] += lazy[node]
        lazy[node] = 0
```

The lazy tag accumulates additively: multiple updates to the same node just sum their pending values. This works because addition distributes over maximum: `max(a + x, b + x) = max(a, b) + x`.

### Step 6: Range update with lazy propagation

```python
def update(node, s, e, l, r, val):
    if r < s or e < l:
        return
    if l <= s and e <= r:
        tree[node] += val
        lazy[node] += val
        return
    push_down(node)
    mid = (s + e) // 2
    update(2*node, s, mid, l, r, val)
    update(2*node+1, mid+1, e, l, r, val)
    tree[node] = max(tree[2*node], tree[2*node+1])
```

After recursing into children, the parent's stored maximum is recomputed from the (now updated) children. Push-down happens before any descent to ensure children are up to date first.

### Step 7: Range query with lazy propagation

The query is identical to the naive version, except `push_down` is called before descending:

```python
def query(node, s, e, l, r):
    if r < s or e < l:
        return 0
    if l <= s and e <= r:
        return tree[node]
    push_down(node)
    mid = (s + e) // 2
    return max(
        query(2*node, s, mid, l, r),
        query(2*node+1, mid+1, e, l, r)
    )
```

### Worked example

Initial: `[10, 20, 30, 40, 50, 60, 70, 80]`

After `U 1 4 5` (add 5 to indices 1-4): `[10, 25, 35, 45, 55, 60, 70, 80]`
After `U 3 6 10` (add 10 to indices 3-6): `[10, 25, 35, 55, 65, 70, 80, 80]`
`Q 2 5` → max(35, 55, 65, 70) = **70**
After `U 0 7 2` (add 2 to all): `[12, 27, 37, 57, 67, 72, 82, 82]`
`Q 0 3` → max(12, 27, 37, 57) = **57**

Sum: 70 + 57 = **127** ✓

### Complexity

| Approach | Time per operation | Total |
|---|---|---|
| Naive scan | O(N) | O(N × Q) — TLE |
| Segment tree with lazy propagation | O(log N) | O((N + Q) log N) — passes |

The O(log N) bound comes from the fact that any range `[l, r]` decomposes into at most 2 log N nodes in the segment tree. Push-down adds at most a constant factor since each node is pushed down at most once per operation.
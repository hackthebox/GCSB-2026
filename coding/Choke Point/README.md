![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />       <font size="10">Choke Point</font>

​        23<sup>rd</sup> April 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=red>Insane</font>


# Synopsis

Choke Point is an insane coding challenge that requires the player to construct the dominator tree of a directed graph using the Lengauer-Tarjan algorithm, then compute the sum of subtree sizes in that tree. The dominator tree is a classical but notoriously difficult structure to compute correctly, and the Lengauer-Tarjan algorithm involves DFS spanning trees, semidominators, path compression, and a two-pass implicit/explicit correction step.

## Skills Required

- Directed graph traversal (DFS) and spanning trees
- Union-Find with path compression
- Familiarity with tree algorithms (subtree sizes, DFS order)
- Ability to implement complex multi-step algorithms precisely

## Skills Learned

- The definition and properties of dominators and the dominator tree
- Semidominator computation via reverse DFS order
- Lengauer-Tarjan implicit/explicit idom correction
- Path-compression union-find for ancestor queries with minimum tracking

## Description

```
Anika's dependency map has grown into something that keeps her awake. Some nodes
are choke points: every communication path from the source to a given platform must
pass through them. Build the dominator tree and compute the sum of all subtree sizes —
a single number that captures the total depth of control concentration in the graph.
```

## Technical Description

```
Choke Point
A directed graph with V nodes and E edges. Source S = 0.
Build the dominator tree. For each reachable node v, compute the size of its
subtree in the dominator tree (the number of nodes it dominates, including itself).
Output the sum of all subtree sizes.

Line 1: V E S
Next E lines: u v (directed edge)

2 <= V <= 50000
2 <= E <= 200000
S = 0; graph may contain cycles; all nodes reachable from S.

Example Input:
7 9 0
0 1
0 2
1 3
2 3
3 5
2 4
4 5
1 6
3 6

Expected output:
14
```

## Solving the challenge

### Step 1: Dominators and the dominator tree

Node `d` **dominates** node `v` (with respect to source `S`) if every path from `S` to `v` in the graph passes through `d`. Every node dominates itself.

The **immediate dominator** `idom[v]` is the closest dominator: the unique dominator `d ≠ v` such that every other dominator of `v` also dominates `d`. The immediate dominator is well-defined for every node reachable from `S` (except `S` itself, whose immediate dominator is set to itself by convention).

The **dominator tree** is built by connecting each node `v` to its immediate dominator `idom[v]`. It is a tree rooted at `S`, and its structure is unique regardless of how the graph is traversed.

The **subtree size** of `v` in the dominator tree is the number of nodes that `v` dominates (including `v` itself). The sum of all subtree sizes equals the sum, over all reachable nodes `v`, of the depth of `v` plus one — a global measure of how deep and concentrated the control structure is.

### Step 2: Naïve approach and why it fails

The brute-force algorithm for each node `v` removes every other node `d` in turn from the graph and checks whether `v` is still reachable from `S` via BFS. If not, `d` dominates `v`. This is O(V² × (V + E)) and fails entirely for V = 50,000.

### Step 3: The Lengauer-Tarjan algorithm — overview

Lengauer-Tarjan (1979) runs in O((V + E) × α(V)) where α is the inverse Ackermann function from union-find path compression — effectively linear in practice. It works in four phases:

1. Run DFS from `S` to assign DFS tree numbers and record tree parents.
2. Compute **semidominators** in reverse DFS order.
3. Compute **implicit immediate dominators** using a union-find structure.
4. Fix **explicit immediate dominators** in forward DFS order.

### Step 4: DFS spanning tree

Run a standard iterative DFS from `S`, recording:

- `dfn[v]`: the DFS discovery order of each node.
- `order[]`: the list of nodes in DFS discovery order.
- `par[v]`: the parent of `v` in the DFS spanning tree.

```python
order = []; dfn = [-1]*V; par = [-1]*V
stack = [(S, iter(g[S]))]
dfn[S] = 0; order.append(S)
while stack:
    v, children = stack[-1]
    try:
        w = next(children)
        if dfn[w] == -1:
            par[w] = v; dfn[w] = len(order); order.append(w)
            stack.append((w, iter(g[w])))
    except StopIteration:
        stack.pop()
```

**Implementation note**: do not hold a reference into the stack across a `push` call in C++. Use a separate per-node index array instead — `stack<pair<int,int>>` with `int& i = stk.top().second` is unsafe because `push()` may reallocate the underlying storage, invalidating the reference.

### Step 5: Semidominators

The **semidominator** `semi[w]` is defined as the node `v` with minimum DFS number such that there exists a path from `v` to `w` in the graph passing only through nodes with DFS number greater than `dfn[w]` (i.e., discovered later than `w`). Formally:

```
semi[w] = min_dfn {v : ∃ path v = v0, v1, ..., vk = w
                       where dfn[vi] > dfn[w] for 0 < i < k}
```

Compute semidominators in reverse DFS order (from last discovered to first). For each predecessor `v` of `w` in the original graph:

- If `dfn[v] < dfn[w]`, then `v` is a candidate semidominator directly.
- If `dfn[v] > dfn[w]`, find the node `u` with minimum `dfn[semi[u]]` on the path from `v` to the root of the current union-find forest. Node `semi[u]` is then a candidate.

```python
for v in rg[w]:          # for each predecessor v of w
    if dfn[v] == -1: continue
    u = eval_(v)         # find min-semi ancestor in UF forest
    if dfn[semi[u]] < dfn[semi[w]]:
        semi[w] = semi[u]
```

### Step 6: Union-Find with minimum tracking

The `eval_(v)` query finds the node `u` on the path from `v` to the root of the union-find forest that minimises `dfn[semi[u]]`. This is implemented with path compression and a parallel `uf_min[]` array that tracks the minimum-semi node along the compressed path.

```python
def find_it(v):
    path = []
    x = v
    while uf_parent[x] != x:
        path.append(x); x = uf_parent[x]
    # compress root→leaf (reversed path order)
    for y in reversed(path):
        if dfn[semi[uf_min[uf_parent[y]]]] < dfn[semi[uf_min[y]]]:
            uf_min[y] = uf_min[uf_parent[y]]
        uf_parent[y] = x
    return uf_min[v]
```

**Critical detail**: path compression must propagate `uf_min` from the root towards the leaf (i.e., in reversed path order). Propagating leaf-to-root gives incorrect results because a node's `uf_min` depends on the already-updated value of its parent's `uf_min`.

After computing `semi[w]`, link `w` into the forest under `par[w]`:

```python
uf_parent[w] = par[w]
```

### Step 7: Implicit immediate dominators

While processing the bucket of `par[w]` (nodes whose semidominator is `par[w]`), compute a temporary `idom[v]` for each bucket member:

```python
for v in bucket[par[w]]:
    u = find_it(v)
    idom[v] = u if dfn[semi[u]] < dfn[semi[v]] else par[w]
```

If `semi[u]` is an ancestor of `semi[v]` (or `semi[v]` itself), the immediate dominator is `u` (which equals the semidominator). Otherwise it is `par[w]`, to be corrected in the next step.

### Step 8: Explicit correction pass

After all nodes are processed, do a single forward pass in DFS order:

```python
for i in range(1, N):
    w = order[i]
    if idom[w] != semi[w]:
        idom[w] = idom[idom[w]]
```

This propagates the correct dominator down the tree for nodes whose immediate dominator was deferred to `par[w]` in the previous step.

### Step 9: Subtree sizes

Build the children list of the dominator tree from the `idom` array. Compute subtree sizes bottom-up in reverse DFS order (children before parents):

```python
children = [[] for _ in range(V)]
for v in order:
    if v != S: children[idom[v]].append(v)

subtree = [1] * V
for v in reversed(order):
    for c in children[v]:
        subtree[v] += subtree[c]

print(sum(subtree[v] for v in order))
```

### Worked example

Graph: 7 nodes, edges `0->1, 0->2, 1->3, 2->3, 3->5, 2->4, 4->5, 1->6, 3->6`.

| Node | Immediate dominator | Reasoning |
|---|---|---|
| 1 | 0 | Only reachable via 0->1 |
| 2 | 0 | Only reachable via 0->2 |
| 3 | 0 | Paths via 0->1->3 and 0->2->3; common prefix is 0 |
| 4 | 2 | Only reachable via 0->2->4 |
| 5 | 0 | Paths via 0->1->3->5, 0->2->3->5, 0->2->4->5 |
| 6 | 0 | Paths via 0->1->6, 0->1->3->6, 0->2->3->6 |

Dominator tree: 0 → {1, 2, 3, 5, 6}, 2 → {4}.

Subtree sizes: `[7, 1, 2, 1, 1, 1, 1]`. Sum = **14** ✓

### Complexity

| Approach | Time | Space |
|---|---|---|
| Brute force (BFS per node per candidate) | O(V² × (V + E)) | O(V + E) |
| Lengauer-Tarjan | O((V + E) × α(V)) | O(V + E) |

The α(V) factor comes from union-find path compression and is effectively constant for any practical input size.
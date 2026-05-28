![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />       <font size="10">Cascade Depth</font>

​        23<sup>rd</sup> April 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=#f0ad4e>Medium</font>


# Synopsis

Cascade Depth is a medium coding challenge that requires the player to find the maximum-weight path in a directed acyclic graph (DAG). The intended solution uses topological sort (Kahn's algorithm) combined with a dynamic programming relaxation, running in O(V + E).

## Skills Required

- Directed graph representation and traversal
- Understanding of topological ordering
- Dynamic programming on DAGs

## Skills Learned

- Kahn's algorithm for topological sort via in-degree BFS
- Longest-path DP: why greedy and Dijkstra do not apply to general weights
- Why the DAG property is essential for this DP to be correct

## Description

```
Anika's dependency mapper has finished its first pass over the coalition's vendor
ecosystem. Each directed edge represents a dependency relationship with an exposure
weight. The depth of a compromise cascade is measured as the total weight of the
longest path leading to any affected node. Find the worst-case cascade depth.
```

## Technical Description

```
Cascade Depth
A weighted DAG with V nodes and E directed edges is given.
Find the maximum total weight of any path in the graph.

Line 1: V E
Next E lines: u v w  (directed edge from u to v with weight w)

2 <= V <= 10000
1 <= E <= 30000
1 <= w <= 1000
The graph is guaranteed to be acyclic.

Example Input:
5 6
0 1 3
0 2 1
1 3 4
2 3 2
3 4 5
1 4 1

Expected output:
12
```

## Solving the challenge

### Step 1: Why shortest-path algorithms do not apply

A natural instinct is to negate all weights and run Dijkstra. This does not work for two reasons:

First, Dijkstra requires non-negative edge weights — negating positive weights produces negative weights, which breaks the algorithm's greedy assumption.

Second, Bellman-Ford handles negative weights but runs in O(V × E), which is too slow for V=10,000 and E=30,000. It also does not take advantage of the acyclic structure.

The key insight is that in a DAG, there are no cycles, so every node has a well-defined "topological level". This means we can compute the longest path to each node in a single forward pass — if we process nodes in topological order.

### Step 2: Kahn's algorithm for topological ordering

Kahn's algorithm produces a topological ordering using in-degree counts and a queue.

Build the adjacency list and count how many edges point INTO each node:

```python
adj      = [[] for _ in range(V)]
indegree = [0] * V

for u, v, w in edges:
    adj[u].append((v, w))
    indegree[v] += 1
```

Seed the queue with all nodes that have no incoming edges (in-degree zero):

```python
queue = deque(i for i in range(V) if indegree[i] == 0)
```

Process nodes from the queue. For each node dequeued, reduce the in-degree of its neighbours. When a neighbour's in-degree reaches zero, it is ready to be processed — all its predecessors have already been handled.

```python
while queue:
    u = queue.popleft()
    for v, w in adj[u]:
        indegree[v] -= 1
        if indegree[v] == 0:
            queue.append(v)
```

### Step 3: Longest-path DP

Maintain an array `dp` where `dp[v]` is the maximum total weight of any path ending at node `v`. Initially all values are 0 (a path of length zero exists at every node).

During the Kahn traversal, relax each outgoing edge immediately after dequeuing:

```python
dp = [0] * V

while queue:
    u = queue.popleft()
    for v, w in adj[u]:
        if dp[u] + w > dp[v]:
            dp[v] = dp[u] + w
        indegree[v] -= 1
        if indegree[v] == 0:
            queue.append(v)
```

Because `u` is processed before any of its successors (topological order), `dp[u]` is already final when we relax `(u, v, w)`. This is the key correctness argument.

### Step 4: Extract the answer

The answer is the maximum value in `dp`:

```python
print(max(dp))
```

### Worked example

Graph: 5 nodes, edges `0->1(3), 0->2(1), 1->3(4), 2->3(2), 3->4(5), 1->4(1)`.

Initial in-degrees: `[0, 1, 1, 2, 2]`. Queue starts with node 0.

| Dequeue | dp before | Relax edges | dp after | Queue |
|---|---|---|---|---|
| 0 | [0,0,0,0,0] | 0->1: dp[1]=max(0,3)=3; 0->2: dp[2]=max(0,1)=1 | [0,3,1,0,0] | {1,2} |
| 1 | [0,3,1,0,0] | 1->3: dp[3]=max(0,7)=7; 1->4: dp[4]=max(0,4)=4 | [0,3,1,7,4] | {2} |
| 2 | [0,3,1,7,4] | 2->3: dp[3]=max(7,3)=7 (no change) | [0,3,1,7,4] | {3} |
| 3 | [0,3,1,7,4] | 3->4: dp[4]=max(4,12)=12 | [0,3,1,7,12] | {4} |
| 4 | [0,3,1,7,12] | — | [0,3,1,7,12] | {} |

Answer: max(dp) = 12. ✓

### Complexity

| Approach | Time | Space |
|---|---|---|
| Bellman-Ford | O(V × E) | O(V + E) |
| Topological sort + DP | O(V + E) | O(V + E) |

The topological sort approach is optimal: every edge is processed exactly once during the Kahn traversal, and the DP update per edge is O(1).
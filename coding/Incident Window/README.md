![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />       <font size="10">Incident Window</font>

​        23<sup>rd</sup> April 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=#f5a623>Easy</font>


# Synopsis

Incident Window is an easy coding challenge that requires the player to count how many distinct time-window anchor values t make a sliding window of width W contain at least K suspicious events. The efficient solution uses a two-pointer sweep over the sorted list of suspicious timestamps, computing valid anchor ranges in O(1) per step.

## Skills Required

- Sorting and basic array manipulation
- Understanding of sliding window / two-pointer technique
- Careful off-by-one handling with half-open intervals

## Skills Learned

- Two-pointer window sweep over sorted timestamps
- Computing anchor-count ranges analytically in O(1)
- Reducing a counting problem to a range arithmetic problem

## Description

```
Anika's correlation engine ingests a raw stream of authentication events from
across the coalition's vendor ecosystem. Each event is timestamped to the nearest
second and tagged as suspicious (S) or normal (N). A suspicious event alone means
nothing — it's the cluster that matters.

An alert window [t, t+W) triggers if it contains at least K suspicious events.
Count how many distinct integer anchor values t produce an alert.
```

## Technical Description

```
Incident Window
N events are given in non-decreasing timestamp order. Each is tagged S or N.
Count the number of distinct integers t in [0, 10000-W] such that the interval
[t, t+W) contains at least K suspicious events.

Line 1: N W K
Next N lines: timestamp event_type

1 <= N <= 50000
1 <= W <= 100
1 <= K <= 20
0 <= timestamp <= 10000

Example Input:
6 4 2
0 N
1 S
3 N
4 S
6 N
7 S

Expected output:
6
```

## Solving the challenge

### Step 1: Extract and sort suspicious timestamps

Normal events are irrelevant to the count. Filter the input to keep only events tagged `S`. Since the input is already in non-decreasing timestamp order, the resulting list is already sorted.

```python
sus = [ts for ts, t in events if t == 'S']
```

### Step 2: Recognise the structure

A window `[t, t+W)` contains suspicious event at position `sus[i]` if and only if `t <= sus[i] < t+W`, which rearranges to `sus[i] - W + 1 <= t <= sus[i]`.

For a window to contain at least K suspicious events, there must be K indices `l <= i1 < i2 < ... < iK <= r` all within a span of less than W seconds. This is exactly the condition that a sliding window of width W over the sorted suspicious array contains at least K elements.

### Step 3: Two-pointer sweep

Maintain left pointer `l` and advance it whenever `sus[r] - sus[l] >= W` (the window spans W or more seconds and would not be a valid half-open interval of width W). At each right pointer position `r`, the window `[l, r]` contains `r - l + 1` suspicious events.

```python
l = 0
for r in range(len(sus)):
    while sus[r] - sus[l] >= W:
        l += 1
    window_count = r - l + 1
```

### Step 4: Count valid anchors analytically

When `window_count >= K`, the K-th suspicious event from the right within the current window is at index `r - K + 1`, with timestamp `pivot = sus[r - K + 1]`.

Any anchor `t` such that `pivot` falls inside `[t, t+W)` will produce a valid window. That means `t <= pivot` and `t > pivot - W`, giving the range:

```
anchor_lo = max(0,            pivot - W + 1)
anchor_hi = min(10000 - W + 1, pivot)
```

If `anchor_hi >= anchor_lo`, there are `anchor_hi - anchor_lo + 1` valid anchors contributed by this step. Add them to the running total.

```python
if r - l + 1 >= K:
    pivot     = sus[r - K + 1]
    anchor_lo = max(0, pivot - W + 1)
    anchor_hi = min(MAX_T - W + 1, pivot)
    if anchor_hi >= anchor_lo:
        answer += anchor_hi - anchor_lo + 1
```

### Step 5: Why this avoids double-counting

At each step, we charge the contribution to the right pointer `r`. For a fixed `r`, the pivot `sus[r - K + 1]` is uniquely determined. As `r` advances, the pivot advances too (it can only move right). This means each valid anchor `t` is counted exactly once — when `r` is the rightmost of the K suspicious events that fall inside the window starting at `t`.

### Worked example

Suspicious timestamps: `[1, 4, 7]`, W=4, K=2.

| r | sus[r] | l | count | pivot | anchor range | contribution |
|---|---|---|---|---|---|---|
| 0 | 1 | 0 | 1 | — | — | 0 |
| 1 | 4 | 0 | 2 | sus[0]=1 | [max(0,-2), min(9997,1)] = [0,1] | 2 |
| 2 | 7 | 1 | 2 | sus[1]=4 | [max(0, 1), min(9997,4)] = [1,4] | 4 |

Total: 6. ✓

### Complexity

| Approach | Time | Space |
|---|---|---|
| Naive (scan all t values) | O(N × MAX\_T) | O(1) |
| Two-pointer with range counting | O(N) | O(N) |

The two-pointer approach is linear in the number of suspicious events after the initial filter. No sorting is required because the input is already ordered.
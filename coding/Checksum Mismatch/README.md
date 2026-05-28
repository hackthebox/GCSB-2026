![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />       <font size="10">Checksum Mismatch</font>

​        23<sup>rd</sup> April 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=green>Very Easy</font>


# Synopsis

Checksum Mismatch is a very easy coding challenge that requires the player to detect corrupted network packets by computing the XOR checksum of each packet's payload and comparing it to the stored value. The solution is a single linear scan with no data structures required.

## Skills Required

- Basic I/O parsing
- Understanding of the XOR bitwise operation
- Looping and counting

## Skills Learned

- XOR as a lightweight integrity check
- Why XOR checksums detect single-byte corruption

## Description

```
During the opening hours of Project Nightfall, Anika's pipeline flags something
subtle: packets arriving from a trusted firmware distribution node are passing
format validation but failing silent integrity checks. Someone has been modifying
payloads in transit and updating the metadata to look clean.

Each packet carries a byte payload and a stored checksum. The checksum is supposed
to be the XOR of every byte in the payload. A mismatch means the packet was
tampered with. Count how many packets in the batch are corrupted.
```

## Technical Description

```
Checksum Mismatch
N packets are given. Each packet has a payload of L bytes and a stored checksum.
The checksum should equal the XOR of all payload bytes.
Count and print the number of corrupted packets.

Line 1: N
Next N lines: L b0 b1 ... b(L-1) checksum

1 <= N <= 10000
2 <= L <= 32
0 <= each byte, checksum <= 255

Example Input:
6
2 170 85 255
2 240 15 1
4 1 2 3 4 4
2 100 200 0
2 7 7 0
3 255 128 127 1

Expected output:
3
```

## Solving the challenge

### Step 1: Understanding XOR checksums

XOR is a bitwise operation where each bit of the result is 1 if the corresponding bits of the operands differ, and 0 if they are the same. It has two properties that make it useful as an integrity check:

**Self-inverse**: `a XOR a = 0` for any value `a`. XOR-ing a value with itself always gives zero.

**Commutativity and associativity**: The order of XOR operations does not matter. `a XOR b XOR c` gives the same result in any order.

When all payload bytes are XOR-ed together, any single-byte modification to the payload changes the result. A legitimate packet satisfies:

```
b0 XOR b1 XOR ... XOR b(L-1) == stored_checksum
```

A corrupted packet does not. The check is O(L) per packet — just fold all bytes with XOR in a single pass.

### Step 2: Parsing each packet

Each line after the first has the form `L b0 b1 ... b(L-1) checksum`. Read all values, compute the XOR of the L payload bytes, and compare to the last value on the line.

```python
parts  = list(map(int, input().split()))
L      = parts[0]
payload = parts[1 : L + 1]
stored = parts[L + 1]
```

### Step 3: Computing the checksum

Fold the payload with XOR. Starting from 0 (the identity element for XOR):

```python
checksum = 0
for b in payload:
    checksum ^= b
```

### Step 4: Counting mismatches

If the computed checksum differs from the stored value, the packet is corrupted. Accumulate a counter across all N packets and print it.

```python
if checksum != stored:
    corrupted += 1
```

### Step 5: Fast I/O for larger inputs

For the largest test cases (N = 10,000, L up to 32), reading line-by-line with `input()` is fast enough in Python. In C++, use `ios::sync_with_stdio(false)` and `cin.tie(nullptr)` to avoid unnecessary flushing overhead.

### Worked example

For the six packets in the example:

| Payload | XOR | Stored | Verdict |
|---|---|---|---|
| 170, 85 | 255 | 255 | Clean |
| 240, 15 | 255 | 1 | **Corrupted** |
| 1, 2, 3, 4 | 4 | 4 | Clean |
| 100, 200 | 172 | 0 | **Corrupted** |
| 7, 7 | 0 | 0 | Clean |
| 255, 128, 127 | 0 | 1 | **Corrupted** |

Three mismatches → output 3.

### Complexity

| Approach | Time | Space |
|---|---|---|
| Single linear scan | O(N × L) | O(1) |

There is no more efficient approach — every byte of every packet must be read at least once. The solution is already optimal.
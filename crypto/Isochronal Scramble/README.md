![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Isochronal Scramble</font>

​	15<sup>th</sup> May 2026

​	Prepared By: `rasti`

​	Challenge Author(s): `wednesdayc`

​	Difficulty: <font color='red'>Hard</font>







# Synopsis

This challenge implements the [CGL isogeny hash function](https://eprint.iacr.org/2006/021.pdf). The goal is to provide a starting curve `E0` and a message `data` such that `CGL_hash(E0, data) == data`. In other words, we are looking for a hashquine (a value which hashes to itself).

The main steps in the solution are:

1. Choose a random destination by selecting a supersingular curve `E_end`.
2. Determine the target value of `data` by calculating the hash of `E_end`.
3. Using the bits of `data` as path directions, walk backwards from `E_end` across the isogeny graph.
4. The curve we arrive at after retracing the steps in `data` is our required `E0`.

The resulting pair `(E0, data)` then satisfies `CGL_hash(E0, data) == E_end`, which when submitted gets us the flag.

# Description

- Deeper still, D9's attestation backbone binds identities to algebraic curves. The access node recognizes only those credentials whose final imprint matches their initial claim. Become your own reflection.

## Skills Required

- Python
- SageMath
- Researching Skills
- Cryptography and Mathematics
- Algebraic Manipulation

## Skills Learned

- Learn about weaknesses in the CGL isogeny hash function.
- Learn how to apply a sequence of 2-isogenies in reverse. 

# Enumeration

## Analyzing the source code

If we look at `challenge.py`, we can see it implements the [CGL isogeny hash function](https://eprint.iacr.org/2006/021.pdf). This algorithm hashes a message by treating the input bits as a path through a graph of supersingular elliptic curves, where

- Nodes: Supersingular elliptic curves over `F_p^2`
- Edges: 2-isogenies between curves 
- Walk: For every bit in the message, the algorithm chooses one of two available outgoing edges to move to the next curve.
- Output: The SHA256 hash of the j-invariant of the final curve.

The challenge script asks us to provide a starting curve `E0` and a message `data` such that `CGL_hash(E0, data) == data`. In other words, we are looking for a hashquine (a value which hashes to itself).

# Solution

## Finding the vulnerability

In this challenge, it is unusual that we have control over the starting curve `E0`, as this deviates from the normal implementation of the CGL hash. If the starting curve `E0` were random and fixed, then finding a hashquine would be extremely difficult unless we could break the collision resistance of the hash function.

By allowing us to choose `E0`, this transforms the problem into a graph search problem. Instead of forcing the path to match the data, we can fix the destination curve and walk backward to find the origin.

The main steps in the solution are hence:

1. Choose a random destination by selecting a supersingular curve `E_end`.
2. Determine the target value of `data` by calculating the hash of `E_end`.
3. Using the bits of `data` as path directions, walk backwards from `E_end` across the isogeny graph.
4. The curve we arrive at after retracing the steps in `data` is our required `E0`.

The resulting pair `(E0, data)` then satisfies `CGL_hash(E0, data) == E_end`.

# Exploitation

The challenge uses the Yoshida-Takashima algorithm (2009) for computing isogenies. To reverse the walk corresponding to `data`, we must invert the algebraic steps performed by the `next_curve` and `CGL_hash` functions.

### Step 1. Recovering internal state (A, alpha).

The `CGL_hash` function outputs a curve defined by coefficients `new_A` and `new_B`. These are derived from the internal state variables `A` (the `a4` invariant of the previous curve) and `alpha` (the x-coordinate of the kernel generator). The corresponding forward code is:

```python
    xi = alpha**2
    new_A = -(4 * A + 15 * xi)
    new_B = -alpha * (8 * A + 22 * xi)
```

To reverse this, we treat `A` and `alpha` as unknowns. We can then express `A` in terms of `new_A` and `alpha`:

```
A = (-new_A - 15alpha^2) / 4
```

Substituting this into the equation for `new_B` yields a cubic equation in terms of `alpha`:
```
8alpha^3 + 2*new_A*alpha - new_B = 0
```
We solve this cubic to find possible values for `alpha`. This gives us potential 'final states' of the walk.

### Step 2. Inverting the Step function

The core loop moves from the curve `(A, alpha)` to `(new_A, new_alpha)` based on a bit `b`. The forward logic calculates:
```
new_A = -(4A + 15 * alpha^2)
new_alpha = alpha +/- 2sqrt(3*alpha^2 + A)
```
Once again, solving for `A` we get
```
A = (-new_A - 15alpha^2) / 4
```

Substituting into the second equation, we then get
```
new_alpha - alpha = +/- sqrt(-(3alpha^2 + new_A))
```
Squaring both sides gives
```
new_alpha^2 - 2*alpha*new_alpha + alpha^2 = -(3alpha^2 + new_A)
```
and hence we get a quadratic in `alpha`:

```
4alpha^2 - 2*new_alpha*alpha + (new_alpha^2 + new_A) = 0
```

The roots of this polynomial correspond to possible preimages of the `next_curve` function.

### Step 3. Branch and prune

Since not every root of the cubic or quadratic equations yields a valid path corresponding to the specific bits in `data`, we perform a depth first search to find a valid path:

1. Start with `E_end`.
2. Solve the cubic to get three initial candidates.
3. For each bit in `data` (processing from last to first):
 - Solve the quadratic to find potential previous states.
 - Verify if the forward step from that candidate matches the required bit.
 - If it matches, recurse.

After a minute or so of searching, we traverse the full length of `data` and arrive at a valid coefficient pair `(A, B)` for `E0`.

## Getting the flag

Once we have found a valid coefficient pair `(A, B)` matching the chosen value of `data`, we can construct the corresponding elliptic curve as follows:

```python
E = EllipticCurve(K, [A, B])
```

To obtain the flag, we can connect to the server submit the starting curve and data to be hashed using `pwntools`:

```python
conn = pwn.connect(REMOTE, PORT)
conn.sendlineafter(b"a4.0 > ", str(E_start.a4()[0]).encode())
conn.sendlineafter(b"a4.1 > ", str(E_start.a4()[1]).encode())
conn.sendlineafter(b"a6.0 > ", str(E_start.a6()[0]).encode())
conn.sendlineafter(b"a6.1 > ", str(E_start.a6()[1]).encode())
```

The server will verify the submitted data forms a hashquine, and if successful, will print the flag.


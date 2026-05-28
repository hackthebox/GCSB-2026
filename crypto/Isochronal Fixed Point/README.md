![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='5'>Isochronal Fixed Point</font>

​	15<sup>th</sup> May 2026

​	Prepared By: `rasti`

​	Challenge Author(s): `wednesdaycc`

​	Difficulty: <font color='darkred'>Insane</font>









# Synopsis

This challenge is centered around a weakness in the [CGL isogeny hash function](https://eprint.iacr.org/2006/021.pdf) when the starting curve is not chosen randomly.

During the registration phase, the challenge asks us to provide a starting curve `E0` and messages `data` such that `CGL_hash(E0, data) == literal_eval(data)`. In other words, these messages are hashquines (a value which hashes to itself).

Once a quine has been registered, we can then pass data which hashes to the same value to `eval()`. The ultimate goal of the chalenge then is to find a collision between a hashquine and a python code execution payload.

The solution to this challenge hence involves solving two smaller subproblems:

- Given `E_end` and `data`, find `E0` such that `CGL_hash(E0, data) == sha256(E_end.j_invariant())`
- Generate a collision by flipping bits in `data` without changing hash output

# Description

- The backbone's registry accepts self-proving credentials and allows them to be superseded by colliding attestations. What verifies as identity can be made to verify as instruction. Cross the threshold from proof to execution.



## Skills Required

- Python
- SageMath
- Researching Skills
- Cryptography and Mathematics
- Algebraic Manipulation

## Skills Learned

- Learn applications for exceptional j-invariants in the supersingular isogeny graph.
- Learn about weaknesses in the CGL isogeny hash function.
- Learn how to apply a sequence of 2-isogenies in reverse. 
- Learn about short `eval` payloads for code execution in Python

# Enumeration

## Analyzing the source code

Looking at `challenge.py`, we can see it implements the [CGL isogeny hash function](https://eprint.iacr.org/2006/021.pdf). This algorithm hashes a message by treating the input bits as a path through a graph of supersingular elliptic curves, where

- Nodes: Supersingular elliptic curves over `F_p^2`
- Edges: 2-isogenies between curves 
- Walk: For every bit in the message, the algorithm chooses one of two available outgoing edges to move to the next curve.
- Output: The SHA256 hash of the j-invariant of the final curve.

During the registration phase, the challenge asks us to provide a starting curve `E0` and messages `data` such that `CGL_hash(E0, data) == literal_eval(data)`. In other words, these messages are hashquines (a value which hashes to itself).

Once a quine has been registered, we can then pass data which hashes to the same value to `eval()`. The ultimate goal of the chalenge then is to find a collision between a hashquine and a python code exec payload.

# Solution

## Finding the vulnerability

In this challenge, it is unusual that we have control over the starting curve `E0`, as this deviates from the normal implementation of the CGL hash. If the starting curve `E0` were random and fixed, then finding a hashquine would be extremely difficult unless we could break the collision resistance of the hash function.

By allowing us to choose `E0`, this transforms the problem into a graph search problem. Instead of forcing the path to match the data, we can fix the destination curve and walk backward to find the origin. This allows us to generate hashquines.

Once a hashquine is found, we then need to find a value which collides with it. Here, we can again use our control of the starting `E0`. Since in the 2-isogeny graph there are two distinct edges going from j-invariant `1728` j-invariant to j-invariant `28749`, this means that after walking to j-invariant `1728` the next curve will be `287496` regardless of the value of the input bit `b`.

Hence by controlling the choice of `E0` such that the walk passes through the curve with j-invariant `1728`, we can flip two bits in the input without changing the output of the hash.

# Exploitation

Implementing the solution to this challenge involves solving two smaller subproblems.

### Subproblem 1: Given `E_end` and `data`, find `E0` such that `CGL_hash(E0, data) == sha256(E_end.j_invariant())`

Note that this is different to solving the hash preimage problem, since here we are finding a possible starting curve given the hash output, rather than finding `data`.

We can transform this problem into a graph search problem by walking backward from the destination curve to find the origin.

#### Subproblem 1 solution overview

The main steps in solving problem 1 are:

1. Choose a random destination by selecting a supersingular curve `E_end`.
2. Determine the target value of `data` by calculating the hash of `E_end`.
3. Using the bits of `data` as path directions, walk backwards from `E_end` across the isogeny graph.
4. The curve we arrive at after retracing the steps in `data` is our required `E0`.

The resulting pair `(E0, data)` then satisfies `CGL_hash(E0, data).j_invariant() == sha256(E_end.j_invariant())`.

The challenge uses the Yoshida-Takashima algorithm (2009) for computing isogenies. To reverse the walk corresponding to `data`, we must invert the algebraic steps performed by the `next_curve` and `CGL_hash` functions.

##### Step 1. Recovering internal state (A, alpha).

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

##### Step 2. Inverting the Step function

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

##### Step 3. Branch and prune

Since not every root of the cubic or quadratic equations yields a valid path corresponding to the specific bits in `data`, we perform a depth first search to find a valid path:

1. Start with `E_end`.
2. Solve the cubic to get three initial candidates.
3. For each bit in `data` (processing from last to first):
 - Solve the quadratic to find potential previous states.
 - Verify if the forward step from that candidate matches the required bit.
 - If it matches, recurse.

After a minute or so of searching, we traverse the full length of `data` and arrive at a valid coefficient pair `(A, B)` for `E0`.

### Subproblem 2: Generate collision by flipping bits in `data` without changing hash output

Once a hashquine is found, we then need to find a value which collides with it. Here, we can again use our control of the starting `E0`. Since in the 2-isogeny graph there are two distinct edges going from j-invariant `1728` j-invariant to j-invariant `28749`, this means that after walking to j-invariant `1728` the next curve will be `287496` regardless of the value of the input bit `b`.

Hence by controlling the choice of `E0` such that the walk passes through the curve with j-invariant `1728`, we can flip two bits in the input without changing the output of the hash.

```
Path 1: 287496 --1--> 1728 --0--> 1728 --1--> 28749 --1--> 377918644469434114298675688 
Path 2: 287496 --1--> 1728 --0--> 1728 --0--> 28749 --0--> 377918644469434114298675688

Result: Bitflips at these indices!       ^            ^
```

We can then align this bitflip to change a comment character (`#`: `0b00100011`) to a space (` `: `0b00100000`). This allows us to append arbitrary code after the comment to pass the quine test, which will be revealed once we flip the comment to a plus. For example:

```
"8c2c1bd881f19df65a0f5c3ec4aea640b3f9d6641a45715ffd3b5a12373504e7"#+breakpoint()
"8c2c1bd881f19df65a0f5c3ec4aea640b3f9d6641a45715ffd3b5a12373504e7" breakpoint()
```

The first payload passes the quine test since `literal_eval` will stop processing after the comment, whereas the latter has the same hash value but will drop into a debugger when passed to `eval`.

## Getting the flag

Now that we have solutions to subproblems 1 and 2, we can put them together to form the final solution. The general strategy is this:

1. Let `E0` be a curve with j-invariant `1728`.
2. Walk along the path represented by the bits `suffix := (1, 1) + data_to__bits("+breakpoint()")`. Let `E_end` be the destination curve.
3. Let `hsh = sha256(E_end.j_invariant())`.
4. Let `prefix = data_to_bits(f'"{j_hash(E_end)}"') + (0, 0, 1, 0, 0, 0)`.
5. Use the solution to subproblem 1 to find a curve `E_sol` such that walking from `E_sol` along `prefix + suffix` ends up at `E_end`.
6. Use the solution to subproblem 2 to invert the first two bits of the suffix. This changes the suffix from 
   `#+breakpoint()` to ` +breakpoint()` without changing the hash output. Let `suffix2` be the result of this inversion.
7. Submit `E0` as the starting curve, `prefix + suffix` as the hashquine, and `prefix + suffix2` as the payload to be passed into `eval`. 

When submitted, our payload will execute the `breakpoint()` function inside the remote process. This drops us into a Python debugging shell, from which we can extract the flag by executing `print(FLAG)`.


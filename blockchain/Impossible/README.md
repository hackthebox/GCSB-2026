# Impossible

23<sup>th</sup> April 2026

Prepared By: `fevtoshi`

Challenge Author(s): `fevtoshi`

Difficulty: Hard

<br>

# Synopsis

This challenge exploits a soundness bug in Jolt zkVM's batched sumcheck verification. The verifier uses prover-controlled `opening_claims` in its equations, but does not bind those claims into the Fiat-Shamir transcript before deriving the batching challenges. Combined with Jolt's linear compression trick, that lets you:

- Forge a valid Jolt proof for the `impossible` guest program without knowing the actual password.
- Bypass the off-chain password verification gate.
- Trigger an on-chain `openReserve` call from the privileged relay.
- Drain the `VeyraReserve` contract's 100 ETH reserve.

The instance is solved once `Setup.isSolved() == true`, meaning:
- `VeyraReserve.egressAuthorized == true`
- `VeyraReserve` has been drained to zero balance

## Description

In the quiet cyber cold war between the Republic of Aster and the Directorate of Veyra, `Impossible` is a sealed on-chain reserve tied to hostile operations. Access is tightly controlled, movement is restricted, and the gate is guarded by advanced zero-knowledge machinery. The system is meant to withstand outside intrusion. Your task is to prove otherwise.

## Skill Required

- Zero-Knowledge Proofs (ZKP) fundamentals (sumcheck, Fiat-Shamir heuristic)
- Cryptographic Vulnerabilities (transcript ordering bugs)
- Rust Programming (interacting with zkVM SDKs and proof generation)
- Solidity (smart contract analysis)
- Foundry (interacting with the blockchain)

## Skills Learned

- Identifying and exploiting Fiat-Shamir transcript bugs (unbound variables) in modern zkVMs
- Forging valid ZK proofs for false statements by exploiting linear verification equations

# Enumeration

## Analyzing the Source Code

Relevant files:
- `contracts/VeyraReserve.sol` — The target contract holding 100 ETH.
- `chall/guest/src/lib.rs` — The Jolt guest program verifying the password.

---

### Files

- `VeyraReserve.sol` — Hostile reserve contract
  - Stores an `accessPhraseHash` (SHA-256) of the required password.
  - Can only be opened (`openReserve`) by the privileged `authorizedRelay`.
  - Once egress is authorized, anyone can call `exfiltrateReserve()` to drain the 100 ETH.

- `lib.rs` (Guest) — The `impossible` function
  - A simple RISC-V program provable with Jolt.
  - Checks if `Sha256::digest(&password[..n]) == expected_access_phrase_hash`.

---

#### `Jolt Vulnerability`

The root cause is a **transcript ordering bug** in Jolt's batched sumcheck protocol.

Jolt uses `opening_claims` from the proof inside batched verification equations, but it does **not** hash those claims into the Fiat-Shamir transcript before deriving the random batching coefficients ($\alpha_i$). That breaks soundness:
1. The verifier's random challenges are fixed independently of the prover's claimed openings.
2. Several of those openings are **virtual** polynomials, so they are not cryptographically bound by the commitment scheme.
3. The final batched verification equations are linear in those virtual `opening_claims`.
4. An attacker can therefore solve for forged deltas ($\Delta w, \Delta r$) that make a false statement verify successfully.

---

# Solution

## Finding the vulnerabilities

1. **Unbound `opening_claims`**: The verifier derives batching challenges before absorbing the prover's `opening_claims`. This violates the Fiat-Shamir requirement that challenges depend on all prior messages.

2. **Linear batched check**: Jolt's sumcheck compression makes the final verification equation a linear combination of per-instance claims. Once the challenges are known, forging becomes a straightforward linear solve.

---

## Exploitation

The exploit is implemented in `htb/solver/src/main.rs` as a standalone Rust crate pinned to Jolt commit `710e678bfa3bcdd3f3a229485308ac7a3841f5ee`:

1. **Trace with Wrong Password**: Run the guest with an arbitrary password. The honest result is `false`.
2. **Forge Output**: Replace the claimed guest output with `true`.
3. **Recover Verifier Data**: Replay the vulnerable verifier logic locally to recover the Stage 3 and Stage 4 batching coefficients and the Stage 3 discrepancy ($D_3$).
4. **Solve Linear System**:
   - Use the recovered coefficients to express the verifier checks as linear equations.
   - Solve for the deltas required in the virtual `RamRa` and `InstructionRa` `opening_claims`.
5. **Patch and Submit**: Patch the serialized proof bytes with those forged `opening_claims`. The resulting proof is accepted even though the password is wrong.
6. **Trigger Relay**: Submit the forged proof to `/api/verify`. The server verifies it and calls `openReserve()`.
7. **Exfiltrate Reserve**: Call `exfiltrateReserve()` on the contract to claim the 100 ETH.

---

### Getting the flag

Use the provided [solver.sh](./htb/solver.sh):

```bash
chmod +x htb/solver.sh
./htb/solver.sh
```

**FLAG:** HTB{REDACTED}

---

## References

- [zkVMs’ Unfaithful Claims - Osec](https://osec.io/blog/2026-03-03-zkvms-unfaithful-claims/)

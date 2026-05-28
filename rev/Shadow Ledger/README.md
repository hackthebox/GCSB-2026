
![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Shadow Ledger</font>

13<sup>th</sup> April 2026

Prepared By: `Kailash S`

Challenge Author(s): `Kailash S`

Difficulty: <font color='green'>Easy</font>








## Synopsis

We're given a stripped x86-64 binary that checks a 4-byte hex key. The verification doesn't compare anything explicitly  it uses an _implicit flow_: for each correct bit, the binary executes a NOP sled that slightly increases the total instruction count. A massive "solver trap" loop is there to make angr and Triton hang forever. The actual check is invisible to any standard tool. The only way to recover the key is to use Intel Pin, count instructions across 33 runs (one baseline + one per bit), and read the delta. Positive delta = bit is 1, negative = bit is 0. Build the key from the 32 deltas, feed it in, get the flag.

## Description

 _Berlin's last transmission before going dark was three words: "Don't count the money. Count the shadows."_

 Task Force Nightfall intercepted a verification daemon that The Professor's unit embedded across compromised SWIFT relay nodes in Sector 7. It's not ransomware. It's the lock on the back door of a financial clearance pipeline moving capital for three allied governments.

## Skills Required

- Static binary analysis (Ghidra / IDA)
- Python scripting
- Understanding of dynamic analysis limitations

## Skills Learned

- Dynamic Taint Analysis and implicit flows
- Dynamic Binary Instrumentation with Intel Pin
- Side-channel key recovery via instruction counting
- Branchless vs branchy code and why it matters for measurement

## MITRE Mappings

- `T1140 — Deobfuscate/Decode Files or Information` — the key is never stored; it's reconstructed from runtime execution behaviour
- `T1027 — Obfuscated Files or Information` — a massive computational trap obfuscates the real verification path from automated analysis tools

## Enumeration

### Given Files

Unzip the release and you get one file: `shadow_ledger`.

```bash
$ file shadow_ledger
shadow_ledger: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

Stripped, x86-64, dynamically linked. Standard stuff.

```bash
$ strings shadow_ledger | grep -i htb
(nothing)

$ strings shadow_ledger | head -20
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
sscanf
...
```

`strings` gives us nothing useful. No flag, no key, no hints. Fine.

```bash
$ ./shadow_ledger
  ╔══════════════════════════════════════════════════════╗
  ║   SHADOW LEDGER // NIGHTFALL VERIFICATION NODE       ║
  ╚══════════════════════════════════════════════════════╝

  usage  : ./shadow_ledger <8-digit hex key>
  example: ./shadow_ledger deadbeef

$ ./shadow_ledger cafebabe
  [-] ACCESS DENIED
  [-] KEY MISMATCH  —  ALERT DISPATCHED TO SECTOR 7
```

Takes one argument: an 8-hex-digit key. Wrong key, access denied.

---

### Looking at the Binary in Ghidra

Load it up. It's stripped so there are no function names, but the logic is short enough to follow. There are three distinct parts.

**Part 1 — The function that always runs first**

```c
void FUN_001(uint32_t seed) {
    uint64_t s = ((uint64_t)seed << 17) ^ 0xDEADBEEFCAFEBABEULL;
    for (int i = 1; i <= 65536; i++) {
        s ^= rotl64(s, 13);
        s ^= (s >> 7);
        s ^= rotl64(s, 17);
        s *= 0x2545F4914F6CDD1DULL;
        s = s % ((uint64_t)i * 31337ULL + 1ULL);
    }
}
```

65536 iterations of XorShift64* multiplication and per-iteration modulo. The output is **never used**. This function exists for one reason: to make symbolic execution tools (angr, Triton) run out of time or memory. The 64-bit multiply and variable modulo produce non-linear SMT constraints that blow up any solver. If you point angr at this binary, it will hang here and never reach the actual check.

**Part 2 — The real verification**

```c
void FUN002(int correct) {
    if (correct) {
        asm volatile(
            "nop\n nop\n nop\n nop\n nop\n"
            "nop\n nop\n nop\n nop\n nop\n"
        );
        g_shadow_count++;
    }
}

for (int i = 0; i < 32; i++) {
    int input_bit  = (input_key  >> i) & 1;
    int secret_bit = (SECRET_KEY >> i) & 1;
    check_bit(input_bit == secret_bit);
}
```

This is the actual key check and it looks completely harmless. For each bit of your input, it compares it against the secret key. If they match, it runs 10 NOPs and increments a counter. If they don't match, it falls through doing nothing.

There is no `if input == secret`. There is no subtraction or XOR of your input against a target. Your input is never directly "compared" to anything in a way that a debugger or taint tracker would catch. The information about whether you got the bit right is encoded purely in _how many instructions executed_ — not in any register value or memory write. This is called an **implicit flow**.

**Part 3 — The opaque predicate**

```c
volatile uint64_t n      = g_shadow_count;
volatile int      opaque = (int)((n * (n + 1ULL)) & 1ULL);  // always 0

if (g_shadow_count == 32ULL && opaque == 0) {
    puts("HTB{...}");
}
```

`n * (n+1)` is always even for any integer n (one of them is always divisible by 2), so `& 1` is always 0. The condition always simplifies to just `g_shadow_count == 32`. But since `g_shadow_count` is a global that's only modified inside `check_bit`, a static disassembler can't determine its value at analysis time — so Ghidra marks the success branch as "possibly unreachable." Nice touch.

### Why Every Standard Tool Fails

|Tool|Why it fails|
|---|---|
|`strings`|No hardcoded secret, no flag in plaintext|
|`ltrace`|No library call that takes the key as input to a comparison|
|`strace`|Same — no syscall leaks the comparison result|
|GDB / manual debugging|You can see the branch in `check_bit` but the counter is never inspected against your input in a single observable moment|
|angr / Triton|Hangs in `solver_trap` — 65536 iterations of non-linear arithmetic exhausts the constraint solver|
|Dynamic taint analysis|Your input taints the branch condition register, but the taint never reaches a memory write or output — no sink is ever reached|


## The Solve Idea

Berlin's hint: _"Don't count the money. Count the shadows."_

The binary leaks information through the **number of instructions it executes**, not through any data value. For each correct bit, exactly ~13 more instructions run (10 NOPs + the increment + call/return overhead). For each wrong bit, ~13 fewer instructions run compared to baseline.

So the solve is:

1. Run with `00000000` → get baseline instruction count
2. For each of the 32 bits, run with key = `1 << bit`
3. Measure delta vs baseline
4. `delta > 0` → secret bit is 1. `delta < 0` → secret bit is 0.
5. Assemble the 32 bits into the key, verify

This is 33 total runs. The tool for measuring instruction counts is **Intel Pin** — a Dynamic Binary Instrumentation framework from Intel that can instrument every instruction as it executes.

---

## Building the Pintool

We need a Pin plugin (called a Pintool) that counts every instruction executed and prints the total at exit.

```cpp
#include "pin.H"
#include <iostream>
using std::cout; using std::endl;

static UINT64 g_icount = 0;

// Called once per basic block — add that block's instruction count
VOID PIN_FAST_ANALYSIS_CALL AddCount(UINT32 count) {
    g_icount += count;
}

// Instrument every basic block to call AddCount
VOID Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)AddCount,
                       IARG_FAST_ANALYSIS_CALL,
                       IARG_UINT32, BBL_NumIns(bbl),
                       IARG_END);
    }
}

// Print the count when the program exits
VOID Fini(INT32 code, VOID *v) {
    cout << "SHADOW_COUNT: " << g_icount << endl;
}

int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
```

Why BBL (basic block) level instead of per-instruction? Performance. Basic blocks are sequences of instructions with no branches — Pin instruments the entry of each block and adds its known instruction count in one shot. Way faster than inserting a callback before every single instruction.

Build it:

```bash
cp icount.cpp $PIN_ROOT/source/tools/ManualExamples/
mkdir -p $PIN_ROOT/source/tools/ManualExamples/obj-intel64
make -C $PIN_ROOT/source/tools/ManualExamples PIN_ROOT=$PIN_ROOT obj-intel64/icount.so
cp $PIN_ROOT/source/tools/ManualExamples/obj-intel64/icount.so icount.so
```

We build inside Pin's own `ManualExamples/` directory because Pin's Makefile system requires `EXPORT_ROOT` to be set correctly — which only works from inside Pin's own source tree.

Test it:

```bash
$PIN_ROOT/pin -t icount.so -- ./shadow_ledger 00000000
# SHADOW_COUNT: 7389482

$PIN_ROOT/pin -t icount.so -- ./shadow_ledger 00000000
# SHADOW_COUNT: 7389482   ← same every time, good — deterministic
```

```bash
$PIN_ROOT/pin -t icount.so -- ./shadow_ledger deadbeef
# SHADOW_COUNT: 7392036   ← higher, signal is real
```

`7392036 - 7389482 = 2554` — that's more NOP sleds firing for a key closer to the answer. The delta exists. Let's automate it.

---

## The Solve Script

Here's how we setup the solve script:

**Setup — paths from environment**

```python
BINARY   = os.environ.get("BINARY",  os.path.join(SCRIPT_DIR, "..", "release", "rev_shadow_ledger", "shadow_ledger"))
PINTOOL  = os.environ.get("PINTOOL", os.path.join(SCRIPT_DIR, "icount.so"))
PIN_ROOT = os.environ.get("PIN_ROOT", "/pin")
PIN      = os.path.join(PIN_ROOT, "pin")
```

Read paths from env vars so the same script works locally and inside Docker without changing anything. Defaults fall back to sensible relative paths.

**Running Pin and parsing the count**

```python
def run_with_pin(key_int: int) -> int:
    key_str = f"{key_int:08x}"
    cmd = [PIN, "-t", PINTOOL, "--", BINARY, key_str]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    for line in output.splitlines():
        if "SHADOW_COUNT:" in line:
            return int(line.split(":")[-1].strip())
    return -1
```

Pin writes its output to stdout. We capture both stdout and stderr (Pin sometimes writes to stderr), find the tagged line `SHADOW_COUNT: N`, and parse the number. The tagged format means we never accidentally pick up a stray number from the binary's own output.

**Step 1 — Baseline**

```python
baseline = run_with_pin(0x00000000)
```

With an all-zero key: every bit where the secret is 0 gives `(0 == 0) = correct` → NOP sled fires. Every bit where the secret is 1 gives `(0 == 1) = wrong` → NOP sled doesn't fire. The baseline captures how many NOP sleds execute when the non-matching bits are all in their zero state.

**Step 2 — Bit sweep**

```python
recovered_key = 0
for bit in range(32):
    test_key = 1 << bit      # only flip one bit at a time
    count    = run_with_pin(test_key)
    delta    = count - baseline

    if delta > 0:
        recovered_key |= test_key   # this bit is 1 in the secret key
```

When we flip bit `i` from 0 to 1:

- If the secret has bit `i` = **0**: we had `(0 == 0) = correct`, now we have `(1 == 0) = wrong`. We **lose** a NOP sled. Delta is **negative**.
- If the secret has bit `i` = **1**: we had `(0 == 1) = wrong`, now we have `(1 == 1) = correct`. We **gain** a NOP sled. Delta is **positive**.

So `delta > 0` means that bit is 1 in the secret. We OR it into `recovered_key`.

**Step 3 — Verify**

```python
result = subprocess.run([BINARY, f"{recovered_key:08x}"], capture_output=True, text=True)
if "HTB{" in result.stdout:
    print("[+] KEY RECOVERED")
```

Run the binary directly (no Pin overhead) with the recovered key. Flag in output = done.

---

## Running It

```
Baseline: 7,389,482

  Bit  0: 7,389,469  (Δ=-13)  bit=0
  Bit  1: 7,389,495  (Δ=+13)  bit=1
  Bit  2: 7,389,495  (Δ=+13)  bit=1
  Bit  3: 7,389,469  (Δ=-13)  bit=0
  Bit  4: 7,389,495  (Δ=+13)  bit=1
  Bit  5: 7,389,469  (Δ=-13)  bit=0
  Bit  6: 7,389,469  (Δ=-13)  bit=0
  Bit  7: 7,389,469  (Δ=-13)  bit=0
  Bit  8: 7,389,469  (Δ=-13)  bit=0
  Bit  9: 7,389,469  (Δ=-13)  bit=0
  Bit 10: 7,389,469  (Δ=-13)  bit=0
  Bit 11: 7,389,469  (Δ=-13)  bit=0
  Bit 12: 7,389,469  (Δ=-13)  bit=0
  Bit 13: 7,389,469  (Δ=-13)  bit=0
  Bit 14: 7,389,469  (Δ=-13)  bit=0
  Bit 15: 7,389,469  (Δ=-13)  bit=0
  Bit 16: 7,389,495  (Δ=+13)  bit=1
  Bit 17: 7,389,469  (Δ=-13)  bit=0
  Bit 18: 7,389,469  (Δ=-13)  bit=0
  Bit 19: 7,389,495  (Δ=+13)  bit=1
  Bit 20: 7,389,469  (Δ=-13)  bit=0
  Bit 21: 7,389,495  (Δ=+13)  bit=1
  Bit 22: 7,389,469  (Δ=-13)  bit=0
  Bit 23: 7,389,469  (Δ=-13)  bit=0
  Bit 24: 7,389,495  (Δ=+13)  bit=1
  Bit 25: 7,389,495  (Δ=+13)  bit=1
  Bit 26: 7,389,495  (Δ=+13)  bit=1
  Bit 27: 7,389,495  (Δ=+13)  bit=1
  Bit 28: 7,389,469  (Δ=-13)  bit=0
  Bit 29: 7,389,495  (Δ=+13)  bit=1
  Bit 30: 7,389,495  (Δ=+13)  bit=1
  Bit 31: 7,389,495  (Δ=+13)  bit=1

Recovered key: 0xdeadc0de

  [+] VERIFICATION COMPLETE
  [+] NIGHTFALL AUTHORISATION ACCEPTED
  [+] 

[+] KEY RECOVERED  —  NIGHTFALL AUTHORISATION COMPLETE
```

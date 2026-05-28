![img|43](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Dudsat?</font>

15<sup>th</sup> March 2026

Prepared By: `Kailash S`

Challenge Author(s): `Kailash S`

Difficulty: <font color='orange'>Medium</font>

<br><br>

# Synopsis

`lbproc` presents itself as a routine RF link budget validation tool ,  the kind of utility that runs unattended on ground station terminals, processes satellite contact window logs, and prints a line of LOCK or NO-LOCK status for each acquisition window. The output is clean, the output format is realistic, and the binary is exactly the right size to be what it claims.

The flag does not exist anywhere in the binary or the data file. It exists only as the runtime output of a two-stage silent computation that the binary performs on every record without ever printing the intermediate values. The first stage is a Doppler prediction model with a deliberately miscalibrated constant  one that produces controlled, deterministic residuals per record. The second stage is a permutation table built from HELIOS-7's own orbital parameters before `main()` even runs, via a GCC constructor registered in `.init_array`. The flag byte at each position is `perm_table[residual & 0xFF]`. Neither stage is visible in the binary's output. Both must be reversed from compiled code  without any symbol names to guide the analysis.

## Description

ORBIT-9 Solutions runs the ground station that talks to HELIOS-7. Three rail networks trust its timing. So does a clearing system that moves money across four countries.

Six weeks ago someone quietly bought ORBIT-9. Last week the clearing system froze for eleven hours. Yesterday a regional airport logged position drift during a HELIOS-7 pass.

Not accidents. Tests.

A burned asset codenamed FERRYMAN pulled one file off an ORBIT-9 maintenance laptop before going dark. A binary — `lbproc` — described internally as a _"link budget validation tool"_. Along with it: fourteen minutes of raw observation data from HELIOS-7's last contact window.

FERRYMAN's final transmission was five words.

> _The numbers are not noise._

You have the binary. You have the log. The ground station is offline and the window is closing.

Figure out what passed through that contact window , because whoever was on the receiving end is still waiting for it.

## Skills Required

- x86-64 assembly reading at intermediate level
- Static analysis with Ghidra or any decompilation tool .
- ELF binary internals  section headers, `.init_array`, constructor mechanism
- Python scripting for binary parsing and arithmetic reconstruction
- IEEE 754 double-precision floating point basics

## Skills Learned

- Identifying and exploiting `.init_array` GCC constructors  code that executes before `main()` and is invisible to players who only trace explicit call graphs
- Recovering a permutation table construction from assembly  Fisher-Yates shuffle driven by a linear congruential generator, extracting both the LCG parameters and the seed formula from compiled code
- Recognising deliberately miscalibrated physics constants as a covert channel  understanding how a wrong `C` in a Doppler formula produces controlled, meaningful residuals
- Precision extraction of `volatile const` doubles from `.rodata` using IEEE 754 byte pattern scanning
- Identifying and blocking data-file algebraic shortcuts  understanding why sub-integer noise in `f_observed` prevents recovery of the Doppler constant without touching the binary

## MITRE Mappings

- **T1020 – Automated Exfiltration** The full two-stage pipeline runs automatically on every execution with no operator interaction. The constructor fires pre-`main`, residuals are computed per record, the table lookup produces the covert payload, and all of it is invisible in the printed output.
- **T1027.013 – Obfuscated Files or Information: Indirect Encoding** The flag requires two independent reversing acts  the Doppler constant and the permutation table  and their composition to understand. Neither the residuals alone nor the table alone constitute the payload. The encoding is structural, not cryptographic.
- **T1574.006 – Hijack Execution Flow: Dynamic Linker** `init_pass_profile` executes via the dynamic linker's `.init_array` mechanism before `main`  a technique used in real implants to establish state before any audited entry point runs.
- **T1029 – Scheduled Transfer** In operational deployment, `lbproc` runs on a schedule tied to satellite pass windows. The TLE parameters change with each pass  so the permutation table, and therefore the encoded payload, is different on every execution. Detection by repetition is impossible.

# Enumeration

### Analysing the Given Files

Two files are provided:

```
lbproc      — ELF 64-bit binary
comms.dat   — binary observation log, 1248 bytes
```

Running `file` on both:

```bash
$ file lbproc
lbproc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=07441b97d11c0344ed3f06ab883ccfaf8d436589,
for GNU/Linux 3.2.0, stripped

$ file comms.dat
comms.dat: data
```

A standard x86-64 binary, fully stripped. `comms.dat` has no magic bytes, no readable strings, nothing that identifies its format , the format most likely must be recovered from the binary.

Running `strings` produces the expected set of operational strings for an RF ground station tool, and nothing else. No flag. No encrypted blobs. No high-entropy garbage.

```bash
$ strings lbproc | grep -v "^.$"
NO-LOCK
Usage: %s <observation_log>
Contact window analysis: %s
lbproc: calibration check failed
lbproc: cannot open observation log
ORBIT-9 Solutions — Link Budget Processor v4.1.2
[%s] window=%03u  f0=%9.3f MHz  status=%s
Processed %d windows. %d acquired, %d lost.
```

Running the binary produces exactly what those strings suggest:

```bash
$ ./lbproc comms.dat
ORBIT-9 Solutions — Link Budget Processor v4.1.2
Contact window analysis: comms.dat
---------------------------------------------------
[2024-03-15T01:52:33Z] window=001  f0= 8025.000 MHz  status=NO-LOCK
[2024-03-15T01:52:47Z] window=002  f0= 8025.000 MHz  status=LOCK
[2024-03-15T01:53:01Z] window=003  f0= 8025.000 MHz  status=LOCK
...
[2024-03-15T01:58:23Z] window=026  f0= 8025.000 MHz  status=NO-LOCK
---------------------------------------------------
Processed 26 windows. 24 acquired, 2 lost.
```

Clean, boring, legitimate-looking output. Nothing anomalous. The first and last windows are `NO-LOCK`  consistent with low elevation at the edges of a satellite pass  and the remaining 24 are `LOCK`. There is nothing to decode in this output directly.

### Section Headers and `.init_array`

Before opening a disassembler, running `readelf -S` reveals the section layout:

```bash
$ readelf -S --wide lbproc
  [Nr] Name              Type            Address          Off    Size
  [15] .text             PROGBITS        00000000004011b0 0011b0 000456
  [17] .rodata           PROGBITS        0000000000402000 002000 0001c0
  [20] .init_array       INIT_ARRAY      0000000000403df0 002e08 000010
  [25] .data             PROGBITS        0000000000404078 003078 000010
  [26] .bss              NOBITS          00000000004040a0 003088 000120
```

`.init_array` has size `0x10`  two 8-byte entries. The standard C runtime always occupies the first slot. The second slot at `0x00403df8` is a non-standard function pointer. This means something runs before `main()`.

```bash
$ readelf -x .init_array lbproc

Hex dump of section '.init_array':
  0x00403e08 00164000 00000000 b0114000 00000000 ..@.......@.....
```

Two pointers: `0x00401600` (standard runtime) and `0x004011b0` (non-standard constructor). The second address points inside `.text`  . It fires before `main` through the dynamic linker's initialisation mechanism.

### Symbol Table

```bash
$ readelf -s lbproc | grep FUNC
```

The binary is fully stripped. The dynamic symbol table shows only imported libc symbols — `fread`, `fopen`, `puts`, `printf`, `ptrace`, `strftime`, `gmtime`, `fabs`, `fclose`. No application function names survive. Ghidra's function list will be populated entirely with auto-named stubs like `FUN_004011b0`, `FUN_00401340`, and so on.
## Decompiling the Binary

### Orienting in a Stripped Binary

Loading `lbproc` into Ghidra with default analysis produces a function list of entirely unnamed stubs. The entry point is identified through the standard `_start` → `__libc_start_main` chain. The function passed as the third argument to `__libc_start_main` is `main` — `FUN_00401220`.

Before renaming anything, three things can be observed immediately from the import list alone:

- `ptrace` is imported — anti-debug is present
- `fread` and `fopen` are imported — the binary reads a binary file
- `strftime` and `gmtime` are imported — timestamps are formatted per-record

That alone tells us the shape of the binary: it opens a file, reads structured records in a loop, and formats timestamps. This is consistent with what `strings` showed.

### Step 2 — Analysing `main` (`FUN_00401220`)

### Discovery: the raw decompile

Ghidra's initial output for `FUN_00401220`, before any renaming:

```c
undefined8 FUN_00401220(int param_1, undefined8 *param_2)
{
  long lVar1;
  FILE *__stream;
  size_t sVar2;
  undefined8 uVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  time_t local_a8 [3];
  double local_90;
  double local_88;
  double local_80;
  float  local_78;
  float  local_74;
  undefined4 local_70;
  char local_68 [40];

  lVar1 = ptrace(PTRACE_TRACEME,0,0,0);
  if (lVar1 == -1) { /* exit 2 */ }
  else if (param_1 == 2) {
    __stream = fopen((char *)param_2[1],"rb");
    /* ... processing loop ... */
    while( true ) {
      sVar2 = fread(local_a8 + 2, 0x30, 1, __stream);
      if (sVar2 != 1) break;
      /* ... lock check, printf ... */
    }
  }
}
```

Three immediate observations that drive the rest of the analysis:

1. The first call is `ptrace(PTRACE_TRACEME)`  a self-tracing anti-debug check. If a debugger is already attached, `ptrace` returns `-1` and the binary exits. This is a side-quest: patch the `je` at the comparison to `jmp`, or use `LD_PRELOAD` to intercept `ptrace`. Either way, it is bypassed in two minutes and never revisited.
2. `fread(local_a8 + 2, 0x30, 1, __stream)`  reads `0x30 = 48 bytes` per iteration. This tells us the record size immediately.
3. The stack layout immediately after `local_a8[2]`  where the 48-byte read lands  is: `local_90` (double), `local_88` (double), `local_80` (double), `local_78` (float), `local_74` (float), `local_70` (uint32). These are the record fields, read directly off the stack.

#### recovering the struct layout

`local_a8` is `time_t[3]` — 3 × 8 bytes. `local_a8 + 2` points to element `[2]`, which is 16 bytes into the array. Immediately following in stack memory are `local_90`, `local_88`, `local_80`, and so on. The 48-byte `fread` fills them in order:

|Stack variable|Record offset|Size|Type|Field|
|---|---|---|---|---|
|`local_a8[2]`|+0|8|uint64|Unix timestamp|
|`local_90`|+8|8|double|`f0` — rest frequency (Hz)|
|`local_88`|+16|8|double|`range_rate` — radial vel (m/s)|
|`local_80`|+24|8|double|`f_observed` — measured rx (Hz)|
|`local_78`|+32|4|float|`elevation` (degrees)|
|`local_74`|+36|4|float|`snr` (dB)|
|`local_70`|+40|4|uint32|`window_id`|
|(padding)|+44|4|uint32|reserved|

`comms.dat` is 1248 bytes. `1248 / 48 = 26` — exactly 26 records, zero remainder.

#### the hidden constant inside the lock check

With variables renamed, the LOCK/NO-LOCK condition in `main` becomes readable:

```c
if ((elevation >= 5.0f) && (snr >= 12.0f) &&
    (fabs(f_observed - (f0 * (1.0 + range_rate / 418229116.0))) <= 5000.0))
    status = "LOCK";
else
    status = "NO-LOCK";
```

This is the classical non-relativistic Doppler prediction formula: `f_pred = f0 × (1 + v/c)`. The elevation and SNR thresholds are standard operational values for an X-band ground station. Everything looks correct  except one number.

The speed of light is **299,792,458 m/s**. The constant in this binary is **418,229,116.0**. That is not a unit conversion. That is not a calibration factor. That is a deliberately wrong value for `c`.

The consequence is immediate: every `f_predicted` this binary computes is systematically wrong. The residual `f_observed − f_predicted` is therefore a controlled, deterministic quantity for every record. Nothing in the binary ever prints that residual.

### The cleaned-up `main`

After renaming all variables, the function reads as:

```c
int main(int argc, char **argv) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        // anti-debug: exit if debugger attached
        return 2;
    }
    FILE *fp = fopen(argv[1], "rb");

    int total = 0, acquired = 0;
    obs_record_t rec;

    while (fread(&rec, 48, 1, fp) == 1) {
        // Format timestamp
        char timebuf[32];
        strftime(timebuf, 32, "%Y-%m-%dT%H:%M:%SZ", gmtime(&rec.timestamp));

        // Doppler prediction — WRONG constant (418229116.0 ≠ c)
        double f_pred = rec.f0 * (1.0 + rec.range_rate / 418229116.0);

        // Lock decision — only this gets printed
        const char *status = "NO-LOCK";
        if (rec.elevation >= 5.0f && rec.snr >= 12.0f &&
            fabs(rec.f_observed - f_pred) <= 5000.0)
            status = "LOCK";

        printf("[%s] window=%03u  f0=%9.3f MHz  status=%s\n",
               timebuf, rec.window_id, rec.f0 / 1e6, status);
        total++;
        if (strcmp(status, "LOCK") == 0) acquired++;
    }
    printf("Processed %d windows. %d acquired, %d lost.\n",
           total, acquired, total - acquired);
}
```

Notice what is missing: there is no computation of `f_observed − f_pred` as a named value, and no storage or printing of the residual. From `main` alone, the residual looks like a throwaway intermediate in the lock condition. The binary prints only LOCK or NO-LOCK. The residual exists, is meaningful, and is invisible.

### Parsing `comms.dat`

With the struct confirmed, all 26 records parse cleanly. The data describes a physically realistic LEO satellite pass:

```
 Win  Timestamp              RR (m/s)    El (°)  SNR (dB)   Status
   1  2024-03-15T01:52:33Z  +6800.00      0.0      8.0    NO-LOCK
   2  2024-03-15T01:52:47Z  +6746.38      9.0     18.5    LOCK
   3  2024-03-15T01:53:01Z  +6586.37     17.9     19.0    LOCK
   4  2024-03-15T01:53:15Z  +6322.48     26.5     19.5    LOCK
   5  2024-03-15T01:53:29Z  +5958.89     34.7     19.9    LOCK
   6  2024-03-15T01:53:43Z  +5501.32     42.3     20.4    LOCK
   7  2024-03-15T01:53:57Z  +4956.99     49.3     20.7    LOCK
   8  2024-03-15T01:54:11Z  +4334.48     55.5     21.1    LOCK
   9  2024-0NO3-15T01:54:25Z  +3643.62     60.8     21.4    LOCK
  10  2024-03-15T01:54:39Z  +2895.30     65.1     21.6    LOCK
  11  2024-03-15T01:54:53Z  +2101.32     68.5     21.8    LOCK
  12  2024-03-15T01:55:07Z  +1274.19     70.7     21.9    LOCK
  13  2024-03-15T01:55:21Z   +426.98     71.9     22.0    LOCK
  14  2024-03-15T01:55:35Z   -426.98     71.9     22.0    LOCK
  15  2024-03-15T01:55:49Z  -1274.19     70.7     21.9    LOCK
  16  2024-03-15T01:56:03Z  -2101.32     68.5     21.8    LOCK
  17  2024-03-15T01:56:17Z  -2895.30     65.1     21.6    LOCK
  18  2024-03-15T01:56:31Z  -3643.62     60.8     21.4    LOCK
  19  2024-03-15T01:56:45Z  -4334.48     55.5     21.1    LOCK
  20  2024-03-15T01:56:59Z  -4956.99     49.3     20.7    LOCK
  21  2024-03-15T01:57:13Z  -5501.32     42.3     20.4    LOCK
  22  2024-03-15T01:57:27Z  -5958.89     34.7     19.9    LOCK
  23  2024-03-15T01:57:41Z  -6322.48     26.5     19.5    LOCK
  24  2024-03-15T01:57:55Z  -6586.37     17.9     19.0    LOCK
  25  2024-03-15T01:58:09Z  -6746.38      9.0     18.5    LOCK
  26  2024-03-15T01:58:23Z  -6800.00      0.0      8.0    NO-LOCK
```

Range rates form a sinusoidal curve from +6800 to −6800 m/s , correct for a LEO pass. Elevation peaks at 71.9° at mid-pass. Windows 1 and 26 are `NO-LOCK` because elevation is 0.0°  below the 5° cutoff. The data is internally consistent and physically realistic. Nothing looks wrong here. The anomaly lives entirely in the arithmetic.

###  The `.init_array` Constructor (`_INIT_1`)

`main` alone explains the LOCK/NO-LOCK output. But it references `perm_table` — a global `uint8_t[256]` at `DAT_004040c0` (`.bss`). Cross-referencing `DAT_004040c0` in Ghidra shows exactly one write site: a function that is never called from `main` and never called from anywhere in the explicit call graph.

The explanation is in `.init_array`:

```bash
$ readelf -x .init_array lbproc

Hex dump of section '.init_array':
  0x00403e08 00164000 00000000 b0114000 00000000
```

Two 8-byte little-endian pointers:

- `0x0000000000401600` — standard C runtime init (`_INIT_0`)
- `0x00000000004011b0` — application constructor (`_INIT_1`)

Ghidra names this second function `_INIT_1`. It is a GCC constructor registered with the dynamic linker through `.init_array`. The dynamic linker calls it before `main()` begins. By the time `main`'s first instruction executes, `_INIT_1` has already run and `perm_table` is fully populated.
### Discovery: the raw decompile

Ghidra's output for `_INIT_1` at `0x004011b0`:

```c
void _INIT_1(void)
{
  undefined1 uVar1;
  long lVar2;
  undefined1 *puVar3;
  undefined1 *puVar4;
  uint uVar5;
  uint uVar6;

  lVar2 = 0;
  do {
    (&DAT_004040c0)[lVar2] = (char)lVar2;
    lVar2 = lVar2 + 1;
  } while (lVar2 != 0x100);
  uVar6 = 0x20fc8;
  puVar3 = &DAT_004041bf;
  do {
    puVar4 = puVar3 + -1;
    uVar6 = uVar6 * 0x19660d + 0x3c6ef35f;
    uVar5 = uVar6 % ((int)puVar3 - 0x4040bfU);
    uVar1 = *puVar3;
    *puVar3 = (&DAT_004040c0)[(int)uVar5];
    (&DAT_004040c0)[(int)uVar5] = uVar1;
    puVar3 = puVar4;
  } while (puVar4 != &DAT_004040c0);
  return;
}
```

The structure is immediately readable even before renaming: a loop counting to `0x100 = 256` fills an array with `i` (identity initialisation), followed by a loop that multiplies by `0x19660d` and adds `0x3c6ef35f` each iteration (LCG), computes a modulo for a swap index, and swaps two array elements (Fisher-Yates). The seed is hardcoded as the literal `0x20fc8`.

### the constant-folded seed

The seed `0x20fc8 = 135112` appears as a **compile-time constant**. GCC evaluated the entire TLE XOR expression at compile time and replaced it with the result. The TLE floating-point loads and XOR operations are gone from the binary  the compiler did the arithmetic so the CPU never has to.

This is what the source computed:

```
(uint32_t)(97.4561  × 1000)   =   97456  =  0x00017CB0
(uint32_t)(213.887  × 100)    =   21388  =  0x0000538C
(uint32_t)(14.57345 × 10000)  =  145734  =  0x00023946
(uint32_t)(72.114   × 1000)   =   72114  =  0x000119B2
                                ──────────────────────────
XOR result                     =  135112  =  0x00020FC8  
```

The TLE values themselves  inclination 97.4561°, RAAN 213.887°, mean motion 14.57345 rev/day, mean anomaly 72.114°  describe HELIOS-7's sun-synchronous LEO orbit. They are still present in `.rodata` as `volatile const` doubles, but the seed is computed from them at build time. The player sees the answer directly: `uVar6 = 0x20fc8`.

The six TLE doubles are still readable in `.rodata` if the player checks, confirming what the seed was derived from:

```bash
$ readelf -x .rodata lbproc | grep -A1 "402180"

  0x00402180  ...
  0x00402188  9e ef a7 c6 4b 07 52 40   →  72.114    (mean anomaly M)
  0x00402190  4b c8 07 3d 9b 25 2d 40   →  14.57345  (mean motion n)
  0x00402198  d1 22 db f9 7e 46 62 40   →  146.203   (argument of perigee)
  0x004021a0  aa f1 d2 4d 62 bc 6a 40   →  213.887   (RAAN Ω)
  0x004021a8  82 23 dc bf 0d 8c 57 3f   →  0.0014372 (eccentricity)
  0x004021b0  29 ed 0d be 30 5d 58 40   →  97.4561   (inclination i)
```

Verify any value with:

```python
import struct
struct.unpack('<d', bytes.fromhex('9eefa7c64b075240'))[0]   # → 72.114
struct.unpack('<d', bytes.fromhex('29ed0dbe305d5840'))[0]   # → 97.4561
```

the seed formula uses only four of the six parameters — INCL, RAAN, N, M. Eccentricity and argument of perigee are present in `.rodata` but not in the XOR. Using all six produces a wrong seed, a wrong table, and a wrong flag.
###  The LCG parameters

The two hex immediates in the shuffle loop body:

```
0x19660d   =  1664525     (LCG multiplier)
0x3c6ef35f =  1013904223  (LCG increment)
```

These are the Knuth / Numerical Recipes Vol.2 32-bit LCG constants — widely documented and recognisable to anyone with PRNG experience. Each iteration: `seed = seed × 1664525 + 1013904223 (mod 2³²)`.

###  the shuffle mechanics

`DAT_004040c0` is `perm_table`  a 256-byte array in `.bss`. `DAT_004041bf` is `perm_table + 255`  the last element. The loop variable `puVar3` walks backward from `+255` to `+0`:

```c
uVar5 = uVar6 % ((int)puVar3 - 0x4040bfU);
```

`(int)puVar3 - 0x4040bf` is the current index `i` (distance from `perm_table - 1` to `puVar3`). So this is `j = seed % i`, which for a backward Fisher-Yates from index 255 to 1 should be `seed % (i + 1)`. The off-by-one is a Ghidra pointer arithmetic presentation artefact — `puVar3` points at element `i` when the modulo is computed, giving `(i+1)` elements in range. The swap then exchanges `*puVar3` with `perm_table[j]`. This is standard Fisher-Yates.

### The cleaned-up constructor

```c
void _INIT_1(void) {
    // Identity initialisation of perm_table[256] at DAT_004040c0
    for (int i = 0; i < 256; i++)
        perm_table[i] = (uint8_t)i;

    // Seed — GCC constant-folded the TLE XOR at compile time:
    // int(97.4561×1000) ^ int(213.887×100) ^ int(14.57345×10000) ^ int(72.114×1000)
    // = 97456 ^ 21388 ^ 145734 ^ 72114 = 135112 = 0x20FC8
    uint32_t seed = 0x20FC8;

    // Fisher-Yates backward shuffle, LCG-driven
    for (int i = 255; i > 0; i--) {
        seed = seed * 1664525 + 1013904223;   // Knuth LCG (mod 2³²)
        int j = seed % (i + 1);
        uint8_t tmp   = perm_table[i];
        perm_table[i] = perm_table[j];
        perm_table[j] = tmp;
    }
    // perm_table[256] is now a bijective permutation of 0–255.
    // It is fully populated before main() runs a single instruction.
    // It is never printed.
}
```

### The Decoy Constant

One question remains from `main`: where does `418229116.0` come from, and is there another constant that might look like the right one?

Running `readelf -x .rodata lbproc` shows the constants region:

bash

```bash
$ readelf -x .rodata lbproc

  0x00402240  0000004a 78deb141   →  +0x248   299792458.0   ← correct speed of light
  0x00402250  0000007c abedb841   →  +0x250   418229116.0   ← actual divisor
```

Both are in `.rodata`. Both are loaded by the code. `299792458.0` is the physically correct speed of light. It is loaded into a register by a `movsd` instruction and immediately discarded — kept in the binary solely to present a plausible-looking decoy alongside the modified constant.

The `divsd` instruction in `main`'s lock check uses the operand at `0x402250` — `418229116.0`. A player who assumes the correct constant and computes residuals gets values in the hundreds of millions. These are not valid table indices. The constant must be confirmed by tracing the `divsd` operand address.

`f_observed` values in `comms.dat` carry a sub-integer fractional component. The residual `f_obs − f_pred` is therefore never a clean integer for any value of `C`. A player who attempts to recover `C` algebraically — solving `C = f0 × rr / (f_obs − f0 − k)` for each `k ∈ 0..255` — obtains 256 fractional candidates, none landing on `418229116.0`. Reading the binary is the only path to this constant.

## Putting It Together

Both layers are now fully understood. The complete execution flow:

```
Before main() — _INIT_1 (0x004011b0) via .init_array:
  ┌─ TLE_INCL = 97.4561   ─┐
  │  TLE_RAAN = 213.887    ├─ XOR → seed = 135112
  │  TLE_N    = 14.57345   │
  └─ TLE_M    = 72.114    ─┘
  seed × 1664525 + 1013904223 (mod 2³²)
  → Fisher-Yates backward shuffle
  → perm_table[256]  ← bijection, lives in .bss, never printed

Per record — FUN_00401220 / main():
  f_pred   = f0 × (1 + range_rate / 418229116.0)
  residual = f_observed − f_pred       ← sub-integer noise present
  r_int    = (int)residual & 0xFF      ← noise truncated by cast
  out      = perm_table[r_int]         ← FLAG BYTE — never printed
  printed  → LOCK / NO-LOCK only
```

The flag formula:

```
flag[i] = chr( perm_table[ int(f_obs_i − f_pred_i) & 0xFF ] )
```
## Building the Solver

All parameters are now fully traced from the binary. The solver replicates both stages externally.

**Build `perm_table` by replicating `init_pass_profile`.**

```python
import struct

TLE_INCL = 97.4561      # .rodata+0x1B0: 29 ed 0d be 30 5d 58 40
TLE_RAAN = 213.887      # .rodata+0x1A0: aa f1 d2 4d 62 bc 6a 40
TLE_N    = 14.57345     # .rodata+0x190: 4b c8 07 3d 9b 25 2d 40
TLE_M    = 72.114       # .rodata+0x188: 9e ef a7 c6 4b 07 52 40

# Seed construction — XOR of four scaled TLE fields
# Recovered from assembly prologue of init_pass_profile
seed = (
      (int(TLE_INCL * 1000)  & 0xFFFFFFFF)   # 97456  → 0x00017CB0
    ^ (int(TLE_RAAN * 100)   & 0xFFFFFFFF)   # 21388  → 0x0000538C
    ^ (int(TLE_N    * 10000) & 0xFFFFFFFF)   # 145734 → 0x00023946
    ^ (int(TLE_M    * 1000)  & 0xFFFFFFFF)   # 72114  → 0x000119B2
) & 0xFFFFFFFF                                # seed   → 135112 = 0x00020FC8

# Fisher-Yates shuffle — LCG from imul/add immediates in loop body
# multiplier 1664525   = 0x0019660D
# increment  1013904223 = 0x3C6EF35F
perm = list(range(256))
for i in range(255, 0, -1):
    seed     = (seed * 1664525 + 1013904223) & 0xFFFFFFFF
    j        = seed % (i + 1)
    perm[i], perm[j] = perm[j], perm[i]

assert sorted(perm) == list(range(256)), "not a valid bijection — check TLE constants"
```

**Compute residuals using `C_LIGHT_MOD` and apply the table.**

```python
# C_LIGHT_MOD recovered from divsd operand trace: .rodata+0x250
# 0000007c abedb841 → 418229116.0
C_MOD = 418229116.0

data = open('comms.dat', 'rb').read()
flag = []

for i in range(0, len(data), 48):
    ts, f0, rr, fobs, el, snr, wid, _ = struct.unpack_from('<QdddffiI', data, i)
    f_pred = f0 * (1.0 + rr / C_MOD)
    r_int  = int(fobs - f_pred) & 0xFF   # int() truncates sub-integer noise
    flag.append(chr(perm[r_int]))

print(''.join(flag))
```

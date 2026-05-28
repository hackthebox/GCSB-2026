![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Enthiran</font>

1<sup>st</sup> April 2026

Prepared By: `Kailash S`

Challenge Author(s): `Kailash S`

Difficulty: <font color='Grey'>Insane</font>

<br><br>

# Synopsis

`enthiran` is a stripped x86-64 Linux ELF binary that presents itself as a routine system
diagnostics utility. It prints a version banner, runs a fake progress bar, and outputs eight
floating-point "diagnostic channel scores" before exiting. Ghidra finds no flag logic, no
comparisons, and no crypto. The channel scores are the flag — encoded in the hidden layer of
a 16→32→8→1 Multi-Layer Perceptron embedded directly in the binary.

The binary collects sixteen features from the live environment, passes them through the MLP,
and stores the eight hidden-layer activations as the channel outputs. Six of those sixteen
features are hardcoded constants in `.rodata` disguised as telemetry. The remaining features
come from `/proc`, all with XOR-obfuscated path strings. Two decoy compute functions exist
inside the inference path and are silently discarded. The flag is never printed directly under
any circumstances.

Recovery requires identifying the MLP architecture from floating-point loop patterns,
extracting all six weight matrices from `.rodata` by first-value search, reconstructing the
sixteen-dimensional canonical input vector, and running external inference. The critical
structural insight is that all eight hidden-layer values are exact multiples of `1/256` — a
property unique to the correct input that serves as a built-in verification test. Once found,
Stage 1 decodes flag bytes 0–7 via XOR with a key found in `.rodata`. Stage 2 uses a
SipHash-inspired stream keyed on all eight hidden values to decode bytes 8–24.

---

## Description

Task Force Nightfall has recovered a binary from a compromised infrastructure monitoring
node. On the surface it is a standard diagnostics utility — version banner, hardware
readouts, environment profile. Clean output, no obvious anomalies. But it was found running
on a node with no legitimate reason to execute it, and its behaviour does not match its
claimed function.

The binary does not compare, decrypt, or flag-print in any way a standard analysis tool
can trace. Every decision is delegated to a learned model embedded in its data section.
Understanding what the binary actually does requires moving beyond control-flow analysis
into the mathematics of its internal representations.

## Skills Required

- Solid understanding of x86-64 ELF internals and stripped binary analysis
- Experience with Ghidra or IDA Pro for floating-point and SIMD pattern identification
- Familiarity with `/proc` filesystem telemetry and Linux system call tracing
- Python scripting with `numpy` for external numerical reconstruction
- Basic understanding of neural network inference (dense layers, ReLU, sigmoid)

## Skills Learned

- How an embedded MLP replaces traditional control flow as a decision mechanism
- Extracting non-contiguous weight arrays from `.rodata` by first-value anchor search
- Reconstructing a multi-dimensional canonical input vector from binary constants
- Using the `n/256` structural property as a verification oracle for the correct input
- Defeating ULP (unit-in-last-place) floating-point rounding with a precision snap step
- Decoding data encoded in hidden-layer activations through two-stage XOR recovery
- Recognising and discarding decoy compute paths whose results are silently discarded

## MITRE Mappings

- **T1027 – Obfuscated Files or Information**  
  XOR-obfuscated `/proc` path strings hide telemetry collection from `strings` and static
  analysis. Six hardcoded constants are disguised as live telemetry features.

- **T1082 – System Information Discovery**  
  The binary actively profiles the host environment — reading `/proc/meminfo`,
  `/proc/stat`, `/proc/loadavg`, `/proc/uptime`, performing `clock_gettime` timing
  measurements and `/dev/urandom` entropy sampling to construct the inference input.

- **T1620 – Reflective Code Loading (analogous)**  
  Execution semantics are externalised from control flow into a learned model. The binary's
  decision logic cannot be recovered by tracing branches — it requires reconstructing and
  evaluating a numerical model.

- **T1140 – Deobfuscate/Decode Files or Information**  
  Flag recovery requires external reconstruction of the MLP inference pipeline and
  application of two-stage XOR decoding using parameters recovered from `.rodata`.

---

# Enumeration

## Analysing the Given Files

```bash
$ file enthiran
enthiran: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

Running `strings` produces version strings, CLI flag names, and diagnostic readout labels.
No flag material, no `/proc` paths, no XOR keys. The `/proc` paths are obfuscated.

```bash
$ ./enthiran
Enthiran System Diagnostics v1.0
=================================

System: Linux 6.1.0 (x86_64)
CPUs:   4
RAM:    8192 MB
Uptime: 3827 seconds

[*] Running environment diagnostics...
  [+] Checking memory subsystem... OK
  [+] Profiling CPU characteristics... OK
  [+] Sampling entropy sources... OK
  [+] Measuring system latency... OK
  [+] Evaluating process state... OK
  [+] Finalizing environment profile... OK

[*] Environment evaluation: score=0.991290
[*] Diagnostic profile:
    channel[0] = 1.1518356817
    channel[1] = 2.1129425070
    channel[2] = 0.3749639244
    channel[3] = 0.3432116070
    channel[4] = 0.1757149696
    channel[5] = 0.9704808376
    channel[6] = 1.3841611968
    channel[7] = 2.4723875922
[+] Profile analysis complete. Nominal.
```

No flag. The binary always produces eight floating-point channel scores and exits cleanly.
The channel values shift slightly between runs — they are live telemetry values, not static.

**The deduction:** the channel scores are the encoded flag. The binary is not comparing
anything against them — it is printing them as the output of its computation and expecting
the analyst to decode them.

To rule out alternative interpretations: after `printf` prints the channel values,
`run_diagnostics()` returns immediately. There is no subsequent branch on h2, no
comparison against a reference, no conditional decode path, and no function that reads
h2 after the print loop. The values are terminal outputs — nothing in the binary consumes
them. Dynamic environment manipulation, /proc shimming, and brute-force telemetry
variation would only change which h2 values are printed; they would not cause the binary
to print the flag directly. The flag must be decoded externally from the h2 values.

## Decompiling the Binary

Loading into Ghidra and running auto-analysis reveals an immediately suspicious picture. The
function list is sparse. For a binary that claims to profile a live environment and produce
eight numerical outputs, Ghidra finds almost no meaningful logic — one print routine, a
fake progress bar, and a dense block of floating-point operations with no obvious purpose.

The key section of `run_diagnostics()` in Ghidra:

```c
void run_diagnostics(void) {
    double feat[16];
    double h2[8];

    extract_features(feat);        // reads /proc, timing, entropy

    // ...fake progress bar with usleep()...

    double gate = mlp_forward(feat, h2);

    printf("[*] Environment evaluation: score=%.6f\n", gate);
    printf("[*] Diagnostic profile:\n");
    for (int i = 0; i < 8; i++) {
        printf("    channel[%d] = %.10f\n", i, h2[i]);
    }
    if (gate >= 0.97)
        puts("[+] Profile analysis complete. Nominal.");
    else
        puts("[-] Profile analysis complete. No anomalies detected.");
}
```

The eight `h2` values printed as channel scores are the output of `mlp_forward()`. The
`gate` value (from the sigmoid output neuron) is also printed as the "score". No comparison
against external data. No flag printing. The channel scores are the answer — but only with
the correct input.

### Identifying the MLP Structure

`mlp_forward()` contains a function called three times with different array arguments:

```c
// Pseudocode from Ghidra decompiler (cleaned)
for (int j = 0; j < out_dim; j++) {
    double acc = bias[j];
    for (int i = 0; i < in_dim; i++) {
        acc += input[i] * weights[i * out_dim + j];
    }
    output[j] = use_relu ? fmax(0.0, acc) : acc;
}
```

This matches the canonical definition of a **dense (fully-connected) neural network
layer**: an affine transform (`input @ weights + bias`) followed by a nonlinear activation.
Three properties confirm it: the inner loop accumulates a dot product (affine transform),
`bias[j]` is added unconditionally (bias term), and `fmax(0.0, acc)` clips negative
outputs (ReLU activation). The structure repeats three times with the output of each
layer feeding the input of the next — a layered composition that is the defining
characteristic of a Multi-Layer Perceptron. It is called three times with loop bounds:

| Layer | in_dim | out_dim | Activation | Weight count | Bias count |
|---|---|---|---|---|---|
| 1 | 16 | 32 | ReLU | 512 doubles | 32 doubles |
| 2 | 32 | 8  | ReLU | 256 doubles | 8 doubles  |
| 3 | 8  | 1  | sigmoid | 8 doubles | 1 double |

Architecture: **16 → 32 → 8 → 1**

The eight outputs from Layer 2 are the eight channel values printed at runtime. The Layer 3
output is the "score". The `exp()` call from `ltrace` confirms the sigmoid function.

### Identifying Decoy Functions

Two additional functions — `_decoy_net_forward()` and `_decoy_transform()` — are called
inside `mlp_forward()` but their return values are explicitly discarded:

```c
(void)_decoy_net_forward(buf, 32);   // result unused
(void)_decoy_transform(buf, 32);     // result unused
```

The `(void)` cast is the key evidence: the C compiler emits this pattern when a return
value is computed and then deliberately thrown away. Tracing both functions in Ghidra
confirms they write only to local stack buffers, make no writes to globals or the heap,
and perform no system calls. Their outputs feed nothing that the inference or decode path
reads. They are provably irrelevant noise — do not spend time on them.

### Finding decode_flag()

A function `decode_flag()` exists in `.text` and is marked `__attribute__((used))` — the
compiler retained it but it is **never called** from normal execution. It contains:

```c
// Stage 1: flag bytes 0-7
for (int i = 0; i < 8; i++) {
    uint8_t v = (uint8_t)(h2[i] * 256.0);
    flag_out[i] = v ^ g_KEY[i];
}
// Stage 2: flag bytes 8-24
uint8_t stream[17];
_h2_stream(h2, stream, 17);
for (int j = 0; j < 17; j++) {
    flag_out[8+j] = g_enc_tail[j] ^ stream[j];
}
```

This is the flag decoding mechanism. The eight h2 values encode flag bytes 0–7 directly.
Bytes 8–24 come from XORing `g_enc_tail` (stored in `.rodata`) with a stream derived from
all eight h2 values. Neither `g_KEY` nor `g_enc_tail` can be bruted independently — the
h2 values must be exactly correct for Stage 2, and partially correct h2 values produce
entirely wrong Stage 2 output.

## Dynamic and Structural Analysis

```bash
$ strace -e trace=openat,clock_gettime ./enthiran 2>&1 | grep openat
openat(AT_FDCWD, "/proc/meminfo", O_RDONLY) = 3
openat(AT_FDCWD, "/proc/uptime",  O_RDONLY) = 3
openat(AT_FDCWD, "/proc/loadavg", O_RDONLY) = 3
openat(AT_FDCWD, "/proc/stat",    O_RDONLY) = 3
openat(AT_FDCWD, "/dev/urandom",  O_RDONLY) = 3
```

The binary reads five system files. The `/proc` path strings are XOR-encoded in `.rodata`
with key `0xA4` — confirmed by scanning `.rodata` for byte sequences that decode to
`/proc/`:

```python
KEY = 0xA4
enc = bytes([0x8b,0xd4,0xd6,0xcb,0xc7,0x8b,0xc9,0xc1,0xc9,0xcd,0xca,0xc2,0xcb])
path = bytes(b ^ KEY for b in enc)  # b'/proc/meminfo'
```

Also multiple `clock_gettime(CLOCK_MONOTONIC)` calls — a timing jitter measurement.
`ltrace` shows `exp()` from `libm` confirming the sigmoid activation function.

---

# Solution

## Locating the Weight Arrays in .rodata

```bash
$ readelf -S enthiran | grep rodata
[18] .rodata  PROGBITS  0x3000  size:0x1dd0
```

`.rodata` is at file offset `0x3000`, size `0x1dd0`. The six weight arrays are **not stored
sequentially** — the compiler reorders static globals. Each array is found by scanning for
its first double value, obtained from Ghidra by tracing the pointer arguments of the three
`mlp_layer()` call sites.

**How to extract first values from Ghidra:** In the decompiler view of `mlp_forward()`,
each `mlp_layer()` call passes three pointer arguments — input, weights, and biases. Click
the weights pointer for Layer 1; Ghidra resolves it to a `.rodata` address. In the Listing
view, navigate to that address and read the first 8-byte value displayed as a `double` —
this is the anchor for `g_W1`. Repeat for each pointer across all three calls. The first
double value at each pointer's target is what `find_array()` searches for. Because each
value is a specific random float (e.g. `−0.7510587290547743`) that is statistically
unique in a 27 KB binary, a single match in `.rodata` is sufficient to locate the full
array.

```python
import struct, math, numpy as np

with open("enthiran", "rb") as f:
    raw = f.read()

RD_OFF, RD_SIZE = 0x3000, 0x1dd0

def find_array(first_val, count):
    needle = struct.pack("<d", first_val)
    pos = RD_OFF
    while True:
        pos = raw.find(needle, pos, RD_OFF + RD_SIZE)
        if pos < 0: raise RuntimeError(f"Not found: {first_val}")
        vals = list(struct.unpack_from(f"<{count}d", raw, pos))
        if all(math.isfinite(v) for v in vals):
            return pos, np.array(vals)
        pos += 1
```

Known array offsets and first values (from Ghidra pointer tracing):

| Array | File offset | Count | First value |
|---|---|---|---|
| `g_b3` | `0x3310` | 1   | `+5.41115650...` |
| `g_W3` | `0x3320` | 8   | `+0.80561544...` |
| `g_b2` | `0x3360` | 8   | `−1.61945023...` |
| `g_W2` | `0x33a0` | 256 | `+0.88751103...` |
| `g_b1` | `0x3ba0` | 32  | `−0.11768843...` |
| `g_W1` | `0x3ca0` | 512 | `−0.75105873...` |

```python
_, W1_flat = find_array(-0.7510587290547743,  512)
_, b1_flat = find_array(-0.11768843326374814,  32)
_, W2_flat = find_array( 0.8875110295764412,  256)
_, b2_flat = find_array(-1.6194502324338378,    8)
_, W3_flat = find_array( 0.8056154352141116,    8)
_, b3_flat = find_array( 5.411156502737637,     1)

W1 = W1_flat.reshape(16, 32);  b1 = b1_flat
W2 = W2_flat.reshape(32,  8);  b2 = b2_flat
W3 = W3_flat.reshape( 8,  1);  b3 = b3_flat
```

## Recovering the FLAG XOR Key and enc_tail

Both are in `.rodata`:

```python
# KEY = DEADBEEFCAFEBABE at file:0x3308
KEY = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
idx = raw.find(KEY, RD_OFF, RD_OFF + RD_SIZE)   # idx = 0x3308

# enc_tail[17] at file:0x32c0
ENC_TAIL = bytes([
    0x33,0xd5,0xf5,0x55,0x07,0xf8,0x45,0x17,
    0xd0,0x7e,0x23,0x27,0x4e,0x3c,0x79,0xef,0x78
])
```

## Reconstructing the 16-Dimensional Input Vector

`extract_features()` in Ghidra reveals two distinct feature types:

### Features 9, 11–15: hardcoded MAGIC constants (NOT telemetry)

Six features appear in the decompiler as direct loads from `static const double` globals —
they bypass the telemetry collection path entirely. These are the true activation keys.

**How we know these are fixed, not runtime-derived:** In Ghidra's decompiler, each of these
six values appears as an immediate floating-point constant loaded directly into a register
and written into the feature array — for example `feat[9] = 0.72000000`. There is no
preceding computation, no system call, no `/proc` read, and no dependency on any other
variable. The C compiler emits this pattern for `static const double` globals: the value
is baked into the binary at compile time and cannot vary at runtime. Unlike features 0–8
(which are computed from live `/proc` reads and timing measurements), these six values are
identical on every machine, every run, every environment — they are designed inputs, not
measured inputs:

| Index | Variable | Value |
|---|---|---|
| 9  | `_MK_A` | **0.72** |
| 11 | `_MK_B` | **0.41** |
| 12 | `_MK_C` | **0.85** |
| 13 | `_MK_D` | **0.33** |
| 14 | `_MK_E` | **0.91** |
| 15 | `_MK_F` | **0.23** |

All six are recoverable from `.rodata` as standalone double constants.

### Features 0–8: canonical telemetry targets

These appear in `.rodata` as a 9-double array — the canonical target values that represent
"normal" environment state:

```
[0.61, 0.55, 0.78, 0.29, 0.44, 0.67, 0.52, 0.38, 0.66]
```

**How we know these are the right values:** The original binary source contained a
soft-clamp step in `extract_features()` that blended live telemetry toward fixed targets:
`feat[i] = 0.65 * live + 0.35 * target[i]`. The targets were embedded as a 9-double
array in `.rodata`. That soft-clamping code was removed from the final binary, but the
target constants remain in `.rodata` as dead data. Critically, the n/256 structural test
(below) acts as an oracle: any wrong telemetry value breaks the n/256 property,
confirming that these are the correct canonical values and not guesses.

**How to locate the array in Ghidra:** The MAGIC constants (0.72, 0.41, 0.85...) are
already pinpointed in `.rodata` from the previous step. Scanning the double constants in
that same region for values in the normalised telemetry range (0–1) that appear in a
contiguous run of exactly 9 reveals this array. The size 9 is not a guess — it matches
the number of telemetry features (indices 0–8) identified from `extract_features()`, and
the array sits immediately adjacent to the MAGIC constants in `.rodata`. The first element
`0.61` (memory pressure, `1 − MemAvailable/MemTotal`) is the anchor used to locate it:
`raw.find(struct.pack("<d", 0.61), RD_OFF)` within the known `.rodata` bounds.

### Feature 10: `mem_total_norm()`

```c
feat[10] = ram_mb / 65536.0;
```

The divisor `65536.0` is present in `.rodata` as a double constant
(`0x40f0000000000000`). The binary also prints `RAM: XXXX MB` in its sysinfo header —
so `feat[10]` = printed RAM in MB divided by `65536.0`.

**Why this is the only unknown, and why sweeping is valid:** Features 9 and 11–15 are
compile-time constants — fixed. Features 0–8 are recoverable from `.rodata` as canonical
targets. Feature 10 is the sole remaining degree of freedom: it reads total RAM via
`sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGE_SIZE)`, which varies by machine. With all
other 15 features fixed, the input vector has exactly one free parameter. Real server RAM
comes in power-of-2 multiples — 4 GB, 8 GB, 16 GB, 32 GB, 64 GB, 128 GB — giving at
most a dozen plausible `feat[10]` values. The sweep is bounded by physical reality, not
by the search space of all floats.

## The n/256 Verification Puzzle

After assembling the canonical input, feature 10 remains unknown — it depends on the
machine's RAM. The key insight is the **n/256 structural property**.

**How a player arrives at this insight:** After extracting the weights and running
inference with several feat[10] candidates, the h2 output values for most candidates
look like `0.73812947...`, `0.88965775...`, `0.72601288...` — arbitrary-looking reals.
But with the correct feat[10], all eight values snap to round numbers: `0.5859375`,
`0.97265625`, `0.984375`... A player notices these look unusually quantized. Computing
`h2[i] * 256` reveals integers: `150.0`, `249.0`, `252.0`... exactly. This is not
floating-point coincidence — floating-point arithmetic does not accidentally produce
values that are exact multiples of 1/256 across all eight neurons simultaneously.

**Why 1/256 specifically:** The Stage 1 decode formula in `decode_flag()` is
`flag[i] = (uint8_t)(h2[i] * 256.0) XOR KEY[i]`. For this to produce a valid ASCII
character, `h2[i] * 256` must land exactly on an integer in the range 0–255. The `b2`
biases were engineered at build time to guarantee this for the correct canonical input.
A random input produces non-integer `h2[i] * 256` values — the truncation `(uint8_t)`
would produce garbage flag bytes. The n/256 property is therefore simultaneously a
correctness requirement for Stage 1 and the oracle that identifies feat[10].

The `b2` biases were engineered at build time so that when the correct canonical input is
supplied, every hidden-layer output is an **exact multiple of 1/256**. A random input
produces values like `0.73812947...`. The correct input produces `0.58593750 = 150/256`
exactly.

This is not coincidence — it is a structural fingerprint uniquely identifying the correct
input. Sweeping feature 10 across plausible RAM values and checking the n/256 property
resolves the ambiguity in milliseconds:

```python
def relu(x):    return np.maximum(0.0, x)
def sigmoid(x): return 1.0 / (1.0 + np.exp(-x))

def is_all_n256(h2, tol=1e-9):
    return all(abs(v - round(v*256)/256.0) < tol for v in h2)

# Feature index mapping (from extract_features() in Ghidra):
# Index  Source           Formula
#   0    /proc/meminfo    1 − MemAvailable/MemTotal   (memory pressure)
#   1    sysconf          nproc / 16.0                (CPU count)
#   2    /dev/urandom     entropy / 8                 (entropy sample)
#   3    /proc/uptime     uptime / (30×86400)         (uptime)
#   4    /proc/loadavg    loadavg / 16.0              (load average)
#   5    clock_gettime    timing jitter / 5e6         (latency)
#   6    /proc/meminfo    1 − MemFree/MemTotal        (free memory ratio)
#   7    /proc/stat       process count / 5000        (process count)
#   8    /proc/stat       ctxt_switches % 1e9         (context switches)
#   9    static const     0.72  (_MK_A — not telemetry, compile-time constant)
#  10    sysconf          ram_mb / 65536.0            (total RAM — only unknown)
#  11    static const     0.41  (_MK_B)
#  12    static const     0.85  (_MK_C)
#  13    static const     0.33  (_MK_D)
#  14    static const     0.91  (_MK_E)
#  15    static const     0.23  (_MK_F)
MAGIC = {9:0.72, 11:0.41, 12:0.85, 13:0.33, 14:0.91, 15:0.23}
TELEM = {0:0.61, 1:0.55, 2:0.78, 3:0.29, 4:0.44, 5:0.67, 6:0.52, 7:0.38, 8:0.66}

def make_input(feat10):
    x = np.zeros(16)
    for i,v in TELEM.items(): x[i] = v
    for i,v in MAGIC.items(): x[i] = v
    x[10] = feat10
    return x

for ram_gb in [4, 8, 16, 32, 48, 64, 128]:
    feat10 = (ram_gb * 1024.0) / 65536.0
    h1  = relu(make_input(feat10) @ W1 + b1)
    h2  = relu(h1 @ W2 + b2)
    gate= sigmoid((h2 @ W3 + b3)[0])
    print(f"RAM={ram_gb:4d}GB  feat[10]={feat10:.4f}  "
          f"h2[0]={h2[0]:.8f}  all_n256={is_all_n256(h2)}")
```

Output:

```
RAM=   4GB  feat[10]=0.0625  h2[0]=1.1308852511  all_n256=False
RAM=   8GB  feat[10]=0.1250  h2[0]=1.0809428739  all_n256=False
RAM=  16GB  feat[10]=0.2500  h2[0]=0.8896577550  all_n256=False
RAM=  32GB  feat[10]=0.5000  h2[0]=0.5859375000  all_n256=True  ✓
RAM=  48GB  feat[10]=0.7500  h2[0]=0.3403664517  all_n256=False
```

Exactly one value passes. The sweep takes under 5 milliseconds. This is **not
brute-force** — it is a deterministic constraint satisfaction test.

## Snapping h2 to Exact n/256

After finding the correct feature 10, numpy's matrix multiply introduces **ULP
(unit-in-last-place) errors** — tiny floating-point rounding differences of 1–2 bits that
cause values like `0.5859375` to be stored as `3fe2c00000000002` instead of the exact
`3fe2c00000000000`. The Stage 2 stream uses raw IEEE 754 bit patterns, so a 1-bit error
changes all 17 output bytes.

The fix is the snap step — mathematically valid because h2[i] IS exactly `n/256`:

```python
h2_exact = np.array([round(v * 256) / 256.0 for v in h2])
```

The `n` values for each neuron:

| i | h2_exact[i] | n (= h2×256) |
|---|---|---|
| 0 | 0.58593750 | 150 |
| 1 | 0.97265625 | 249 |
| 2 | 0.98437500 | 252 |
| 3 | 0.57812500 | 148 |
| 4 | 0.64062500 | 164 |
| 5 | 0.80078125 | 205 |
| 6 | 0.80859375 | 207 |
| 7 | 0.79687500 | 204 |

## Stage 1 Decode — Flag Bytes 0–7

From `decode_flag()` in Ghidra: `flag[i] = (uint8_t)(h2[i] * 256.0) XOR KEY[i]`

```python
flag = bytearray(25)
for i in range(8):
    flag[i] = round(h2_exact[i] * 256) ^ KEY[i]
```

Step by step:

| i | h2×256 | hex | XOR KEY[i] | result |
|---|---|---|---|---|
| 0 | 150 | `0x96` | `0x96 ^ 0xDE` | `0x48` = `H` |
| 1 | 249 | `0xF9` | `0xF9 ^ 0xAD` | `0x54` = `T` |
| 2 | 252 | `0xFC` | `0xFC ^ 0xBE` | `0x42` = `B` |
| 3 | 148 | `0x94` | `0x94 ^ 0xEF` | `0x7B` = `{` |
| 4 | 164 | `0xA4` | `0xA4 ^ 0xCA` | `0x6E` = `n` |
| 5 | 205 | `0xCD` | `0xCD ^ 0xFE` | `0x33` = `3` |
| 6 | 207 | `0xCF` | `0xCF ^ 0xBA` | `0x75` = `u` |
| 7 | 204 | `0xCC` | `0xCC ^ 0xBE` | `0x72` = `r` |

Partial flag: `HTB{n3ur`

Verification: all 8 bytes must be printable ASCII. If any are not, h2 or KEY is wrong.

## Stage 2 Decode — Flag Bytes 8–24

The `_h2_stream()` function in `decode_flag()` is a SipHash-inspired nonlinear mix of all
eight h2 values. The reconstruction is grounded directly in Ghidra's disassembly — not
inferred:

- **State initialisation:** `mov rax, 0x736f6d6570736575` — the SipHash IV constant,
  visible as an immediate in the function prologue.
- **Per-neuron mixing:** three 64-bit multiply-then-XOR steps with constants
  `0x9e3779b97f4a7c15` (Fibonacci golden ratio hash), `0xff51afd7ed558ccd` (MurmurHash3
  finaliser mix), visible as `imul`/`xor` pairs on `rax`.
- **Output generation:** a loop of `rotl`/`imul`/`xor` with `0xbf58476d1ce4e5b9` and
  `0x6c62272e07bb0142` producing one output byte per iteration — matching the disassembled
  inner loop exactly.
- **Structure:** all eight h2 values feed the state before any output byte is generated,
  meaning partial h2 knowledge cannot isolate individual stream bytes. This is confirmed
  empirically: flipping any single h2 value by 1/256 changes all 17 output bytes (100%
  avalanche per neuron, verified against every neuron).

The Python reconstruction below uses these constants verbatim, in the order they appear
in the disassembly. Each block in the Python loop corresponds directly to one group of
`xor`, `rol`/`ror`, and `imul` instructions in the disassembly — preserving the exact
operation sequence and constants. The outer loop over h2 values maps to the per-neuron
mixing block; the inner loop over `j` maps to the output-byte generation block. Any
deviation from the exact constant values or operation order produces the wrong stream and
garbage flag bytes — which serves as a self-verifying test.

```python
import struct

def rotl64(x, k):
    x &= 0xFFFFFFFFFFFFFFFF
    return ((x << k) | (x >> (64-k))) & 0xFFFFFFFFFFFFFFFF

def h2_stream(h2_vals, length=17):
    state = 0x736f6d6570736575       # SipHash IV constant — visible in Ghidra
    for v in h2_vals:
        bits   = struct.unpack("<Q", struct.pack("<d", float(v)))[0]
        state ^= bits
        state  = rotl64(state, 17) ^ (state * 0x9e3779b97f4a7c15 & 0xFFFFFFFFFFFFFFFF)
        state  = rotl64(state, 31)
        state ^= (state >> 33) * 0xff51afd7ed558ccd & 0xFFFFFFFFFFFFFFFF
    out = []
    for j in range(length):
        state ^= j * 0x6c62272e07bb0142 & 0xFFFFFFFFFFFFFFFF
        state  = rotl64(state, 13)
        state  = (state * 0xbf58476d1ce4e5b9) & 0xFFFFFFFFFFFFFFFF
        state ^= state >> 31
        out.append(state & 0xFF)
    return bytes(out)

stream = h2_stream(h2_exact.tolist())
for j in range(17):
    flag[8+j] = ENC_TAIL[j] ^ stream[j]
```

Stage 2 decodes to `4l_r3v3rs3r_1337}`.

Verification: all 17 bytes must be printable ASCII. If any are not, the snap step was
skipped or h2 values are wrong.

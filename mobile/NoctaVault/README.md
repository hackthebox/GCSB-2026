![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left />

<br>

<br>

<font size='5'>NoctaVault</font>

12<sup>th</sup> April 2026

Prepared By: lawbyte

Challenge Author: lawbyte

Difficulty: <font color='red'>Insane</font>

<br>

<br>

<br>

# Synopsis

A threat actor distributed an Android application disguised as an offline
password manager called **NoctaVault**. A secret operational credential is
embedded inside, sealed with a recovery phrase. The app uses a custom
multi-layer native packer — the real code never touches `classes.dex`, and
every per-build constant in the native library is randomised so no two
builds look the same.

## Skills Required

- Android reverse engineering (APK structure, ADB, `apksigner`)
- Java DEX decompilation with jadx
- ARM64 native analysis in IDA Pro / Hex-Rays
- Recognising `ChaCha20`, `SHA-256`, and `LZ4` from their *structure*
  (constants are masked, inlined, or constant-folded by `-O3`)
- Custom register-VM bytecode reversing
- Spotting compiler folds: a constant-folded XOR can hide a key in plain sight
- SMT modelling of an 8-bit XOR/ROL/ADD mixer

## Skills Learned

- Reversing a DEX packer with cert-bound decryption keys
- Recovering a per-string evolving-XOR string table
  (`k_{i+1} = (17·k_i + i + 0x9e) mod 256`)
- Identifying a "masked" SHA-256 (FIPS round function with a non-canonical
  initial vector)
- Reconstructing a salt-driven mixer schedule from unrolled VM bytecode
- Building a single-oracle verifier over a multi-round byte-mixer
- Finding dynamically-bound native methods via `RegisterNatives`

---

# Big Picture — Five Layers to Peel

Before diving in, here is the complete attack map. Every section below
contributes one piece.

**APK structure and data flow:**

```mermaid
flowchart TB
    subgraph APK["voidshell.apk"]
        subgraph DEX["classes.dex — 6 KB  |  visible DEX, bootstrap only"]
            SA["StubApp.attachBaseContext()<br>1. u(ctx)      → decrypt loader.dat<br>2. injectDex() → inject hidden DEX<br>3. b(loader)   → RegisterNatives for R.n"]
        end

        subgraph L1["loader.dat — 21 KB  |  LAYER 1"]
            LD["ChaCha20 encrypted<br>real app DEX"]
        end

        subgraph L2["payload.bin — 17 KB  |  LAYER 2 + 3"]
            PB["ChaCha20<br>+ LZ4 decompress<br>+ rolling-XOR<br>+ wire-permuted<br>32-opcode VM bytecode"]
        end

        subgraph L4["VM bytecode  |  LAYER 4 (mixer + 1 oracle)"]
            VM["3 rounds × 96 byte-updates<br>(salt-driven XOR/ROL/ADD)<br>masked SHA-256 → 1 stored digest"]
        end

        subgraph SO["libvault.so — 26 KB  |  all crypto lives here"]
            LV["sub_19EC sub_2C20  sub_3148<br>sub_1590  sub_445C<br>sub_3278  sub_333C<br>sub_3C18  sub_41F0  sub_4DA0"]
        end
    end

    SA -->|"reads + decrypts"| LD
    SA -->|"calls b()"| LV
    LV -->|"decrypts loader.dat"| LD
    LV -->|"decrypts + runs VM"| PB
    PB -->|"flag in"| VM
```

**Key derivation — both keys are cert-bound, the mixer has its own salt:**

```mermaid
flowchart LR
    subgraph KDF1["loader.dat  →  dex_key"]
        A1["xmmword_A70/A80<br>.rodata:0xA70, 32 bytes<br>(VS_CHACHA_KEY ⊕ 'dex_pkg\\0…')"] --> H1["SHA-256"]
        B1["APK cert SHA-256"] --> H1
        C1["'voidshell-dex-v1'<br>byte_119F decoded with key 0x97"] --> H1
        H1 --> R1["dex_key"]
    end

    subgraph KDF2["payload.bin  →  device_key"]
        A2["VS_CHACHA_KEY<br>(reassembled from 4 inline immediates +<br>xmmword_A90, ⊕ antidbg score)"] --> H2["SHA-256"]
        B2["APK cert SHA-256"] --> H2
        C2["hw_fp = 0x00 × 16"] --> H2
        D2["'voidshell-v1'<br>byte_CB6 decoded with key 0x15"] --> H2
        H2 --> R2["device_key"]
    end

    subgraph KDF3["mixer schedule"]
        S["salt (32 bytes,<br>painted by VM bytecode<br>into scratch[64..96])"] --> R3["random.Random(<br>SHA256(b'vsmix-v2|' || salt))"]
        R3 --> P3["per round:<br>perm[r], key[r], shift[r], step[r]"]
    end
```

> Both keys depend on the APK signing certificate — repackaging with a
> different signer silently produces garbage and returns ACCESS DENIED.

---

# Solution

## Step 1 — Install and understand the objective

![](images/app1.png)

The app presents as an offline password manager. On first launch it asks
for a master password. After setting one, the vault shows a single locked
entry:

![](images/app2.png)

Tapping **Project Nightfall \[SEALED\]** opens:

![](images/app3.png)

Any guess returns *"That phrase does not match."* The recovery phrase is
the flag. Everything else in the app is genuine — the packer is the
challenge.

---

## Step 2 — Unpack the APK and spot anomalies

```bash
unzip voidshell.apk -d unpacked
ls -lh unpacked/ unpacked/assets/ unpacked/lib/
```

```
classes.dex             6.2 KB   ← tiny — a real app would be 50+ KB
assets/
  loader.dat           21.0 KB   ← unknown encrypted blob
  payload.bin          17.0 KB   ← another unknown encrypted blob
lib/
  arm64-v8a/
    libvault.so        26.0 KB
  armeabi-v7a/
    libvault.so        19.0 KB
```

A login UI plus a database should produce a much larger DEX. A 6 KB DEX
screams **"the real code is hidden elsewhere."** The `assets/` blobs and
the native library will get us there.

> **Note.** The APK ships `arm64-v8a` and `armeabi-v7a` only. There is no
> `x86_64` slice, so we cannot just `objdump -d` the file on a Linux host;
> we work in IDA Pro on the `arm64-v8a` build (this writeup uses that).

---

## Step 3 — Decompile `classes.dex` with jadx

```bash
jadx -d out voidshell.apk
```

The entire DEX is just `StubApp` — a bootstrap loader — and an
auto-generated `R` class. No activities, no database, nothing:

![](images/image.png)

```java
public class StubApp extends Application {
    private native byte[] u(Context context);    // "unpack" loader.dat
    private native void   b(ClassLoader loader); // "bind" R.n via RegisterNatives

    static { System.loadLibrary("vault"); }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            byte[] dex = u(base);                // 1. decrypt loader.dat
            if (dex != null && dex.length > 0) {
                injectDex(base, dex);            // 2. inject hidden DEX
                b(base.getClassLoader());        // 3. bind flag-check native
            }
        } catch (Throwable th) { }
    }

    public static void injectDex(Context base, byte[] dex) throws Exception {
        // Write the decrypted DEX to disk, build a DexClassLoader,
        // then *prepend* its dexElements into the parent ClassLoader's
        // pathList — so Android finds the hidden classes first on every
        // subsequent class lookup.
        ...
    }
}
```

Both `u()` and `b()` are in `libvault.so`. Open that in IDA Pro.

---

## Step 4 — Quick external check of `libvault.so`

**Exported functions:**

```bash
nm --dynamic --defined-only lib/arm64-v8a/libvault.so | grep ' T '
```

```
0x000019EC T Java_io_noctavault_app_StubApp_u
0x00002C20 T Java_io_noctavault_app_StubApp_b
```

Only two exports. There is no `Java_..._R_n` symbol — the flag-check
function is bound **dynamically** via `RegisterNatives` and has no visible
name.

**Visible strings:**

```bash
strings -a lib/arm64-v8a/libvault.so | sort -u
```

Anything sensitive (`payload.bin`, `loader.dat`, `voidshell-v1`,
`SHA-256`, `PackageManager`, `TracerPid`, `frida`, …) is **absent**. The
strings are XOR-obfuscated in the binary and decoded on the stack just
before each use.

The fact that strings are *not* in plain `.rodata`, combined with only
two JNI exports, tells you that practically all the work is done by
internal helpers behind `RegisterNatives` and stack-decrypted strings.

---

## Step 5 — Reverse the per-string XOR table

Open `Java_io_noctavault_app_StubApp_u` in IDA, press `F5`. The first thing you see, before any
JNI call, is a tight little loop like this:

![](images/u1.png)

```c
v12 = 151;
do {
    v20[v11] = byte_119F[v11] ^ v12;   // decode one byte
    v13 = v11++ + 17 * v12;            // k *= 17, then add i
    v12 = v13 - 98;                    // ≡ +0x9e (mod 256)
} while ( v11 != 17 );
```

This pattern repeats **everywhere** the binary needs a string. Each
occurrence has its own `<starting_key>` baked in as an immediate, a
`byte_XXXX` source pointer, and a `<length>` loop count. The recurrence
is identical:

```
k_{i+1} = (17·k_i + i + 0x9e) mod 256          ; -98 ≡ +0x9e (mod 256)
out[i]  = blob[i] ^ k_i
```

Mirror this in your solver:

```python
def vs_str_step(k, i):
    return (k * 17 + i + 0x9E) & 0xFF

def vs_decode(blob, length, start_key):
    out = bytearray(); k = start_key
    for i in range(length):
        out.append(blob[i] ^ k)
        k = vs_str_step(k, i)
    return bytes(out[:-1])      # strip trailing NUL
```

Apply it to `byte_119F` (length 17, key `0x97 = 151`).

**Where does `byte_119F` come from?** In IDA's decompiler window, look for
the `byte_119F` label that appears in the decode loop. Double-click it — IDA
jumps straight to its `.rodata` definition and shows you the raw bytes:

![](images/byte_119f.png)

The DATA XREF comment (`Java_io_noctavault_app_StubApp_u+120↓o`) confirms this
blob is read inside the `u()` function. IDA lists all 17 DCB bytes:

```
.rodata:000000000000119F  byte_119F  DCB  0xE1, 0xCA, 0xFD, 0x10, 0x26, 0x2F, 0x3F, 0xF2, 0x4F
.rodata:00000000000011A8              DCB  0xD4, 0x54, 0xBD, 0x79, 0x96, 0x60, 0x13, 0xEF
```

XOR them with `vs_decode` using start key `0x97`:

```python
>>> blob = bytes.fromhex("e1cafd10262f3ff24fd454bd79966013ef")
>>> vs_decode(blob, 17, 0x97)
b'voidshell-dex-v1'
```

This is the first piece of evidence that `loader.dat` is decrypted with a
key derived from a hash that mixes in a version suffix. We will see the
matching suffix `voidshell-v1` for `payload.bin` shortly.

**How to find all the other strings.** Press **F5** on
`Java_io_noctavault_app_StubApp_u`. Hex-Rays already shows the first
decode loop in plain sight:

```c
v12 = 151;                               // start key = 0x97
do {
    v20[v11] = byte_119F[v11] ^ v12;     // ← blob label visible here
    v13 = v11++ + 17 * v12;
    v12 = v13 - 98;
} while ( v11 != 17 );                   // length = 17
```

Now repeat for every function in the verification call chain:

| Function | Press F5 → look for |
|---|---|
| `Java_..._u` @ `0x19EC` | `byte_119F` loop (start key `0x97`) |
| `sub_1590` @ `0x1590` | `byte_CB6` loop (start key `0x15`) |
| `sub_4DA0` @ `0x4DA0` | `byte_CC3`, `byte_CD5`, `byte_CE0`, `byte_CF6` loops |
| `Java_..._b` @ `0x2C20` | `byte_1113`, `byte_108F`, `byte_104C`, `byte_111D`, `byte_11FE`, `byte_11DE`, `byte_11E6` loops |

In each loop, read off three values:

1. **`byte_XXXX`** label — double-click it to see the raw encrypted bytes.
2. **Start key** — the immediate assigned *before* the loop starts.
3. **Length** — the loop-exit counter (`while (v_idx != N)` → length is N).

**Concrete example — `sub_1590` @ `0x1590`:**

Press F5 on `sub_1590`. Scroll to the decode loop — Hex-Rays shows this:

![](images/sub_1590.png)

```c
v18 = 0;
v19 = 21;                               // ← start key = 21 = 0x15
do {
    v50[v18] = byte_CB6[v18] ^ v19;     // ← blob = byte_CB6
    v20 = v18++ + 17 * v19;
    v19 = v20 - 98;
} while ( v18 != 13 );                  // ← length = 13
sub_35B4((int)v48, v50, 0xCu);          // feeds 12 decoded bytes to SHA256_Update
```

Three values read off directly from the decompile:
- **blob** = `byte_CB6`, **start key** = `21` (`0x15`), **length** = `13`

Double-click `byte_CB6` → IDA shows the 13 raw bytes at `0xCB6`.
Decode → `"voidshell-v1\0"` (12 printable + NUL). The `sub_35B4` call
immediately below passes `0xC = 12` bytes to SHA256_Update — that is the
KDF suffix for `payload.bin`.

![](images/byte_CB6.png)

This same three-value read works for every loop in the binary.

**IDA Python helper — decode any string without leaving IDA:**

Open **File → Script command** (or press `Alt+F7`) and paste:

```python
import ida_bytes

def vs_decode(addr, length, start_key):
    blob = ida_bytes.get_bytes(addr, length)
    out, k = bytearray(), start_key
    for i, b in enumerate(blob):
        out.append(b ^ k)
        k = (k * 17 + i + 0x9E) & 0xFF
    return bytes(out[:-1]).decode()   # strip trailing NUL

# Example: decode byte_CB6  (start key 21, length 13)
print(vs_decode(0xCB6, 13, 21))       # → voidshell-v1

# Decode all strings — fill in the values you read from each loop:
strings = [
    (0x119F, 17, 0x97),   # voidshell-dex-v1
    (0xCB6,  13, 0x15),   # voidshell-v1
    (0xCC3,  18, 0xD6),   # /proc/self/status
    (0xCD5,  11, 0x98),   # TracerPid:
    (0xCE0,  16, 0x56),   # /proc/self/maps
    (0xCF6,  12, 0xFF),   # gum-js-loop
    (0x1113, 10, 0xEE),   # payload.bin
    (0x11FE, 39, 0xC5),   # io.noctavault…NightfallGate
    (0x108F, 47, 0xCC),   # JNI signature
    (0x104C, 27, 0xA2),   # JNI method name+sig
    (0x111D, 38, 0x1D),   # cert-extract strings
    (0x11DE,  8, 0xDB),   # sLoader
    (0x11E6, 24, 0x36),   # Ljava/lang/ClassLoader;
]
for addr, length, key in strings:
    print(f"0x{addr:04X}  {vs_decode(addr, length, key)!r}")
```

All strings decoded this way:

| Address  | Length | Start key | Decoded plaintext |
|----------|-------:|----------:|-------------------|
| `byte_119F` | 17 | `0x97` (151) | `voidshell-dex-v1` |
| `byte_CB6`  | 13 | `0x15` (21)  | `voidshell-v1` |
| `byte_CC3`  | 18 | `0xD6` (214) | `/proc/self/status` |
| `byte_CD5`  | 11 | `0x98` (152) | `TracerPid:` |
| `byte_CE0`  | 16 | `0x56` (86)  | `/proc/self/maps` |
| `byte_CF6`  | 12 | `0xFF` (255) | `gum-js-loop` |
| `byte_1113` | 10 | `0xEE` (238) | `payload.bin` |
| `byte_11FE` | 39 | `0xC5` (197) | `io.noctavault.app.secure.NightfallGate` |
| `byte_108F` | 47 | `0xCC` (204) | `(Landroid/content/Context;Ljava/lang/String;)I` |
| `byte_104C` | 27 | `0xA2` (162) | `(JNI getMethodID name+signature)` |
| `byte_111D` | 38 | `0x1D` (29)  | `(cert-extract JNI strings)` |
| `byte_11DE` |  8 | `0xDB` (219) | `sLoader` |
| `byte_11E6` | 24 | `0x36` (54)  | `Ljava/lang/ClassLoader;` |

---

## Step 6 — Reverse `u()` at `0x19EC`

Hex-Rays output, simplified to the readable parts:

![](images/u.png)

```c
__int64 Java_io_noctavault_app_StubApp_u(JNIEnv *env, jobject self, jobject ctx)
{
    /* §6.1 — read assets/loader.dat into a heap buffer */
    enc = sub_1C48(env, ctx, /*string id*/ 55, &enc_len);

    /* §6.2 — outer header check */
    if (*(uint32_t*)enc != 1480934486) return 0;     // 1480934486 = "VDEX"
    dex_size  = ((uint32_t*)enc)[1];                  // bytes 4..8
    nonce_tag = ((uint32_t*)enc)[2];                  // bytes 8..12

    /* §6.3 — fetch APK signing-cert SHA-256 */
    cert = sub_233C(env, ctx);

    /* §6.4 — derive dex_key */
    src[0] = xmmword_A70;            // 32 bytes from .rodata:0xA70
    src[1] = xmmword_A80;
    sub_3278(&sha);                  // SHA-256 init
    sub_35B4(&sha, src,  32);        // mixed_dex_key
    sub_35B4(&sha, cert, 32);        // cert SHA-256
    /* decode "voidshell-dex-v1" from byte_119F with key 0x97, then: */
    sub_35B4(&sha, suffix, 16);
    sub_38AC(&sha, dex_key);         // SHA-256 final → dex_key

    /* §6.5 — ChaCha20 decrypt */
    nonce[0..7]  = 0xE4FE02775C22238A;        // bytes 0..7 (inline)
    nonce[8..11] = nonce_tag;                  // bytes 8..11 (from header)

    plain = malloc(dex_size);
    sub_3C18(dex_key, nonce, 0, enc + 12, plain, dex_size);
    return jbyteArrayOf(plain, dex_size);
}
```

We will walk each piece next.

### §6.1 — `sub_1C48` is the asset reader

The function is large, but its structure is clear: it decodes several
JNI class/method names (each via the per-string XOR loop you reversed in
Step 5), invokes `Context.getAssets()` → `AssetManager.open(name)`, and
reads the stream into a doubling-malloc buffer.

The third argument (`a3 = 55` in our caller) is a **string ID**. The
function indexes into a small table (`byte_12C0` for length, `byte_130D`
for starting key, `word_1226` for blob offset) to pull the right
encrypted asset name and decode it. ID 55 → `"loader.dat"`. The runtime
flag check (Step 10) calls the same function with ID 4 → `"payload.bin"`.

### §6.2 — VDEX magic: `1480934486` = `"VDEX"`

```c
if (*(uint32_t*)enc != 1480934486) return 0;
```

`1480934486 = 0x58454456` LE → `"VDEX"`. Hexdump confirms:

![](images/loader.png)

So `loader.dat` layout:

```
[0..4]   "VDEX"   (magic)
[4..8]   dex_size  (u32 LE = 21408)
[8..12]  nonce_tag (u32 LE — patched into ChaCha20 nonce)
[12..]   ciphertext
```

### §6.3 — `sub_233C` returns the signing-cert SHA-256

![](images/sub_233C.png)

`sub_233C` decodes the JNI class/method names
`android/content/pm/PackageManager`, `getPackageInfo`, `signingInfo`,
`getApkContentsSigners`, `toByteArray`, etc. (each via the per-string XOR
loop), and walks:

```
ctx.getPackageManager()
   .getPackageInfo(pkgName, /*GET_SIGNING_CERTIFICATES*/ 0x8000000)
   .signingInfo
   .getApkContentsSigners()[0]
   .toByteArray()        ← raw DER cert bytes
```

The very last call is `sub_3BA4(cert_bytes, len, out)`, a SHA-256 oneshot.
Open `sub_3BA4` to confirm: it builds a SHA-256 context with **the same
init function** (`sub_3278`) we saw in `u()`, then calls update + final.

We do not have to run the app to get the value — `apksigner` does it for
free:

```bash
apksigner verify --print-certs voidshell.apk | grep -i "SHA-256"
```

![](images/sign.png)

```
Signer #1 certificate SHA-256 digest:
  0f508490ff27ba9b9fa0966a018c08f4b1053fbaa54f9a49539ff16aa58f4209
```

This value is **cert-bound** — repackage with a different signing key
and the KDF produces a wrong `dex_key`, decryption silently outputs
garbage, and the app returns ACCESS DENIED.

### §6.4 — `xmmword_A70/A80` — the pre-computed mixed key

You are still in the **same F5 decompile of `Java_..._u`**. After the cert
call at `0x1A74`, Hex-Rays shows this:

![](images/a70-a80.png)

```c
src[0] = xmmword_A70;                    /* 0x1AA0 */
src[1] = xmmword_A80;                    /* 0x1AA0 */
sub_3278((__int64)&v21);                 /* SHA-256 init  */
sub_35B4((int)&v21, src, 0x20u);         /* SHA256_Update(src, 32 bytes) */
sub_35B4((int)&v21, v10, 0x20u);         /* SHA256_Update(cert, 32 bytes) */
```

IDA calls them `xmmword_A70` / `xmmword_A80` because each is a 16-byte
(128-bit) value at that address — IDA uses the `xmmword_` prefix for
`.rodata` entries it sees loaded into XMM/SIMD registers. Double-click
`xmmword_A70` → IDA jumps to `.rodata:0xA70`:

![](images/roa70-a80.png)

```
.rodata:0xA70   82 EA 5F E6  A4 86 45 E5  9E 42 C1 4B  B9 4C 1B 9C
.rodata:0xA80   E2 96 A7 67  D8 AF 6C 9E  C4 64 A9 2A  55 44 1E B6
```

These 32 bytes look random and feed straight into `SHA256_Update`. They
are not used as a ChaCha key directly — they are pre-mixed input for the
KDF hash. From the solver's perspective you can treat them as a fixed
32-byte blob and move on:

```python
mixed_dex_key = bytes.fromhex(
    "82ea5fe6a48645e59e42c14bb94c1b9c"
    "e296a767d8af6c9ec464a92a55441eb6")
dex_key = sha256(mixed_dex_key + cert_sha256 + b"voidshell-dex-v1").digest()
```

> **Why "pre-mixed"?** The C source computes `mixed[i] = VS_CHACHA_KEY[i]
> ^ tag[i]` with a compile-time-constant `tag = "dex_pkg\0\0...\0"`. With
> `-O3` the compiler folds the entire XOR loop and stores only the result
> in `.rodata`. We will exploit this fold in §10 to recover the raw
> `VS_CHACHA_KEY`.

### §6.5 — Identifying SHA-256 (the **masked** flavour comes later)

`sub_3278` is the SHA-256 initialiser used by the cert KDF:

![](images/sub_3278.png)

The **source of `mask` and `store`**: press F5 on `sub_3278`. Hex-Rays shows:

```c
__int64 sub_3278(__int64 ctx)
{
    for (i = 0; i != 8; ++i)
        ctx[i] = _byteswap_ulong(dword_ABC[i])           // ← label 1
               ^ _byteswap_ulong(*(u32*)&byte_ADC[4*i]); // ← label 2
    ctx->bit_count = 0;
    ctx->buf_len   = 0;
    return ctx;
}
```

Two `.rodata` labels appear — `dword_ABC` and `byte_ADC`. Double-click each to jump to their definitions. You can read the raw bytes using IDA Python (`ida_bytes.get_bytes`) since these addresses hold masked constants, not plain ASCII:

![](images/roabc-adc.png)

![](images/adc-abc.png)

- **`dword_ABC`** → jumps to `.rodata:0xABC`.
  Read raw bytes with IDA Python: `ida_bytes.get_bytes(0xABC, 32)`

  ```text
  89 25 e1 3c  b5 82 ce 3b  b6 67 fa e4  88 2f ed 73
  5f 70 fc b4  53 d3 62 42  b5 dd af 9d  11 a7 a3 aa
  ```

  → this is **`sha_iv_mask`** (32 bytes, call it `mask`).

- **`byte_ADC`** → jumps to `.rodata:0xADC`.
  Read raw bytes: `ida_bytes.get_bytes(0xADC, 32)`

  ```text
  e3 2c 07 5b  0e e5 60 be  8a 09 09 96  2d 60 18 49
  0e 7e ae cb  c8 d6 0a ce  aa 5e 76 36  4a 47 6e b3
  ```

  → this is **`sha_h0_masked`** (32 bytes, call it `store`).

The loop applies `bswap32` to both before XOR-ing — that converts from
little-endian (ARM64 native storage) to big-endian (SHA-256 word order).
XOR-ing them recovers the FIPS H0 vector.

Save this as `verify_h0.py` and run it with `python verify_h0.py`:

```python
# verify_h0.py
# Proves that dword_ABC XOR byte_ADC == FIPS SHA-256 H0

import struct

# bytes from .rodata:0xABC  (double-click dword_ABC in IDA → read with get_bytes)
mask  = bytes.fromhex("8925e13cb582ce3bb667fae4882fed735f70fcb453d36242b5ddaf9d11a7a3aa")

# bytes from .rodata:0xADC  (double-click byte_ADC in IDA → read with get_bytes)
store = bytes.fromhex("e32c075b0ee560be8a0909962d6018490e7eaecbc8d60aceaa5e76364a476eb3")

# These are the official SHA-256 initial hash values defined in FIPS 180-4
# (the public SHA-256 standard). They are the same in every SHA-256
# implementation — we use them as the known "ground truth" to verify that
# mask XOR store really does give us FIPS SHA-256, not something else.
# You can verify them yourself: python3 -c "import hashlib; print(hashlib.sha256(b'').hexdigest())"
# → the first 32 bytes of that digest always use these H0 constants internally.
FIPS_H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

for i in range(8):
    m = struct.unpack(">I", mask [i*4:i*4+4])[0]
    s = struct.unpack(">I", store[i*4:i*4+4])[0]
    result = m ^ s
    status = "✓" if result == FIPS_H0[i] else "✗ MISMATCH"
    print(f"H0[{i}] = {hex(m)} ^ {hex(s)} = {hex(result)}  {status}")
```

Output:

![](images/shell8.png)

All eight values match the **FIPS 180-4 SHA-256 H0 constants** ✓.

So `sub_3278` is standard SHA-256 with the H0 reconstructed at init time:

- **`dword_ABC`** @ `.rodata:0xABC` = `sha_iv_mask` (the XOR mask)
- **`byte_ADC`** @ `.rodata:0xADC` = `sha_h0_masked` (the stored masked H0)

`sha_h0_masked ⊕ sha_iv_mask = FIPS H0`. The canonical FIPS H0 byte
sequence **never appears verbatim** in the binary — `yara` SHA-256
fingerprints fail. The cert KDF still produces real FIPS SHA-256 at
runtime, so we can use stock `hashlib.sha256` for it.

There is a **second** SHA-256 init function further down (`sub_333C`)
that only loads the stored vector without XOR-ing the mask back. That is
the "masked" variant used inside the VM. We will look at it in Step 12.

---

## Step 7 — Decrypt `loader.dat`

**Where does the nonce `8a23225c7702fee4` come from?**

You are still in the `Java_..._u` decompile. Right after the SHA256_Final
call, Hex-Rays shows:

![](images/hex.png)

```c
v21 = 0xE4FE02775C22238ALL;   /* 0x1B78 — nonce bytes 0..7, inline constant */
v22 = vmovn_s16(v17).n64_u32[0];  /* nonce bytes 8..11 = nonce_tag from header */

sub_3C18(v19, &v21, 0, v8 + 3, v14, v7);  /* ChaCha20(key, nonce=&v21, ...) */
```

`v21` and `v22` sit adjacent on the stack, forming the 12-byte nonce.
`0xE4FE02775C22238A` interpreted as **little-endian bytes** = `8A 23 22 5C 77 02 FE E4`,
which reversed to the Python hex string is `8a23225c7702fee4`. You can verify:

```python
>>> import struct
>>> struct.pack("<Q", 0xE4FE02775C22238A).hex()
'8a23225c7702fee4'
```

`nonce_tag` (bytes 8..11) comes from the file header — byte offset 8 of
`loader.dat`, which is `00 00 00 00` → 0. So the full 12-byte nonce is
`8a23225c7702fee4 00000000`.

```python
# decrypt_loader.py
import hashlib, struct
from Crypto.Cipher import ChaCha20

# §6.4 — mixed_dex_key from .rodata:0xA70/A80 (read with get_bytes in IDA)
MIXED_KEY   = bytes.fromhex(
    "82ea5fe6a48645e59e42c14bb94c1b9c"
    "e296a767d8af6c9ec464a92a55441eb6")

# §6.3 — apksigner output
CERT_SHA256 = bytes.fromhex(
    "0f508490ff27ba9b9fa0966a018c08f4b1053fbaa54f9a49539ff16aa58f4209")

blob      = open("assets/loader.dat", "rb").read()
assert blob[:4] == b"VDEX"
dex_size  = struct.unpack_from("<I", blob, 4)[0]   # 21408
nonce_tag = struct.unpack_from("<I", blob, 8)[0]   # 0  (bytes 8..11 of header)

# KDF: SHA256(mixed_dex_key || cert_sha256 || "voidshell-dex-v1")
dex_key   = hashlib.sha256(MIXED_KEY + CERT_SHA256 + b"voidshell-dex-v1").digest()

# Nonce: 0xE4FE02775C22238A LE (inline in u()) + nonce_tag from header
nonce     = struct.pack("<Q", 0xE4FE02775C22238A) + struct.pack("<I", nonce_tag)
# = 8a23225c7702fee4 00000000

plain = ChaCha20.new(key=dex_key, nonce=nonce).decrypt(blob[12:])[:dex_size]
assert plain[:4] == b"dex\n"
open("real.dex", "wb").write(plain)
print(f"[+] real.dex written ({dex_size} bytes)")
```

---

## Step 8 — Analyse the hidden DEX

Open `real.dex` in jadx:

![](images/real.png)

The full app appears: login activity, vault store, credential adapter,
and — importantly — the gate class:

![](images/real1.png)

```java
package io.noctavault.app.secure;

public class NightfallGate {
    public static ClassLoader sLoader;        // populated by StubApp.b()

    public static boolean verify(Context ctx, String phrase) {
        try {
            Class<?> r = sLoader.loadClass("io.noctavault.app.secure.R");
            int ok = (int) r.getDeclaredMethod("n", Context.class, String.class)
                            .invoke(null, ctx, phrase);
            return ok == 1;
        } catch (Throwable t) { return false; }
    }
}
```

And the `R` class is a stub whose `n` method is **bound at runtime** by
the native side:

![](images/real2.png)

```java
package io.noctavault.app.secure;

public class R {
    public static native int n(Context ctx, String phrase);
}
```

So the recovery-phrase check is `R.n(ctx, phrase)`, and `R.n` lives in
`libvault.so`. We find it next.

---

## Step 9 — Find the flag-check function in `Java_io_noctavault_app_StubApp_b`

Press F5 on `Java_io_noctavault_app_StubApp_b` at `0x2C20`. IDA gives you
a messy 150-line output full of vtable offsets and generic variable names.
Here is how to read it — the five key blocks, annotated:

![](images/b.png)

**Block 1 — decode the class name for `loadClass`:**

```c
v17 = 29;
for ( j = 0; j != 38; ++j ) {           // length = 38
    *(_BYTE *)(v16 + j) = byte_111D[j] ^ v17;
    v19 = j + 17 * v17;
    v17 = v19 - 98;                      // same per-string recurrence
}
// → v16 now contains "io.noctavault.app.secure.R\0" (38 bytes, key 29)
```

Then immediately:

```c
v20 = v6(v4, v5);   // v6 = vtable[264/8] = GetMethodID on the loader class
                     // returns the method ID for the loadClass() method
v28 = (vtable[272/8])(v4, a3, v20, v27);
// CallObjectMethod(env, loader, loadClass_mid, "io.noctavault.app.secure.R")
// → v28 = classR (the Class object for R)
```

**Block 2 — build the `JNINativeMethod` struct:**

This is the most important block. Look for `strcpy(v55, "n")` — it hardcodes
the method name `"n"` (1 byte, no XOR needed):

```c
strcpy(v55, "n");                   // method name = "n"

v29 = 204;
for ( m = 0; m != 47; ++m ) {      // length = 47, key = 204
    v55[m + 4] = byte_108F[m] ^ v29;
    ...
}
// → v55+4 = "(Landroid/content/Context;Ljava/lang/String;)I\0"
//   (the JNI type signature that matches R.n)

v56[0] = v55;           // JNINativeMethod.name      = "n"
v56[1] = &v55[4];       // JNINativeMethod.signature = "(Landroid...)"
v56[2] = sub_3148;      // JNINativeMethod.fnPtr     = ← THE FLAG CHECKER
```

**Block 3 — call `RegisterNatives`:**

```c
v33 = *(vtable[1720/8]);    // JNI vtable offset +1720 = index 215 = RegisterNatives
v33(v4, v28, v56, 1);       // RegisterNatives(env, classR, methods[1], count=1)
```

> **How do you know offset `+1720` = `RegisterNatives`?**
> The JNI `JNIEnv` vtable is a fixed array defined in `jni.h`. Each function
> has a fixed index. Divide the byte offset by 8 (pointer size on 64-bit):
> `1720 / 8 = 215`. Count to slot 215 in the JNI interface table — that is
> `RegisterNatives`. You can also confirm by cross-checking the 4 arguments:
> `(JNIEnv*, jclass, JNINativeMethod*, jint)` which matches exactly.

**Block 4 — decode and load `NightfallGate` class:**

```c
v37 = 197;
for ( n = 0; n != 39; ++n ) {      // length = 39, key = 197
    *(_BYTE *)(...) = byte_11FE[n] ^ v37;
    ...
}
// → decoded = "io.noctavault.app.secure.NightfallGate\0"

v40 = (vtable[1336/8])(v4);         // vtable +1336 = GetClassLoader or findClass
v41 = (vtable[272/8])(v4, a3, v20, v40);
// loadClass("io.noctavault.app.secure.NightfallGate") → v42 = cNG
```

**Block 5 — set `NightfallGate.sLoader = loader`:**

```c
// decode "sLoader" (byte_11DE, key 219, length 8)
// decode "Ljava/lang/ClassLoader;" (byte_11E6, key 54, length 24)

v54 = (vtable[1152/8])(v4, v41);
// GetStaticFieldID(env, cNG, "sLoader", "Ljava/lang/ClassLoader;") → field ID

(vtable[1232/8])(v4, v42, v54, a3);
// SetStaticObjectField(env, cNG, sLoader_fid, loader)
// → NightfallGate.sLoader is now the ClassLoader that holds R
```

**Two facts to take away:**

1. `v56[2] = sub_3148` — the function pointer bound as `R.n` is **`sub_3148`**.
   This is confirmed by being the only non-vtable, non-decode function pointer
   assigned in this block.
2. The signature `"(Landroid/content/Context;Ljava/lang/String;)I"` from
   `byte_108F` matches `R.n(Context ctx, String phrase)` exactly — 2 args, returns int.

Open `sub_3148` next.

---

## Step 10 — Reverse `sub_3148` — the `R.n` bridge

Press F5 on `sub_3148`. This is what IDA actually shows — annotated line by line:

```c
__int64 __fastcall sub_3148(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
// a1 = JNIEnv*    a2 = jclass (unused)
// a3 = Context    a4 = phrase jstring
{
  __int64 result;       // return value
  void   *v8;           // cert SHA-256 (32 bytes, from sub_233C)
  void   *v10;          // payload.bin bytes (from sub_1C48)
  const char *v11;      // UTF-8 phrase string
  size_t  v12;          // phrase length
  int     v13;          // 0 = rejected, 1 = accepted
  __int64 v14;          // payload size (out-param)
  _QWORD  v15[3];       // hw_fp — 16 zero bytes on stack

  result = 0;
  if ( a3 )             // must have a Context
  {
    if ( a4 )           // must have a phrase jstring
    {
      result = sub_233C(a1, a3);          // fetch APK cert SHA-256 (32 bytes)
      if ( result )
      {
        v8 = (void *)result;              // v8 = cert buffer

        v14 = 0;
        v9 = sub_1C48(a1, a3, 4, &v14);  // read assets/payload.bin
        //                         ↑ string ID 4 = "payload.bin"
        //   v14 = file size (set by sub_1C48)
        if ( v9 )
        {
          v10 = (void *)v9;               // v10 = payload buffer

          v11 = (const char *)
                (*(__int64 (__fastcall **)(__int64, __int64, _QWORD))
                    (*(_QWORD *)a1 + 1352LL))(a1, a4, 0);
          //  vtable offset 1352 ÷ 8 = slot 169 = GetStringUTFChars(env, phrase, NULL)
          //  → v11 = raw UTF-8 of the recovery phrase

          v12 = strlen(v11);              // phrase length

          v15[0] = 0;
          v15[1] = 0;                     // hw_fp = 16 zeros (no device binding)

          v13 = sub_1590(
                    v11, v12,             // phrase bytes + length
                    v8,  32,              // cert SHA-256, 32 bytes
                    v15, 16,              // hw_fp (zeros), 16 bytes
                    v10, v14);            // payload.bin + size
          // ↑ sub_1590 is the main verifier — returns 0 (fail) or 1 (pass)

          (*(void (__fastcall **)(__int64, __int64, const char *))
                    (*(_QWORD *)a1 + 1360LL))(a1, a4, v11);
          //  vtable offset 1360 ÷ 8 = slot 170 = ReleaseStringUTFChars

          free(v8);
          free(v10);
          return v13 != 0;   // 1 = ACCESS GRANTED
        }
        else { free(v8); return 0; }
      }
    }
  }
  return result;
}
```

![](images/sub_3148.png)

**Reading the vtable calls:** divide the byte offset by 8 to get the JNI
slot index, then look it up in `jni.h`:

| Vtable offset | Slot (÷8) | JNI function |
|--------------|-----------|--------------|
| `+1352` | 169 | `GetStringUTFChars` |
| `+1360` | 170 | `ReleaseStringUTFChars` |

**Three facts confirmed:**

1. **`sub_1C48(a1, a3, 4, &v14)`** — string ID `4` = `"payload.bin"`.
   Verify with the IDA Python decoder from Step 5: `vs_decode(0x1113, 10, 0xEE)`.
2. **`v15[0] = 0; v15[1] = 0`** — `hw_fp` is 16 zero bytes. No hardware
   binding at this layer.
3. **`sub_1590`** takes 8 arguments — flag, cert, hw_fp, payload — and returns
   the pass/fail decision. That is the function we reverse next.

---

## Step 11 — Reverse `sub_1590` — the main verifier at `0x1590`

Press F5 on `sub_1590`. The function is ~190 lines. Here is the actual
IDA output, cut into labelled sections with every important line annotated.

![](images/1590.png)

**Parameter map** — IDA gives generic names; here is what each one means:

```c
void *sub_1590(
    __int64 a1,              // phrase bytes (UTF-8 string)
    __int64 a2,              // phrase length
    void   *a3,              // cert SHA-256 buffer (32 bytes)
    __int64  a4,             // cert length   (must == 32)
    void   *a5,              // hw_fp buffer  (16 zeros)
    __int64  a6,             // hw_fp length  (must == 16)
    _DWORD *a7,              // payload.bin data pointer
    unsigned __int64 a8)     // payload.bin size (must >= 14)
```

### A — Outer header checks

This is exactly what IDA shows at the top of the function:

```c
result = 0;
if ( a4 == 32 && a6 == 16 && a8 >= 0xE )   // basic sanity on sizes
{
    if ( *a7 != 1145647190 )                // 1145647190 = 0x44493056 = "V0ID" LE
        return 0;
    v10 = *(unsigned int *)((char *)a7 + 6);  // v10 = stage1_size (decompressed)
    if ( (unsigned int)v10 <= 0x18000 )       // max 96 KB
    {
        v11 = *(unsigned int *)((char *)a7 + 10);  // v11 = lz_size (compressed)
        if ( (unsigned int)(v11 + 14) <= a8 )      // must fit in payload buffer
        {
            // ... rest of function
```

`1145647190 = 0x44493056` LE bytes = `56 30 49 44` = `"V0ID"`.

`payload.bin` outer header layout, derived from those byte offsets:

```text
payload[0..4]   "V0ID"  (magic, *a7)
payload[4]       1      (version)
payload[5]       flags
payload[6..10]   stage1_size  ← v10 = *(a7+6)
payload[10..14]  lz_size      ← v11 = *(a7+10)
payload[14..]    ChaCha20(LZ4(stage1))
```

### B — Anti-debug silently corrupts the key

Immediately after the header check, IDA shows:

```c
v14 = dword_7D50;           // global: boot-time antidbg score
v17 = sub_4DA0(0);          // runtime antidbg score
// XOR antidbg score into the first 4 bytes of the key:
src[0] = (v17 | v14) ^ 0xE6;
src[1] = ((unsigned __int16)(v17 | v14) >> 8)  ^ 0x8F;
src[2] = ((v17 | (unsigned int)v14) >> 16) ^ 0x27;
src[3] = ((v17 | (unsigned int)v14) >> 24) ^ 0xB9;
// key bytes 4..20 from .rodata:0xA90:
v52 = xmmword_A90;
// key bytes 20..28 inline immediate:
v53 = 0x2AA964C49E6CAFD8LL;
// key bytes 28..32 inline immediate:
v54 = -1239530411;          // = 0xB61E4455 LE = key[28..32]
```

The immediates `0xE6 / 0x8F / 0x27 / 0xB9` are bytes 0..3 of
`VS_CHACHA_KEY` (exactly how this XOR works is explained in §D below).
`sub_4DA0` checks `TracerPid:`, Frida markers in `/proc/maps`, and
`State: t` in `/proc/status`. On a clean device score = 0, XOR is a
no-op. Under a debugger the key bytes flip silently → wrong `device_key`
→ garbage after ChaCha20 → fail with zero error output.

### C — Device-key KDF

```c
sub_3278(v48);                           // SHA-256 init (FIPS, reconstructs H0)
sub_35B4((int)v48, src, 0x20u);          // SHA256_Update(key_buffer, 32 bytes)
sub_35B4((int)v48, a3, 0x20u);           // SHA256_Update(cert_sha256, 32 bytes)
sub_35B4((int)v48, a5, 0x10u);           // SHA256_Update(hw_fp, 16 bytes)

// decode "voidshell-v1\0" from byte_CB6 (start key 21, length 13):
v18 = 0;
v19 = 21;
do {
    v50[v18] = byte_CB6[v18] ^ v19;
    v20 = v18++ + 17 * v19;
    v19 = v20 - 98;
} while ( v18 != 13 );

sub_35B4((int)v48, v50, 0xCu);           // SHA256_Update("voidshell-v1", 12 bytes)
sub_38AC(v48, v49);                      // SHA256_Final → v49 = device_key (32 bytes)
```

The suffix is `"voidshell-v1"` — different from the `"voidshell-dex-v1"`
in `loader.dat`. The two assets use independent keys; you cannot reuse one
to decrypt the other.

### D — Recovering `VS_CHACHA_KEY` in one XOR

If you read the bytes at `.rodata:0xA70` carefully, you notice something
peculiar:

![](images/aa70-aa0.png)

```
; ── mixed_dex_key (VS_CHACHA_KEY ⊕ "dex_pkg\0"+24 zeros) — 32 bytes ──────────
.rodata:0xA70   82 EA 5F E6 A4 86 45 E5  9E 42 C1 4B B9 4C 1B 9C
.rodata:0xA80   E2 96 A7 67 D8 AF 6C 9E  C4 64 A9 2A 55 44 1E B6
;               ↑ bytes A70..A8F are the 32-byte pre-mixed key passed into SHA-256

; ── anti-debug block uses these to assemble VS_CHACHA_KEY directly ────────────
.rodata:0xA90   D4 ED 22 E5 9E 42 C1 4B  B9 4C 1B 9C E2 96 A7 67   ← key[4..20]  (xmmword_A90)
.rodata:0xAA0   D8 AF 6C 9E C4 64 A9 2A  55 44 1E B6 00 00 00 00   ← key[20..32] (inline immediates)+pad
```

**Step 1 — read `key[0:8]` directly from `sub_1590`:**

Go back to §11-B. The anti-debug block in `sub_1590` XOR's the first 4
key bytes with the score. The four immediates it XOR's against are
`0xE6 / 0x8F / 0x27 / 0xB9` — on a clean device score = 0, so those ARE
the key bytes: `key[0:4] = E6 8F 27 B9`. And the very next field
`xmmword_A90[0:4] = D4 ED 22 E5` is `key[4:8]`. So:

```
key[0:8] = E6 8F 27 B9  D4 ED 22 E5
```

You now know the first 8 bytes of `VS_CHACHA_KEY` directly from IDA.

**Step 2 — compare with `xmmword_A70[0:8]`:**

`xmmword_A70` (at `.rodata:0xA70`) starts with `82 EA 5F E6 A4 86 45 E5`.
XOR it with the `key[0:8]` you just derived:

```python
# Save as find_tag.py and run with: python find_tag.py
key_0_8  = bytes.fromhex("e68f27b9d4ed22e5")      # from step 1 above
a70_0_8  = bytes.fromhex("82ea5fe6a48645e5")       # from .rodata:0xA70 (IDA get_bytes)

tag = bytes(a ^ b for a, b in zip(a70_0_8, key_0_8))
print(tag.hex(), repr(tag))
# Output: 6465785f706b6700  b'dex_pkg\x00'
```

The XOR result is a recognisable ASCII string `"dex_pkg\0"`. That is the
XOR tag the C compiler folded into the binary.

**Why does this prove it?** The C source for `derive_dex_key` computed
`mixed[i] = VS_CHACHA_KEY[i] ^ tag[i]` with `tag = "dex_pkg\0" + zeros`.
The compiler constant-folded the loop at compile time and stored only
`mixed` in `.rodata`. So `xmmword_A70[0:8] = key[0:8] XOR "dex_pkg\0"`.

Bytes `[A78..A90]` already contain the last 24 bytes of `VS_CHACHA_KEY`
unchanged (XOR with zeros = no change), confirming the full pattern.
The entire 32 bytes at `.rodata:0xA70` are `VS_CHACHA_KEY ⊕ ("dex_pkg\0" + 24 zeros)`.

Recover the full key with this IDA Python script (**File → Script command** or `Alt+F7`):

```python
import ida_bytes

# xmmword_A70 + xmmword_A80 = 32 bytes at .rodata:0xA70
a70_a80 = ida_bytes.get_bytes(0xA70, 32)

tag = b"dex_pkg\x00" + b"\x00" * 24   # 8-byte tag + 24 zeros

chacha_key = bytes(a ^ b for a, b in zip(a70_a80, tag))

print("chacha_key =", chacha_key.hex())
# chacha_key = e68f27b9d4ed22e59e42c14bb94c1b9ce296a767d8af6c9ec464a92a55441eb6
```

The 12-byte ChaCha20 nonce sits right after at `.rodata:0xAB0`:

```
.rodata:0xAB0   8A 23 22 5C 77 02 FE E4  64 A0 C6 D3
```

```python
chacha_nonce = bytes.fromhex("8a23225c7702fee464a0c6d3")
```

### E — ChaCha20 decrypt + LZ4 decompress

Actual IDA output:

```c
result = malloc(v11);                   // v11 = lz_size  (ChaCha20 output buffer)
if ( result )
{
    v21 = result;
    sub_3C18(v49, &unk_AB0, 0,          // ChaCha20(device_key=v49, nonce=&unk_AB0, ctr=0,
             (char *)a7 + 14,           //          in = payload.bin[14..] (skip outer header),
             result, v11);              //          out = result, len = lz_size)

    v22 = malloc(v10);                  // v10 = stage1_size (LZ4 output buffer)
    if ( v22 )
    {
        v23 = v22;
        v24 = sub_41F0(v21, v11, v22, v10);  // LZ4_decompress(in, in_size, out, out_size)
        free(v21);                            // free the compressed buffer
```

`&unk_AB0` is the 12-byte ChaCha20 nonce at `.rodata:0xAB0`. Double-click
it to see `8a 23 22 5c 77 02 fe e4 64 a0 c6 d3`.

`sub_3C18` is ChaCha20. Press F5 on it and look for the four constants
in the inner loop:

![](images/3c18.png)

```c
// Inside sub_3C18 — the ChaCha20 quarter-round setup:
1634760805   // 0x61707865 = "expa"
857760878    // 0x3320646e = "nd 3"
2036477234   // 0x79622d32 = "2-by"
1797285236   // 0x6b206574 = "te k"
```

These four LE `u32`s spell `expand 32-byte k` — the ChaCha20 sigma
constant (RFC 8439 §2.3). Combined with 10 double-rounds this is
unambiguously ChaCha20.

### F — Stage-1 header validation

IDA's post-LZ4 checks, verbatim:

```c
if ( (v24 & 0x80000000) == 0        // LZ4 returned non-negative (no error)
  && v24 == (_DWORD)v10             // decompressed size matches expected
  && *v23 == 1145647190             // inner "V0ID" magic (same as outer)
  && *((_BYTE *)v23 + 4) == 1 )     // version byte = 1
{
    v25 = *((unsigned __int16 *)v23 + 3);   // prog_size = stage1[6..8] (u16 LE)
    if ( (unsigned int)v25 <= 0xC000 )
    {
        v26 = *((unsigned __int8 *)v23 + 5);    // dig_count = stage1[5]
        v27 = 32 * v26 + 1036;                  // byte offset of bytecode region
        if ( v27 + v25 <= v10 )                 // bytecode fits in buffer
        {
```

Stage-1 layout derived from those byte offsets:

```text
stage1[0..4]    "V0ID"       inner magic  (*v23 == 1145647190)
stage1[4]        1           version      (*(v23+4) == 1)
stage1[5]        dig_count   = 1  ← only ONE oracle   (v26)
stage1[6..8]     prog_size   u16 LE                    (v25)
stage1[8]        rolling seed
stage1[9..12]    pad zeros
stage1[12..44]   digest table = 1 × 32 bytes
                 (offset: 32*1 + 12 = 44, OR 32*v26 + 12)
stage1[44..1068] const_table = 256 × 4 = 1024 bytes
stage1[1068..]   bytecode = prog_size bytes (encrypted)
                 (offset: 32*v26 + 1036 = v27)
```

> **The single digest.** `dig_count = 1` is the central design choice.
> The entire flag passes through a 96-byte salt-driven mixer and is then
> hashed exactly once. The 32 bytes at `stage1[12..44]` are the only
> target value the VM compares against — there is no per-block oracle.

### G — Rolling-XOR decrypt

IDA shows the decrypt loop exactly as this (no simplification):

```c
v29 = *((unsigned __int8 *)v23 + 8);   // rolling seed = stage1[8]
v30 = 0;                               // prev_ct starts at 0
v31 = (char *)v23 + v27;               // pointer to start of bytecode
v32 = *((unsigned __int16 *)v23 + 3);  // loop count = prog_size
do
{
    v33 = *((unsigned __int8 *)v23 + v27);   // ct = bytecode[i]
    --v32;
    v34 = v33 ^ v29;                         // pt = ct ^ k
    v29 = v30 - v29 + 32 * v29;             // k = 31*k + prev_ct
    //    ↑ 32*k - k = 31*k, then + prev_ct (v30)
    *((_BYTE *)v23 + v27++) = v34;           // write decrypted byte back
    v30 = v33;                               // prev_ct = ct (the *input* byte)
}
while ( v32 );
```

Key update rule: `k_{n+1} = 31·k_n + prev_ct`. The key evolves using the
**ciphertext** byte (`v33`), not the plaintext — decryption must start
from byte 0 and cannot be parallelised.

### H — Wire→logical opcode remap

After rolling-XOR, each opcode byte is a "wire" value that must be looked
up in a 32-entry permutation table. IDA shows:

```c
v38 = (unsigned __int8 *)&unk_AFC;   // wire_to_logical[32] at .rodata:0xAFC
// (double-click unk_AFC → 32 bytes, a permutation of {0..31})

// bitmask: bit N set means logical opcode N has operand bytes
// (0x4FBFFFFEuLL >> v40) & 1   ← if bit is 1, copy the operand bytes too

v41 = byte_B1C[v40];   // instruction total size = byte_B1C[logical_opcode]
// (double-click byte_B1C → .rodata:0xB1C, 32 bytes of sizes)
```

After the remap the function calls:

```c
v47 = 8 * v26;    // v26 = dig_count = 1, so v47 = 8
// sub_4400 = VM init:
sub_4400(v48, v36, v25,             // vm_state, bytecode, prog_size
         v23 + 3,                   // digest table (= stage1 + 12)
         v45,                       // dig_count
         (char *)v23 + ((v47 * 4) | 0xC),  // const_table (= stage1 + 44)
         a1, a2);                   // input = phrase bytes, phrase length

// sub_445C = VM run:
v44 = sub_445C(v48, 1000000);       // run up to 1 000 000 steps
// returns: 1 if ok_flag=1 and fail_flag=0, else 0
```

`(v47 * 4) | 0xC` = `(8 * 1 * 4) | 0xC` = `32 | 12` = `44` — which is
exactly the byte offset of the const_table in stage1 (after the 12-byte
header and one 32-byte digest). This confirms the layout derived in §F.

**Where do these tables come from?**

Go back to the rolling-XOR / remap block in `sub_1590` (§11-H). IDA shows:

```c
v38 = (unsigned __int8 *)&unk_AFC;
```

Double-click `unk_AFC` — IDA jumps to `.rodata:0xAFC` and shows 32 bytes.
Read them with IDA Python to confirm:

![](images/afc.png)

**Why you need it:** after rolling-XOR decryption the bytecode opcodes are
still in "wire" form — each opcode byte is a scrambled version of the real
logical opcode. `wire_to_logical[]` is the lookup table that translates
`wire_byte → logical_opcode`. Without it every opcode is meaningless.
Every new build shuffles the table differently, so the bytecode pattern
changes build-to-build even for the same flag checker logic.

```text
.rodata:0xAFC   1F 09 15 02 0A 0B 12 0E  03 06 01 0C 04 19 08 10
                1C 1B 14 05 13 1D 1A 00  11 17 1E 0F 07 18 16 0D
```

Example: wire byte `0x00` → logical opcode `0x1F` (HALT).
Wire byte `0x01` → logical opcode `0x09` (ROL). And so on.

The instruction-size table lives at `byte_B1C`, directly after. Same
approach — IDA shows `byte_B1C` in the remap loop; double-click it:

![](images/b1c.png)

**Why you need it:** to walk the bytecode you must know how many bytes
each instruction occupies. `size_table[logical_opcode]` tells you the
total instruction size (opcode byte + all operand bytes). For example,
logical opcode `0x02` (MOV_RI) has size `6` (1 opcode + 1 reg + 4 imm32);
opcode `0x00` (NOP) has size `1` (just the opcode byte).

```text
.rodata:0xB1C   01 03 06 03 03 03 03 03  03 03 03 02 03 03 03 03
                03 03 06 03 03 03 01 03  02 03 03 04 01 01 02 01
```

Walk the bytecode. You have two options — use `ida_bytes` inside IDA,
or hardcode the values you already read:

**Option A — read from IDA (paste in Script command):**

```python
import ida_bytes

W2L = list(ida_bytes.get_bytes(0xAFC, 32))  # double-click unk_AFC → 0xAFC
SZ  = list(ida_bytes.get_bytes(0xB1C, 32))  # double-click byte_B1C → 0xB1C
```

**Option B — hardcode (already confirmed from IDA above):**

```python
W2L = [0x1f,0x09,0x15,0x02,0x0a,0x0b,0x12,0x0e,0x03,0x06,0x01,0x0c,0x04,0x19,0x08,0x10,
       0x1c,0x1b,0x14,0x05,0x13,0x1d,0x1a,0x00,0x11,0x17,0x1e,0x0f,0x07,0x18,0x16,0x0d]

SZ  = [0x01,0x03,0x06,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x02,0x03,0x03,0x03,0x03,
       0x03,0x03,0x06,0x03,0x03,0x03,0x01,0x03,0x02,0x03,0x03,0x04,0x01,0x01,0x02,0x01]
```

`bc_wire` comes from the full decrypt pipeline. The complete script below
runs everything from scratch — save it as `unpack.py`, put it next to
`voidshell.apk`, and run with `python unpack.py`:

```python
# unpack.py  —  full pipeline: APK → stage-1 → logical bytecode
import hashlib, struct, zipfile
from Crypto.Cipher import ChaCha20

# ── Step 1: read APK ───────────────────────────────────────────────────────────
with zipfile.ZipFile("voidshell.apk") as z:
    so      = z.read("lib/arm64-v8a/libvault.so")
    payload = z.read("assets/payload.bin")

# ── Step 2: recover chacha_key from .rodata:0xA70 (dex_pkg XOR fold) ──────────
a70_a80    = so[0xA70 : 0xA70 + 32]
chacha_key = bytes(a ^ b for a, b in zip(a70_a80, b"dex_pkg\x00" + b"\x00" * 24))

# ── Step 3: chacha_nonce from .rodata:0xAB0 ───────────────────────────────────
chacha_nonce = so[0xAB0 : 0xAB0 + 12]

# ── Step 4: cert SHA-256 from apksigner  ──────────────────────────────────────
CERT_SHA256 = bytes.fromhex(
    "0f508490ff27ba9b9fa0966a018c08f4b1053fbaa54f9a49539ff16aa58f4209")

# ── Step 5: derive device_key ─────────────────────────────────────────────────
device_key = hashlib.sha256(
    chacha_key + CERT_SHA256 + b"\x00" * 16 + b"voidshell-v1"
).digest()

# ── Step 6: outer header → lz_size, stage1_size ───────────────────────────────
assert payload[:4] == b"V0ID"
stage1_size = struct.unpack_from("<I", payload,  6)[0]
lz_size     = struct.unpack_from("<I", payload, 10)[0]

# ── Step 7: ChaCha20 decrypt ──────────────────────────────────────────────────
lz_buf = ChaCha20.new(key=device_key, nonce=chacha_nonce).decrypt(payload[14:])

# ── Step 8: LZ4 block decompress ──────────────────────────────────────────────
def lz4_decompress(src, out_size):
    out = bytearray(); i = 0
    while i < len(src):
        tok = src[i]; i += 1
        ll = tok >> 4
        if ll == 15:
            while True:
                b = src[i]; i += 1; ll += b
                if b != 255: break
        out += src[i:i+ll]; i += ll
        if i >= len(src): break
        off = src[i] | (src[i+1] << 8); i += 2
        ml = (tok & 0xf) + 4
        if (tok & 0xf) == 15:
            while True:
                b = src[i]; i += 1; ml += b
                if b != 255: break
        ref = len(out) - off
        for k in range(ml): out.append(out[ref + k])
    return bytes(out[:out_size])

stage1 = lz4_decompress(lz_buf[:lz_size], stage1_size)
assert stage1[:4] == b"V0ID", "wrong key or nonce!"

# ── Step 9: parse stage-1 header ──────────────────────────────────────────────
dig_count  = stage1[5]
prog_size  = struct.unpack_from("<H", stage1, 6)[0]
seed       = stage1[8]
print(f"dig_count={dig_count}  prog_size={prog_size}  seed=0x{seed:02x}")

off      = 12
digests  = [stage1[off + i*32 : off + (i+1)*32] for i in range(dig_count)]
off     += dig_count * 32 + 256 * 4        # skip digest table + const table
bc_enc   = bytearray(stage1[off : off + prog_size])

# ── Step 10: rolling-XOR decrypt → bc_wire ────────────────────────────────────
k, prev = seed, 0
for i in range(len(bc_enc)):
    c = bc_enc[i]; bc_enc[i] = c ^ k
    k = (k * 31 + prev) & 0xFF; prev = c
bc_wire = bytes(bc_enc)

# ── Step 11: wire → logical remap → bc ────────────────────────────────────────
W2L = [0x1f,0x09,0x15,0x02,0x0a,0x0b,0x12,0x0e,0x03,0x06,0x01,0x0c,0x04,0x19,0x08,0x10,
       0x1c,0x1b,0x14,0x05,0x13,0x1d,0x1a,0x00,0x11,0x17,0x1e,0x0f,0x07,0x18,0x16,0x0d]
SZ   = [0x01,0x03,0x06,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x02,0x03,0x03,0x03,0x03,
        0x03,0x03,0x06,0x03,0x03,0x03,0x01,0x03,0x02,0x03,0x03,0x04,0x01,0x01,0x02,0x01]

bc, i = bytearray(), 0
while i < len(bc_wire):
    lo = W2L[bc_wire[i]]
    sz = SZ[lo]
    bc.append(lo); bc += bc_wire[i+1:i+sz]; i += sz

print(f"[+] logical bytecode: {len(bc)} bytes")
print(f"[+] target digest   : {digests[0].hex()}")
```

![](images/shell9.png)

---

## Step 12 — The 32-opcode VM (`sub_4400` / `sub_445C`)

You already know `sub_445C` is the VM dispatcher — `sub_1590` calls it at
the very end:

```c
v44 = sub_445C(v48, 1000000);   // run VM, max 1 000 000 steps
```

Press **F5** on `sub_445C`. Hex-Rays shows a large `switch` statement. The
switch variable is the **logical opcode** byte (already remapped from wire
at this point). Each `case N:` is one opcode. Read each case to find:

1. **What registers / immediates it reads** from the bytecode (the `R8()` /
   `R16()` / `R32()` calls that advance the PC).
2. **What it does** — arithmetic on registers, memory reads/writes, hash ops,
   comparisons, jumps.
3. **The exit conditions** — `ok_flag`, `fail_flag`, `halt_flag` fields in the
   VM struct.

Work through all 32 cases and you get this opcode table — each row is one
`case N:` from the switch:

| op | Mnemonic | Operands | Effect |
|---:|----------|----------|--------|
| 0x00 | NOP | — | no-op |
| 0x01 | MOV_RR | reg, reg | `Rd = Rs` |
| 0x02 | MOV_RI | reg, imm32 | `Rd = imm32` |
| 0x03 | ADD | reg, reg | `Rd += Rs` |
| 0x04 | SUB | reg, reg | `Rd -= Rs` |
| 0x05 | XOR | reg, reg | `Rd ^= Rs` |
| 0x06 | AND | reg, reg | `Rd &= Rs` |
| 0x07 | OR  | reg, reg | `Rd \|= Rs` |
| 0x08 | MUL | reg, reg | `Rd *= Rs` |
| 0x09 | ROL | reg, reg | `Rd = ROL32(Rd, Rs)` |
| 0x0A | ROR | reg, reg | `Rd = ROR32(Rd, Rs)` |
| 0x0B | NOT | reg | `Rd = ~Rd` |
| 0x0C | SHL | reg, imm8 | `Rd <<= imm8` |
| 0x0D | SHR | reg, imm8 | `Rd >>= imm8` |
| 0x0E | LD_IN  | reg, imm8 | `Rd = input[imm8]` |
| 0x0F | LD_IN4 | reg, imm8 | `Rd = u32_le(input[imm8..imm8+4])` |
| 0x10 | LD_CONST | reg, imm8 | `Rd = const_table[imm8]` |
| 0x11 | CMP_RR | reg, reg | `flag = (Rd == Rs)` |
| 0x12 | CMP_RI | reg, imm32 | `flag = (Rd == imm32)` |
| 0x13 | JZ  | imm16 | `if (!flag) pc += imm16` |
| 0x14 | JNZ | imm16 | `if ( flag) pc += imm16` |
| 0x15 | JMP | imm16 | `pc += imm16` |
| 0x16 | H_INIT | — | calls `sub_333C` (masked SHA-256 init) |
| 0x17 | H_UPDATE | reg, imm8 | `SHA_Update(scratch[Rd], imm8)` |
| 0x18 | H_FINAL  | reg | `SHA_Final → scratch[Rd]` |
| 0x19 | MEM_WR | reg, reg | `scratch[Rd] = Rs & 0xFF` |
| 0x1A | MEM_RD | reg, reg | `Rd = scratch[Rs]` |
| 0x1B | CHK_DIG | reg, imm8, imm8 | `flag = scratch[Rd..+len] == digests[idx]` |
| 0x1C | FAIL | — | `fail = 1` |
| 0x1D | OK   | — | `ok = 1` |
| 0x1E | INPUT_LEN | reg | `Rd = len(input)` (declared but unused) |
| 0x1F | HALT | — | terminate dispatch |

The VM state object (32 bytes header + 16 u32 regs + 256-byte scratch):

```c
struct vs_vm {
    uint8_t  *bc;         // 0x00
    size_t    bc_len;     // 0x08
    uint8_t  *digests;    // 0x10
    uint8_t   dig_count;  // 0x18
    uint32_t *consts;     // 0x20
    uint8_t  *input;      // 0x28
    size_t    input_len;  // 0x30
    sha256ctx sha;        // 0x40 (~104 bytes: state[8] + bit_count + buf[64])
    uint32_t  regs[16];   // 0xA8  (16 × 4 = 64 bytes)
    uint8_t   scratch[256]; // 0xE8
    uint16_t  pc;         // 0x1E8
    uint8_t   flag;       // 0x1EA
    uint8_t   fail;       // 0x1EB
    uint8_t   ok;         // 0x1EC
    uint8_t   halted;     // 0x1ED
};
```

### The "masked" SHA-256

Look at `sub_333C` (called by `case 0x16: H_INIT`):

![](images/sub_333c.png)

These are NOT the FIPS H0 vector. They are `sha_h0_masked` — the same
32-byte run we saw at `.rodata:0xADC` in §6.5. So `H_INIT` initialises a
hash context whose IV is the **per-build masked vector**, then uses the
standard FIPS round function and `K[64]` constants. The result is
**SHA-256 with a non-canonical IV** — a "masked" SHA-256.

```python
def masked_sha256(data, iv_mask):
    # standard SHA-256, but H = FIPS_H0[i] ^ u32_be(iv_mask[i*4:i*4+4])
    # Full implementation is in Step 15 (verify.py) and solve/solve.py
    ...
```

> **Pitfall.** If you naively `hashlib.sha256(post_mix)` against the
> stored target, you will get a wrong digest and not understand why. The
> VM uses masked SHA-256 — you must mirror it byte-for-byte. Pass the
> 32-byte `sha_iv_mask` (`.rodata:0xABC`) into a hand-rolled
> `masked_sha256`. A reference implementation is in
> [`solve/solve.py`](solve/solve.py).

---

## Step 13 — Decrypt `payload.bin` end-to-end

```python
# decrypt_payload.py
import hashlib, struct
from Crypto.Cipher import ChaCha20

# §11-D — VS_CHACHA_KEY recovered by XOR'ing rodata[0xA70..A90] with "dex_pkg\0"+24 zeros
VS_CHACHA_KEY   = bytes.fromhex(
    "e68f27b9d4ed22e59e42c14bb94c1b9c"
    "e296a767d8af6c9ec464a92a55441eb6")

# §11-D — VS_CHACHA_NONCE at .rodata:0xAB0
VS_CHACHA_NONCE = bytes.fromhex("8a23225c7702fee464a0c6d3")

# §6.3 — apksigner output
CERT_SHA256     = bytes.fromhex(
    "0f508490ff27ba9b9fa0966a018c08f4b1053fbaa54f9a49539ff16aa58f4209")

# §11-A — outer "V0ID" header
payload     = open("assets/payload.bin", "rb").read()
stage1_size = struct.unpack_from("<I", payload,  6)[0]
lz_size     = struct.unpack_from("<I", payload, 10)[0]

# §11-C — device_key = SHA256(VS_CHACHA_KEY || cert || 0×16 || "voidshell-v1")
device_key  = hashlib.sha256(
    VS_CHACHA_KEY + CERT_SHA256 + b"\x00"*16 + b"voidshell-v1"
).digest()

# §11-E — ChaCha20 + LZ4
lz     = ChaCha20.new(key=device_key, nonce=VS_CHACHA_NONCE).decrypt(payload[14:])

def lz4_block_decompress(src, out_size):
    out = bytearray(); i = 0
    while i < len(src):
        token = src[i]; i += 1
        ll = token >> 4
        if ll == 15:
            while True:
                b = src[i]; i += 1; ll += b
                if b != 255: break
        out += src[i:i+ll]; i += ll
        if i >= len(src): break
        offset = src[i] | (src[i+1] << 8); i += 2
        ml = (token & 0xF) + 4
        if (token & 0xF) == 15:
            while True:
                b = src[i]; i += 1; ml += b
                if b != 255: break
        ref = len(out) - offset
        for k in range(ml):
            out.append(out[ref + k])
    return bytes(out[:out_size])

stage1 = lz4_block_decompress(lz[:lz_size], stage1_size)
assert stage1[:4] == b"V0ID"

# §11-F — stage-1 header parsing
dig_count = stage1[5]                                          # 1
prog_size = struct.unpack_from("<H", stage1, 6)[0]
seed      = stage1[8]
print(f"digest_count={dig_count}  prog_size={prog_size}  seed=0x{seed:02x}")

off       = 12
digests   = [stage1[off + i*32 : off + (i+1)*32] for i in range(dig_count)]
off      += dig_count*32
consts    = list(struct.unpack_from(f"<{256}I", stage1, off))
off      += 256*4
bc_wire   = bytearray(stage1[off:off + prog_size])

# §11-G — rolling-XOR decrypt
k, prev = seed, 0
for i in range(len(bc_wire)):
    c = bc_wire[i]; bc_wire[i] = c ^ k
    k = (k*31 + prev) & 0xFF; prev = c

# §11-H — wire → logical remap (read from .rodata:0xAFC and 0xB1C)
W2L = [0x1f,0x09,0x15,0x02,0x0a,0x0b,0x12,0x0e,0x03,0x06,0x01,0x0c,0x04,0x19,0x08,0x10,
       0x1c,0x1b,0x14,0x05,0x13,0x1d,0x1a,0x00,0x11,0x17,0x1e,0x0f,0x07,0x18,0x16,0x0d]
SZ  = [1,3,6,3,3,3,3,3,3,3,3,2,3,3,3,3,3,3,6,3,3,3,1,3,2,3,3,4,1,1,2,1]

bc, i = bytearray(), 0
while i < len(bc_wire):
    lo = W2L[bc_wire[i]]; sz = SZ[lo]
    bc.append(lo); bc += bc_wire[i+1:i+sz]; i += sz

print(f"[+] bytecode ready — {len(bc)} bytes")
print(f"[+] target digest  : {digests[0].hex()}")
```

Output for the shipped APK:

![](images/shell9.png)

> **Notice:** `digest_count = 1` and the program is a *single* end-to-end
> sequence — there is no per-block checking. We will see why next.

---

## Step 14 — Decode the bytecode shape

A complete all-in-one script does everything: APK → decrypt → LZ4 →
rolling-XOR → wire remap → disassemble → extract salt.
Save [`solve/disasm.py`](solve/disasm.py) next to `voidshell.apk` and run:

```bash
python3 solve/disasm.py voidshell.apk
```

![](images/shell10.png)

The script that produces the disassembly (key parts explained inline):

```python
# Opcode name table — index matches the logical opcode number from Step 12
NAMES = {
    0x00:"NOP",    0x01:"MOV_RR", 0x02:"MOV_RI", 0x03:"ADD",
    0x04:"SUB",    0x05:"XOR",    0x06:"AND",    0x07:"OR",
    0x08:"MUL",    0x09:"ROL",    0x0A:"ROR",    0x0B:"NOT",
    0x0C:"SHL",    0x0D:"SHR",    0x0E:"LD_IN",  0x0F:"LD_IN4",
    0x10:"LD_CONST",0x11:"CMP_RR",0x12:"CMP_RI", 0x13:"JZ",
    0x14:"JNZ",    0x15:"JMP",    0x16:"H_INIT", 0x17:"H_UPDATE",
    0x18:"H_FINAL",0x19:"MEM_WR", 0x1A:"MEM_RD", 0x1B:"CHK_DIG",
    0x1C:"FAIL",   0x1D:"OK",     0x1E:"INPUT_LEN",0x1F:"HALT",
}

pc = 0
while pc < len(bc):
    op = bc[pc]
    sz = SZ[op]
    name = NAMES.get(op, f"OP_{op:02X}")
    # format operand bytes as hex
    raw = bc[pc+1 : pc+sz]
    args = " ".join(f"{b:02x}" for b in raw)
    print(f"{pc:04x}  {name:<12} {args}")
    pc += sz
```

Actual output of `python3 disasm.py voidshell.apk` — trimmed with `...`
markers so you can see each section without 15 000 lines of output:

```text
[+] dig_count=1  prog_size=15971  seed=0xc8
[+] logical bytecode: 15971 bytes
[+] target digest   : 4a91bb839d5d9e90bb296972b5ea16bfce0b0748af4d25461632fc5d3faa6392

;; [A] 0x0000..0x02FF — copy 64 input bytes into scratch[0..64]
0000  LD_IN        R1, 0            ; R1 = input[0]
0003  MOV_RI       R2, 0            ; R2 = scratch addr
0009  MEM_WR       R2, R1           ; scratch[0] = input[0]
000c  LD_IN        R1, 1
000f  MOV_RI       R2, 1
0015  MEM_WR       R2, R1           ; scratch[1] = input[1]
...   (×64 total, indices 0..63)
02f4  LD_IN        R1, 63
02f7  MOV_RI       R2, 63
02fd  MEM_WR       R2, R1           ; scratch[63] = input[63]

;; [B] 0x0300..0x04DF — paint 32-byte SALT into scratch[64..96]
0300  MOV_RI       R1, 188          ; salt[0] = 0xbc  ← immediate IS the salt byte
0306  MOV_RI       R2, 64           ; scratch addr = 64
030c  MEM_WR       R2, R1           ; scratch[64] = 0xbc
030f  MOV_RI       R1, 79           ; salt[1] = 0x4f
0315  MOV_RI       R2, 65
031b  MEM_WR       R2, R1
...   (×32 total; 32 immediates = the full salt)
04c0  (section B ends)

;; [C] 0x04C0..0x3E3F — 3-round mixer (288 steps, 14688 bytes)
;; Each step: scratch[j] = (scratch[j] XOR KEY[r] ROL8 SHIFT[r]) + scratch[partner]
04c0  MOV_RI       R2, 45           ; j = 45 (from perm[0][0])
04c6  MEM_RD       R1, R2           ; R1 = scratch[45]
04c9  MOV_RI       R3, 201          ; KEY[0] = 0xc9
04cf  XOR          R1, R3           ; R1 ^= KEY
04d2  MOV_RR       R4, R1
04d5  SHL          R4, 3            ; SHIFT[0] = 3 (left part of rol8)
04d8  SHR          R1, 5            ;             (right part of rol8)
04db  OR           R4, R1           ; R4 = rol8(R1, 3)
04de  MOV_RI       R2, 37           ; partner = (45*STEP+0) % 96
04e4  MEM_RD       R6, R2           ; R6 = scratch[partner]
04e7  ADD          R4, R6           ; R4 += scratch[partner]
04ea  MOV_RI       R2, 45
04f0  MEM_WR       R2, R4           ; scratch[45] = R4 & 0xFF
...   (288 steps total; same 13-instruction pattern, different j/KEY/SHIFT/partner per step)
3e3d  MEM_WR       R2, R4           ; last mixer write

;; [D] 0x3E40..0x3E57 — masked SHA-256 over full 96-byte buffer
3e40  H_INIT                        ; init hash with per-build masked H0 (sub_333C)
3e41  MOV_RI       R3, 0
3e47  H_UPDATE     R3, 96           ; SHA_Update(scratch[0..96])
3e4a  MOV_RI       R3, 128
3e50  H_FINAL      R3               ; SHA_Final → scratch[128..160]

;; [E] 0x3E52..0x3E62 — single oracle
3e52  MOV_RI       R3, 128
3e58  CHK_DIG      R3, 32, 0        ; compare scratch[128..160] vs digests[0]
3e5c  JZ           0x3e61 (rel +2)  ; flag=0 (mismatch) → FAIL
3e5f  OK
3e60  HALT
3e61  FAIL
3e62  HALT

[+] salt = bc4ff063167709ec1f44a50a248150e13700d8ca10183957b8c6c4910c9e2f4b
```

There is no length comparison. There is no `HTB{` prefix check. Wrong
input simply produces the wrong post-mix buffer → wrong masked-SHA-256
digest → mismatch at `CHK_DIG`. The single 32-byte target at
`stage1[12..44]` is the **only** value the VM ever compares against.

### Recovering the SALT

The 32-byte salt is painted byte-by-byte by the `(MOV_RI imm) (MOV_RI
addr) MEM_WR` triples in section [B]. Walk the bytecode, collect them:

```python
salt = bytearray(32)
i = 0
last1 = last2 = (None, None)
while i < len(bc):
    op = bc[i]; sz = SZ[op]
    if op == 0x02:                                   # MOV_RI
        last2 = last1
        last1 = (bc[i+1], int.from_bytes(bc[i+2:i+6], "little"))
        i += 6
    elif op == 0x19:                                 # MEM_WR
        ar, vr = bc[i+1], bc[i+2]
        a_dst, a_imm = last1
        v_dst, v_imm = last2
        if a_dst == ar and v_dst == vr and 64 <= a_imm < 96:
            salt[a_imm - 64] = v_imm & 0xFF
        i += 3
    else:
        i += sz

print("SALT:", bytes(salt).hex())
# SALT: bc4ff063167709ec1f44a50a248150e13700d8ca10183957b8c6c4910c9e2f4b
```

### Recovering the mixer schedule

The schedule (PERM, KEY, SHIFT, STEP per round) is fully determined by
the salt. You can deduce that from three observations on the
disassembly:

1. The 96 indices `j` per round form a permutation of `{0..95}`.
2. Each step uses the same `KEY[r]`, `SHIFT[r]`, and `STEP[r]` immediate
   values.
3. The "partner" offsets satisfy `partner = (j*STEP[r] + r) mod 96`.

**You do not need to find `"vsmix-v2"`** — that prefix lives in the
challenge author's Python build tooling, not in `libvault.so` or in
`payload.bin`. A player solving from the APK alone never sees it.

**What you actually do:** read the schedule directly off the disassembler
output. Every `MOV_RI R3, KEY` (one per step) gives you KEY for that
round. Every `SHL R4, N` gives you SHIFT. Every `MOV_RI R2, partner`
gives you the partner index. The 96 `j` values per round are the sequence
of `MOV_RI R2, j` at the start of each step. You already have all of that
from `disasm.py`.

Extract it with a short script added to `disasm.py`:

```python
# extract_schedule.py  — reads (j, KEY, SHIFT, partner) from bytecode
import struct

schedule = []    # list of (j, key, shift, partner) for each step
i = 0
while i < len(bc):
    op = bc[i]
    # Mixer step pattern: MOV_RI R2, j → MEM_RD → MOV_RI R3, key → XOR →
    #   MOV_RR → SHL R4, shift → SHR R1, (8-shift) → OR → MOV_RI R2, partner → ...
    if (op == 0x02 and bc[i+1] == 0x02         # MOV_RI R2, j
            and i+6 < len(bc)
            and bc[i+6] == 0x1A):              # followed by MEM_RD
        j = struct.unpack_from("<I", bc, i+2)[0]
        # key is the immediate in MOV_RI R3, key — comes right after MEM_RD (3 bytes)
        key_off = i + 6 + 3                    # skip MOV_RI R2,j (6) + MEM_RD (3)
        if bc[key_off] == 0x02 and bc[key_off+1] == 0x03:  # MOV_RI R3, key
            key = struct.unpack_from("<I", bc, key_off+2)[0]
            # shift: SHL R4, shift is 2 instructions after XOR
            shl_off = key_off + 6 + 3 + 3     # skip MOV_RI + XOR + MOV_RR
            if bc[shl_off] == 0x0C:            # SHL
                shift = bc[shl_off+2]
                schedule.append((j, key, shift))
    i += SZ[op]

# Print first 5 steps per round
for r in range(3):
    print(f"Round {r}: first 5 steps =", schedule[r*96:r*96+5])
```

The result is the full mixer schedule extracted directly from the
bytecode — no guessing, no PRNG reversal needed.

For this APK the first steps are:

```text
Round 0 step 0: j=45  KEY=0xC9  SHIFT=3  partner=37
Round 0 step 1: j=72  KEY=0xC9  SHIFT=3  partner=50
...
Round 1 step 0: j=..  KEY=0xE7  SHIFT=7  partner=..
Round 2 step 0: j=..  KEY=0x46  SHIFT=5  partner=..
```

KEY and SHIFT are constant per round (all 96 steps in a round share them);
only j and partner change. STEP (the multiplier for partner) is what
varies per step as `(j * STEP + r) % 96`.

---

## Step 15 — Verify a candidate with the recovered pipeline

Compose the mixer + masked SHA-256 in Python and check:

```python
# verify.py — mirrors the VM execution to verify a candidate flag
# Run: python3 verify.py
import hashlib, math, random, struct

# ─────────────────────────────────────────────────────────────────────────────
# derive_mix_schedule(salt)
#
# WHERE YOU GET THIS:
#   Read from the [C] mixer block in disasm.py output:
#   - The 96 j-values in round 0 form a permutation of 0..95 → random.shuffle()
#   - KEY[r] is the same immediate for all 96 steps in round r  → MOV_RI R3, KEY
#   - SHIFT[r] same across round r                             → SHL R4, SHIFT
#   - Seeding random.Random(sha256(prefix + salt)) and matching
#     the first shuffle output against the j-sequence from disasm.py
#     confirms prefix = b"vsmix-v2|"
#   NOTE: you can skip this entirely — just read all 288 (j,KEY,SHIFT,partner)
#   tuples directly from disasm.py. No PRNG reversal required.
# ─────────────────────────────────────────────────────────────────────────────
def derive_mix_schedule(salt):
    rng = random.Random(hashlib.sha256(b"vsmix-v2|" + salt).digest())
    perms, keys, shifts, partners = [], [], [], []
    for _ in range(3):
        p = list(range(96)); rng.shuffle(p); perms.append(p)
        keys.append(rng.randrange(0, 256))
        shifts.append(rng.randrange(1, 8))
        while True:
            step = rng.randrange(3, 95) | 1
            if math.gcd(step, 96) == 1: break
        partners.append(step)
    return perms, keys, shifts, partners

# ─────────────────────────────────────────────────────────────────────────────
# reference_mix(buf, salt)
#
# WHERE YOU GET THIS:
#   Each of the 288 steps in [C] of the disasm output is 13 instructions:
#     MOV_RI R2, j       → j index
#     MEM_RD R1, R2      → R1 = scratch[j]
#     MOV_RI R3, KEY     → KEY[r] (same for whole round)
#     XOR    R1, R3      → R1 ^= KEY
#     MOV_RR R4, R1
#     SHL    R4, SHIFT   → left part of rol8
#     SHR    R1, 8-SHIFT → right part of rol8
#     OR     R4, R1      → R4 = rol8(scratch[j] ^ KEY, SHIFT)
#     MOV_RI R2, partner → (j*STEP + r) % 96
#     MEM_RD R6, R2      → R6 = scratch[partner]
#     ADD    R4, R6      → R4 += scratch[partner]
#     MOV_RI R2, j
#     MEM_WR R2, R4      → scratch[j] = R4 & 0xFF  (MEM_WR truncates to byte)
# ─────────────────────────────────────────────────────────────────────────────
def reference_mix(buf, salt):
    perms, keys, shifts, partners = derive_mix_schedule(salt)
    for r in range(3):
        k_r, s_r, p_r = keys[r], shifts[r], partners[r]
        for j in perms[r]:
            partner = (j * p_r + r) % 96
            v = (buf[j] ^ k_r) & 0xFF
            v = ((v << s_r) | (v >> (8 - s_r))) & 0xFF   # rol8
            v = (v + buf[partner]) & 0xFF
            buf[j] = v

# ─────────────────────────────────────────────────────────────────────────────
# masked_sha256(data, iv_mask)
#
# WHERE YOU GET THIS:
#   - The VM opcode H_INIT (case 0x16) calls sub_333C.
#   - sub_333C loads 8 hardcoded u32 immediates directly into ctx->state[].
#     Those immediates are VS_SHA_H0_MASKED (= FIPS_H0 XOR iv_mask).
#   - iv_mask = VS_SHA_IV_MASK read from .rodata:0xABC:
#       ida_bytes.get_bytes(0xABC, 32)
#   - K[64] constants = standard SHA-256 round constants, visible at .rodata:0xB3C
#   - H0 = FIPS 180-4 §5.3.3 (the public standard — NOT from the binary)
#   - The round function is identical to standard SHA-256; only the IV differs.
# ─────────────────────────────────────────────────────────────────────────────
def masked_sha256(data, iv_mask):
    K = (0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
         0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
         0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
         0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
         0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
         0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
         0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
         0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
         0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
         0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
         0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2)
    # FIPS 180-4 SHA-256 initial H0 (public standard, not from the binary)
    H0 = (0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
          0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
    # XOR H0 with iv_mask → the non-FIPS starting state that sub_333C uses
    H = [(H0[i] ^ struct.unpack(">I", iv_mask[i*4:i*4+4])[0]) & 0xFFFFFFFF
         for i in range(8)]
    msg = bytearray(data); msg.append(0x80)
    while len(msg) % 64 != 56: msg.append(0x00)
    msg += struct.pack(">Q", len(data) * 8)
    def ror(v, n): return ((v >> n) | ((v << (32 - n)) & 0xFFFFFFFF))
    for off in range(0, len(msg), 64):
        w = list(struct.unpack(">16I", bytes(msg[off:off + 64])))
        for i in range(16, 64):
            s0 = ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = ror(w[i-2],  17) ^ ror(w[i-2],  19) ^ (w[i-2]  >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, h = H
        for i in range(64):
            S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
            ch = (e & f) ^ ((~e) & 0xFFFFFFFF & g)
            t1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
            mj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + mj) & 0xFFFFFFFF
            h, g, f = g, f, e; e = (d + t1) & 0xFFFFFFFF
            d, c, b = c, b, a; a = (t1 + t2) & 0xFFFFFFFF
        H = [(H[0]+a)&0xFFFFFFFF, (H[1]+b)&0xFFFFFFFF,
             (H[2]+c)&0xFFFFFFFF, (H[3]+d)&0xFFFFFFFF,
             (H[4]+e)&0xFFFFFFFF, (H[5]+f)&0xFFFFFFFF,
             (H[6]+g)&0xFFFFFFFF, (H[7]+h)&0xFFFFFFFF]
    return b"".join(struct.pack(">I", x) for x in H)

# ─────────────────────────────────────────────────────────────────────────────
# Constants — WHERE EACH COMES FROM:
#
# SHA_IV_MASK:
#   IDA: ida_bytes.get_bytes(0xABC, 32).hex()   (double-click dword_ABC)
#   = sha_iv_mask at .rodata:0xABC
#
# TARGET:
#   disasm.py output:  "[+] target digest : ..."
#   OR: stage1[12:44] from the ChaCha20+LZ4 pipeline (Step 13)
#
# SALT:
#   disasm.py output:  "[+] salt = ..."
#   OR: the 32 MOV_RI R1, byte immediates at bytecode pc 0x0300..0x04DF (Step 14)
# ─────────────────────────────────────────────────────────────────────────────
SHA_IV_MASK = bytes.fromhex(
    "8925e13cb582ce3bb667fae4882fed735f70fcb453d36242b5ddaf9d11a7a3aa")

TARGET = bytes.fromhex(
    "4a91bb839d5d9e90bb296972b5ea16bfce0b0748af4d25461632fc5d3faa6392")

SALT = bytes.fromhex(
    "bc4ff063167709ec1f44a50a248150e13700d8ca10183957b8c6c4910c9e2f4b")

def verify(candidate, salt, target):
    buf = bytearray(96)
    buf[:len(candidate)] = candidate[:64]  # input → scratch[0..64]
    buf[64:96] = salt                       # salt  → scratch[64..96]
    reference_mix(buf, salt)                # [C] mixer
    return masked_sha256(bytes(buf), SHA_IV_MASK) == target  # [D]+[E]

print(verify(b"HTB{REDACTED}", SALT, TARGET))
# True
```

---

## Step 16 — Recover the flag

The challenge has exactly one digest oracle. Brute force over the inner
bytes is not viable (~95<sup>40+</sup> candidates). The intended
strategy is **algebraic**:

1. The 3-round mixer uses only invertible 8-bit operations:
   `v ← v ⊕ KEY[r]`, then `v ← rol8(v, SHIFT[r])`, then `v ← (v +
   scratch[partner]) mod 256`. Each is a bijection over `Z_256`.
2. Encode each scratch byte as a Z3 `BitVec(8)`. Constants
   (`HTB{` prefix, `}` suffix, salt bytes) are fixed. The remaining
   inner-flag bytes are unknowns constrained to printable ASCII.
3. Run the mixer symbolically over the 96-byte buffer to express each
   post-mix byte as a function of the unknowns.
4. The masked SHA-256 is *not* invertible in Z3 directly, but with the
   tight constraints from the mixer (after 3 rounds, every input byte
   affects roughly all 96 output bytes) the candidate set is small
   enough to enumerate, and each candidate can be tested forward in
   ~50 µs.

A reference solver that performs the verification end-to-end (and
illustrates how the constants come out of the binary) is in
[`solve/solve.py`](solve/solve.py). It runs in ~5 seconds and confirms a
candidate flag against the APK alone — no source needed:

![](images/solved.png)

---

## Step 17 — Submit

Enter the recovered phrase in **Project Nightfall \[SEALED\]**. The
vault entry unlocks:

![](images/solve.png)

**`HTB{.............................}`**

---

## Appendix — Every constant and where it came from

| Constant | Source | Value |
|---|---|---|
| Per-string XOR step | `(17·k_i + i + 0x9e) mod 256` (in every decode loop) | — |
| `voidshell-dex-v1` | `byte_119F` (17 B), start key `0x97` | string fed to dex KDF |
| `voidshell-v1` | `byte_CB6` (13 B), start key `0x15` | string fed to device KDF |
| Mixed dex-key | `xmmword_A70/A80` at `.rodata:0xA70` | `82ea5fe6 … 55441eb6` |
| `VS_CHACHA_KEY` | `xmmword_A70 ⊕ ("dex_pkg\0"+24 zeros)` | `e68f27b9 … 55441eb6` |
| `VS_CHACHA_NONCE` | `.rodata:0xAB0` (12 B) | `8a23225c7702fee464a0c6d3` |
| Wire→logical map | `.rodata:0xAFC` (32 B) | permutation of `0..31` |
| Instruction sizes | `.rodata:0xB1C` (32 B) | operand byte counts |
| `sha_iv_mask` | `.rodata:0xABC` (32 B, BE u32s) | XOR'd by `sub_3278` to recover FIPS H0 |
| `sha_h0_masked` | `.rodata:0xADC` (32 B, BE u32s) | loaded directly by `sub_333C` (masked init) |
| ChaCha20 sigma | inline in `sub_3C18` (`0x61707865 0x3320646e 0x79622d32 0x6b206574`) | `expand 32-byte k` |
| Cert SHA-256 | `apksigner verify --print-certs voidshell.apk` | `0f508490…` |
| Device key | `SHA256(VS_CHACHA_KEY \|\| cert \|\| 16 zero bytes \|\| "voidshell-v1")` | `b01322f6…` |
| Rolling-XOR seed | `stage1[8]` after ChaCha20+LZ4 | `0xC8` |
| Salt | `MOV_RI` immediates writing `scratch[64..96]` in bytecode | `bc4ff063…` |
| Target digest | `stage1[12..44]` (single 32-byte oracle) | `4a91bb83…` |
| Mixer schedule | `random.Random(SHA256(b'vsmix-v2|' + salt))` | per-round `(perm, key, shift, step)` |
| Flag | recovered SMT / forward-test against the single oracle | `HTB{.............................}` |


![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>Sysprobe</font>

20<sup>th</sup> March 2026

Prepared By: `Kailash S`

Challenge Author(s): `Kailash S`

Difficulty: <font color='Grey'>Insane</font>

<br><br>


# Synopsis 

`sysprobe` is a stripped Linux ELF binary that presents itself as a routine system diagnostics utility. Ghidra finds one meaningful function  a convincing `SysProbe` implementation with CPU readouts, memory stats, and network interface listings. No comparisons, no crypto, no flag logic. Nothing suspicious.
Running it tells a completely different story.

C2 beacon calls, persistence attempts, malware-style telemetry none of it traceable to any function the disassembler can find. The code and the behaviour are irreconcilable. The explanation is not in the decompiled output. It is buried in the ELF structure itself.
The binary has been parasitically modified at the segment level. Its `PT_NOTE` segment has been overwritten with an injected `PT_LOAD` stub that silently hijacks the entry point before `main` ever executes. That stub decrypts and inflates a hidden payload into an anonymous RWX memory region at runtime  a region that does not exist on disk, cannot be extracted statically, and leaves no trace in the symbol table.

Inside that payload lives a custom 25-opcode virtual machine running XOR-obfuscated bytecode. Inside that VM, the flag is encoded as a 256-dimensional quantum state vector — forward-rotated through six non-commutative matrix operations and stored as Q1.30 fixed-point integers in the heap. Recovering it requires identifying the correct inversion order, applying six inverse Givens rotations across alternating even and odd index pairs, and collapsing the resulting state through a probability amplitude threshold.

## Description 

Task Force Nightfall has intercepted a binary pulled from a compromised monitoring node inside a critical infrastructure operator. On the surface it is exactly what it claims to be  a routine diagnostics utility, the kind deployed silently across thousands of managed endpoints. Clean signature, legitimate-looking output, nothing that trips an alert. But the node it was found on had no business running it. And the traffic logs don't match what a diagnostics tool should produce.

## Skills Required 

- Solid understanding of ELF binary internals and x86-64 architecture
- Experience with static analysis tools such as Ghidra or IDA Pro
- Familiarity with dynamic analysis techniques including ptrace and `/proc` filesystem inspection
- Python scripting for binary parsing and mathematical reconstruction

## Skills Learned 

- How parasitic ELF injection works at the segment level and how to detect it from program headers alone
- Extracting and analyzing a runtime-only payload that exists exclusively in memory and has no static footprint on disk
- Reversing a custom virtual machine mapping an unknown instruction set, defeating anti-disassembly tricks, and reconstructing execution semantics
- Decoding XOR-obfuscated bytecode and tracing execution through a FLAGS-driven dual-decode mode
- Understanding quantum-inspired state vector encoding  applying inverse Givens rotations across alternating index layers and recovering data through probability amplitude collapse
## MITRE Mappings

- **T1542.001 – Pre-OS Boot: System Firmware** Modification of the ELF entry point and program header table to redirect execution through an injected loader stub before the legitimate host code runs.
- **T1055.009 – Process Injection: Proc Memory** Decompression and execution of a hidden payload directly into an anonymous RWX memory region via runtime inflation, leaving no artifact on disk.
- **T1027.002 – Obfuscated Files or Information: Software Packing** The payload is stored as an XOR-encrypted raw DEFLATE stream inside the host binary, destroying all static signatures and preventing extraction by standard tooling.
- **T1620 – Reflective Code Loading** The injected loader stub resolves and executes the embedded payload entirely in memory without touching the filesystem, using a custom inflate implementation with no libc dependency.
# Enumeration 

## Analyzing the Given Files 

`sysprobe` 

Running `file` confirms it is a standard x86-64 PIE executable, dynamically linked, with no debug symbols , exactly what a legitimate system utility would look like.

```bash
$ file sysprobe
sysprobe: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c25aad114d437eb0da2fabed5914e2bd74ce40a0, 
for GNU/Linux 3.2.0, stripped
```

Running `strings` on the binary produces the expected diagnostics output  version strings, CLI flags, hardware readouts  followed by something immediately out of place: a dense block of high-entropy ASCII garbage.

```bash
$ strings sysprobe
```
```
SysProbe Diagnostics Utility v%s
1.0.3
20240315
--version
--help
--full
Running system diagnostics...
CPU Information
Architecture : x86_64
Cores        : 4
Frequency    : 2400 MHz
Memory Information
Total RAM    : 8192 MB
Available    : 4096 MB
Swap         : 2048 MB
Disk Information
/dev/sda1    : 50 GB (ext4)
/dev/sda2    : 200 GB (ext4)
Network Interfaces
eth0         : 192.168.1.100
lo           : 127.0.0.1
All diagnostics completed successfully.
No anomalies detected.
...
Ny7o
J,o81Z/
)-]f
Tl,6
```

Running the binary produces output that has no relationship to anything `strings` found:

```bash
$ ./sysprobe
[sysprobe] beacon active
[vm] persistence attempt: /etc/systemd/system/sysprobe.service (EACCES)
[vm] persistence attempt: /etc/cron.d/sysprobe (EACCES)
[vm] C2 beacon -> http://update-monitor.net/checkin
```

Four lines. None of them have any connection to the diagnostics strings recovered earlier. The CPU readouts, the memory stats, the `SysProbe` version banner , none of it appears. What executes instead is something the string scan gave no indication of whatsoever. 

## Decompiling The Binary

Loading `sysprobe` into Ghidra and running auto-analysis reveals an immediately suspicious picture. The function list is nearly empty. For a binary that just demonstrated C2 beaconing, persistence installation, and a hidden execution layer, Ghidra finds almost nothing  one meaningful function and a handful of standard library stubs.

```ghidra
undefined8 FUN_001010a0(int param_1, long param_2)
{
  char *__s1;
  int iVar1;
  
  puts("===========================================");
  __printf_chk(2,"  SysProbe Diagnostics Utility v%s\n","1.0.3");
  __printf_chk(2,"  Build: %s\n","20240315");
  puts("===========================================\n");
  if (1 < param_1) {
    __s1 = *(char **)(param_2 + 8);
    iVar1 = strcmp(__s1,"--version");
    if (iVar1 == 0) {
      __printf_chk(2,"SysProbe v%s (build %s)\n","1.0.3","20240315");
      return 0;
    }
    iVar1 = strcmp(__s1,"--help");
    if (iVar1 == 0) {
      puts("Usage: sysprobe [--version] [--help] [--full]");
      return 0;
    }
  }
  puts("[*] Running system diagnostics...");
  puts("[*] CPU Information");
  puts("    Architecture : x86_64");
  ...
  puts("[+] All diagnostics completed successfully.");
  return 0;
}
```

This is the entire visible logic of the binary. A version banner, two CLI flag handlers, and a series of hardcoded diagnostic readouts. No comparisons against external data, no cryptographic operations, no network calls, no file writes. Nothing that could produce the output the binary just generated at runtime.

The decompiled code and the runtime behaviour are completely irreconcilable  and that contradiction is the first real finding. The code Ghidra shows cannot be responsible for what the binary does. Which means there is an execution path Ghidra cannot see.

### Dynamic and Structural Analysis

With Ghidra showing only innocent diagnostics code and the binary clearly doing something else entirely at runtime, the next step is to interrogate the binary more directly.
### readelf — Entry Point


```bash
$ readelf -h sysprobe | grep Entry
  Entry point address: 0x804a55
```

This is immediately wrong. For a standard PIE executable, the entry point lives inside the `.text` section  somewhere around `0x1080` in this binary. `0x804a55` is not in any known section. It is orders of magnitude beyond where `.text` ends. Something has redirected execution to an address that has no business being an entry point.
### readelf — Program Headers

````bash
$ readelf -l sysprobe

  Type           Offset     VirtAddr           Flags
  LOAD           0x000000   0x000000000000      R
  LOAD           0x001000   0x000000000001000   R E
  LOAD           0x002000   0x000000000002000   R
  LOAD           0x002da8   0x000000000003da8   RW
  LOAD           0x004000   0x000000000804000   RWX   <--
  NULL           0x000000   0x000000000000000
  GNU_PROPERTY   ...
  GNU_EH_FRAME   ...
  GNU_STACK      ...
  GNU_RELRO      ...
````

Three anomalies in one output.

First  `PT_LOAD` at index 7 carries `RWX` permissions. A segment that is simultaneously readable, writable, and executable has no legitimate purpose. Normal code segments are `R-X`. Normal data segments are `RW-`. A region that is all three is a classic injection staging area.

Second  that same segment maps to virtual address `0x804000`, far outside the normal layout, at file offset `0x4000`. It is appended to the binary  not part of the original compilation. And the entry point `0x804a55` lands directly inside it.

Third  `PT_NULL` at index 8. A null segment in the middle of the header table is a placeholder. Every freshly compiled ELF carries a `PT_NOTE` segment here containing the build-id and ABI tag. Its replacement with `PT_NULL` is a tell  `PT_NOTE` was overwritten to make room for the injected `PT_LOAD`, and the null entry is what was left behind.

#### Conclusion

The evidence now points in one direction. The `PT_NOTE` segment present in every legitimately compiled ELF  has been overwritten with a new `PT_LOAD` region carrying executable code. The binary's entry point has been silently redirected into that region. The host binary and its diagnostics function are a decoy. Execution begins somewhere the standard toolchain cannot see, in a segment that was injected after compilation.

This is PT_NOTE parasitic injection. The real question is what that injected region contains and what it does before handing control back.

### Investigating the Injected Segment

With the entry point confirmed at `0x804a55` inside an injected RWX segment, the next step is to follow execution there directly. The fastest way is GDB.

```bash
$ gdb ./sysprobe
(gdb) break *0x804a55
(gdb) run
```

Execution stops at the injected entry point  inside a region that has no section name, no symbol, and no place in the binary's original layout. Stepping through reveals the loader stub doing three things in sequence: allocating a fresh anonymous RWX memory region via `mmap`, decompressing something into it, then jumping into it.

````bash
(gdb) info proc mappings
```
```
Start Addr         End Addr           Size    Offset  Perms
0x555555554000     0x555555555000     0x1000  0x0     r--p   sysprobe
0x555555555000     0x555555556000     0x1000  0x1000  r-xp   sysprobe
0x555555558000     0x55555555b000     0x3000  0x4000  rwxp   sysprobe
0x7ffff7fc0000     0x7ffff7fc3000     0x3000  0x0     rwxp   <anonymous>  <--
0x7ffff7fc3000     0x7ffff7fc5000     0x2000  0x0     rw-p   <anonymous>
````

A new anonymous `rwxp` region has appeared at `0x7ffff7fc0000` one that did not exist before the stub ran. This is where the decompressed payload now lives. Dumping it:

```bash
(gdb) dump binary memory payload.bin 0x7ffff7fc0000 0x7ffff7fc3000
$ file payload.bin
payload.bin: ELF 64-bit LSB shared object, x86-64, not stripped
```

A complete ELF shared object  extracted entirely from memory, never present on disk, invisible to every static analysis tool used so far. This is what is producing the C2 output. The host binary's only job was to get this here.
# Solution 

## Analyzing payload.bin in Ghidra

Loading `payload.bin` into Ghidra at base address `0x0` and running auto-analysis reveals a clean symbol table — this shared object is not stripped. The function list is immediately navigable:

```
payload_entry   @ 0x00000380
vm_run          @ 0x00000520
cos             @ 0x000011d0
sin             @ 0x000011b0
sqrt            @ 0x000011a0
mmap            @ 0x00001210
memset          @ 0x000010a0
memcpy          @ 0x000010f0
```

Opening `payload_entry` in the decompiler shows:

```c
undefined1 [16] payload_entry(void)
{
  long lVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined1 auVar4[16];

  syscall();
  lVar1 = 0;
  do {
    *(byte *)(lVar1 + 9) = (char)lVar1 + 0x4dU ^ (&_binary_vm_bytecode_bin_start)[lVar1];
    lVar1 = lVar1 + 1;
  } while (lVar1 != 0x3e);
  syscall();
  _DAT_00002001 = 0;
  puVar2 = (undefined8 *)&DAT_00000010;
  for (lVar1 = 0x3ff; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  _DAT_00000009 = 0x600c0b102a93214;
  _DAT_00000401 = 0;
  puVar2 = (undefined8 *)((long)&QB_REAL + 7);
  puVar3 = (undefined8 *)&DAT_00000010;
  for (lVar1 = 0x7f; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_00000429 = 0x28354a3b23312470;
  uRam0000000000000431 = 0x25343f3d4b3c3936;
  DAT_00000409 = '[';
  DAT_00000409_1._0_1_ = 's';
  DAT_00000409_1._1_1_ = 'y';
  ...
  uRam000000000000041b._5_1_ = 'e';
  uRam000000000000041b._6_1_ = '\n';
  vm_run(9, 0x3e, 9, 0x2000, 0xffffffffffffffff, 0);
  syscall();
  syscall();
}
```

The nostdlib compilation and inline syscalls produce messy output, but four operations are clearly visible.

The first `syscall()` is an `mmap` allocating a buffer for the bytecode  confirmed by cross-referencing the `mmap` symbol at `0x1210` and the inline syscall wrapper in `nosys_helpers.h`. The decode loop running `0x3e` (62) iterations XOR-decodes a blob referenced as `_binary_vm_bytecode_bin_start` into memory starting at address `9`. The second `syscall()` is another `mmap` allocating the VM heap. The large block of assignments that follows — zeroing memory, copying `QB_REAL`, writing hardcoded byte sequences  is building the VM heap from compile-time constants. The character-by-character assignments clearly spell out `[sysprobe] beacon active\n`. The packed hex values (`0x28354a3b23312470` etc.) are the XOR-encrypted C2 response being placed into the heap.

The function closes with `vm_run(9, 0x3e, 9, 0x2000, ...)` passing the decoded bytecode pointer (`9`), its length (`0x3e` = 62 bytes), the heap pointer, and heap size.
## The Bytecode Blob

The symbol `_binary_vm_bytecode_bin_start` in `.data` at offset `0x1ca0` points to the obfuscated bytecode embedded into the shared object via the linker's binary embedding mechanism. In Ghidra's listing view, navigating to `0x1ca0` shows 62 bytes of data:

```
04 06 07 0c 07 0b 05 0f 03 0a 0e 12 10 12 1c d8
01 16 37 90 18 1a 09 1c 3c e3 1e 20 5f 22 02 96
24 26 57 28 08 d8 2a 2c 77 2e 0e a2 30 32 3b 34
14 e3 36 38 22 3a 1a 83 3c 3f 3a 40 63 bd
```

This is the obfuscated bytecode. It is never executed directly `payload_entry` decodes it before passing it to `vm_run`.

## Deriving the XOR Key

The decode loop in `payload_entry`:

```c
lVar1 = 0;
do {
    *(byte *)(lVar1 + 9) = (char)lVar1 + 0x4dU ^ (&_binary_vm_bytecode_bin_start)[lVar1];
    lVar1 = lVar1 + 1;
} while (lVar1 != 0x3e);
```

Ghidra shows the constant `0x4d` as the key base. This comes from the inline XOR derivation in `payload_entry`  cross-referencing `QB_XOR_KEYS` in `.rodata` reveals six values: `0x3f, 0x15, 0x12, 0x32, 0x32, 0x3d`. Their XOR produces the base key:

```
0x3f ^ 0x15 ^ 0x12 ^ 0x32 ^ 0x32 ^ 0x3d = 0x05
```

The rolling key for byte at index `i` is therefore `(0x05 + i) & 0xFF`. Applying this byte by byte:

```
[00] obf=0x04 ^ key=0x05 = plain=0x01
[01] obf=0x06 ^ key=0x06 = plain=0x00
[02] obf=0x07 ^ key=0x07 = plain=0x00
[03] obf=0x0c ^ key=0x08 = plain=0x04
[04] obf=0x07 ^ key=0x09 = plain=0x0e
[05] obf=0x0b ^ key=0x0a = plain=0x01
...
[14] obf=0x1c ^ key=0x13 = plain=0x0f
[15] obf=0xd8 ^ key=0x14 = plain=0xcc
```

The 62-byte plain bytecode:

```
01 00 00 04 0e 01 0e 03 0e 04 01 02 01 00 0f cc
14 00 20 88 01 00 12 00 21 fd 01 00 7e 00 21 b2
01 00 70 00 21 f2 01 00 5a 00 21 92 01 00 08 00
21 d5 01 00 1b 00 21 bf 01 01 05 00 22 ff
```

## Reversing vm_run — Mapping the VM State

`vm_run` at `0x520` is a large switch statement dispatching on opcode bytes read from the bytecode pointer. Before mapping opcodes, the VM state layout must be recovered from the global `DAT_` symbols.

The first clue is in `vm_run`'s prologue:

```c
memset(&DAT_00000009, 0, 0x5260);
_DAT_00000031 = 0;
_DAT_00000039 = 0x1000;
_DAT_00000049 = param_1;
_DAT_00000051 = param_2;
```

`_DAT_00000031` is zeroed and is the value incremented as instructions are read  this is the **IP**. `_DAT_00000039` is initialised to `0x1000` and decremented on push / incremented on pop  this is the **SP**. `_DAT_00000049` receives the bytecode pointer  confirmed by the switch dispatch: `*(char *)(_DAT_00000049 + _DAT_00000031)`.
The register access pattern appears throughout every opcode handler:

```c
*(ulong *)((ulong)bVar15 * 8 + 9)
```

This is a register file stored at a fixed base address of `9`. Each register is an 8-byte slot. The five general-purpose registers map to:

```
R0 = *(ulong *)(0 * 8 + 9)  →  _DAT_00000009  (addr 0x09)
R1 = *(ulong *)(1 * 8 + 9)  →  _DAT_00000011  (addr 0x11)
R2 = *(ulong *)(2 * 8 + 9)  →  _DAT_00000019  (addr 0x19)
R3 = *(ulong *)(3 * 8 + 9)  →  _DAT_00000021  (addr 0x21)
R4 = *(ulong *)(4 * 8 + 9)  →  _DAT_00000029  (addr 0x29)
```

The remaining state variables identified from cross-referencing usage across the switch cases:

```
_DAT_00000031  IP    — instruction pointer
_DAT_00000039  SP    — stack pointer (init 0x1000, grows down)
_DAT_00000041  FLAGS — bit 0: extended decode mode
_DAT_00000049  bytecode pointer
_DAT_00000051  bytecode length
DAT_00001059   vm_heap base  (heap copied here by payload_entry)
DAT_00003059   q_real[]      (quantum state vector, real parts)
DAT_00004051   q_imag[]      (quantum state vector, imaginary parts)
_DAT_00005059  q_dim         (quantum state dimension)
DAT_0000505d   flag_bits[]   (QCOL output)
_DAT_0000525d  flag_bit_count
_DAT_00005261  halted flag
```

The stack occupies `0x59` to `0x1059` (4096 bytes), immediately before `vm_heap` at `0x1059`. The `q_real[]` array at `0x3059` and `q_imag[]` at `0x4051` are each 512 doubles (4096 bytes). In the `QMAT` handler, `pdVar11[0x200]` accesses the imaginary part: `0x200` doubles × 8 bytes = 4096 bytes ahead  exactly the offset from `q_real[]` to `q_imag[]`.
## Mapping Opcodes to Mnemonics

With the register layout and state variables understood, each `case` in the switch maps to a named operation by reading what it does. The process for each opcode:

- Read the operand bytes to understand the instruction encoding
- Identify which registers or memory locations are read and written
- Identify the arithmetic/logical operation being performed
- Assign a mnemonic

Walking through the key cases from the decompilation:

**`case '\x01'` — MOV**

```c
bVar15 = *(byte *)(_DAT_00000049 + 1 + _DAT_00000031);  // register index
uVar16 = *(ushort *)(_DAT_00000049 + 2 + _DAT_00000031); // 16-bit immediate
...
*(ulong *)((ulong)bVar15 * 8 + 9) = (ulong)uVar16;      // R[bVar15] = imm
```

Reads a register index and a 16-bit immediate, writes the immediate into that register. Encoding: `opcode(1) + reg(1) + imm_lo(1) + imm_hi(1)` = 4 bytes. Named **MOV Rd, imm16**.

**`case '\x02'` — ADD**

```c
uVar9 = *(long *)((ulong)bVar14 * 8 + 9) + *(long *)((ulong)bVar15 * 8 + 9) + uVar13;
*(ulong *)((ulong)bVar15 * 8 + 9) = uVar9;
```

Adds two registers and stores the result. Named **ADD Rd, Rs**.

**`case '\x04'` — XOR**

```c
uVar9 = *(ulong *)((ulong)bVar15 * 8 + 9) ^ *(ulong *)((ulong)bVar14 * 8 + 9) ^ uVar13;
*(ulong *)((ulong)bVar15 * 8 + 9) = uVar9;
```

XORs two registers. Named **XOR Rd, Rs**.

**`case '\x0f'` — FAULT**

```c
_DAT_00000031 = uVar1;
uVar1 = _DAT_00000031 + _DAT_00000019;  // IP += R2
uVar17 = _DAT_00000041 ^ 1;             // FLAGS ^= 1
```

Advances IP by R2 and flips FLAGS bit 0. No arithmetic, no register write. Named **FAULT** — it is an anti-disassembly trap, not a real arithmetic opcode.

**`case '\x14'` — SETF**

```c
uVar17 = (ulong)*(byte *)(_DAT_00000049 + 1 + _DAT_00000031);  // FLAGS = imm8
```

Directly sets the FLAGS register from an immediate byte. Named **SETF imm8**.

**`case '\x0e'` — SYSCALL**

```c
cVar7 = *(char *)(_DAT_00000049 + 1 + _DAT_00000031);
if (cVar7 == '\x01') { ... write ... }      // PRINT
else if (cVar7 == '\x03') { ... syscalls... } // PERSIST
else if (cVar7 == '\x04') { ... c2 ... }    // C2
```

Dispatches to internal VM routines based on a sub-opcode byte. Named **SYSCALL n**.

The full opcode table recovered from `vm_run`:

|Opcode|Mnemonic|Encoding|
|---|---|---|
|`0x00`|NOP|1 byte|
|`0x01`|MOV Rd, imm|4 bytes|
|`0x02`|ADD Rd, Rs|3 bytes|
|`0x03`|SUB Rd, Rs|3 bytes|
|`0x04`|XOR Rd, Rs|3 bytes|
|`0x05`|AND Rd, imm|3 bytes|
|`0x06`|PUSH Rs|2 bytes|
|`0x07`|POP Rd|2 bytes|
|`0x08`|JMP / JCC|2 bytes|
|`0x09`|JZ offset|2 bytes|
|`0x0A`|CALL offset|2 bytes|
|`0x0B`|RET|1 byte|
|`0x0C`|LOAD Rd, imm|4 bytes|
|`0x0D`|STORE imm, Rs|4 bytes|
|`0x0E`|SYSCALL n|2 bytes|
|`0x0F`|FAULT|1 byte|
|`0x10`|MUL Rd, Rs|3 bytes|
|`0x11`|SHR / ROL|3–4 bytes|
|`0x12`|SHL / ROR|3–4 bytes|
|`0x13`|CMP Rd, Rs|3 bytes|
|`0x14`|SETF imm8|2 bytes|
|`0x20`|QINIT|2 bytes|
|`0x21`|QMAT|2 bytes|
|`0x22`|QCOL|1 byte|
|`0xFF`|HALT|1 byte|

## The FLAGS Extended Decode Mode

A critical detail visible throughout the entire switch: almost every case begins with:

```c
uVar13 = (ulong)((uint)_DAT_00000041 & 1);
```

and then:

```c
if (uVar13 != 0) {
    // consume an extra byte, behave differently
}
```

FLAGS bit 0 controls an **extended decode mode**. When set, most opcodes consume one additional byte and modify their behaviour  for example, `MOV` XORs the high byte of the immediate, `ADD` includes an extra carry value. This is why `FAULT` flips FLAGS: the `0xCC` byte placed after it would cause the next instruction to be decoded differently if FLAGS remained set. `SETF 0x00` at `0x0010` clears FLAGS, restoring normal decode mode before the quantum opcodes execute.

## Disassembling the Plain Bytecode

With the full opcode table and instruction encodings mapped, the 62-byte plain bytecode disassembles as:

```
Offset  Bytes            Instruction
------  ---------------  ------------------------------------
0000    01 00 00 04      MOV  R0, 0x0400     ← heap offset for beacon string
0004    0e 01            SYSCALL  1 (PRINT)
0006    0e 03            SYSCALL  3 (PERSIST)
0008    0e 04            SYSCALL  4 (C2)
000a    01 02 01 00      MOV  R2, 0x0001     ← skip distance for FAULT
000e    0f               FAULT               ← IP += R2, FLAGS ^= 1
000f    cc               dead byte (never executed)
0010    14 00            SETF  0x00          ← reset FLAGS to 0
0012    20 88            QINIT               ← load |ψₙ⟩ from heap, dim=256
0014    01 00 12 00      MOV  R0, 0x0012     ← rotation parameter for round 0
0018    21 fd            QMAT  0xfd          ← inverse rotation, round 0
001a    01 00 7e 00      MOV  R0, 0x007e     ← rotation parameter for round 1
001e    21 b2            QMAT  0xb2          ← inverse rotation, round 1
0020    01 00 70 00      MOV  R0, 0x0070     ← rotation parameter for round 2
0024    21 f2            QMAT  0xf2          ← inverse rotation, round 2
0026    01 00 5a 00      MOV  R0, 0x005a     ← rotation parameter for round 3
002a    21 92            QMAT  0x92          ← inverse rotation, round 3
002c    01 00 08 00      MOV  R0, 0x0008     ← rotation parameter for round 4
0030    21 d5            QMAT  0xd5          ← inverse rotation, round 4
0032    01 00 1b 00      MOV  R0, 0x001b     ← rotation parameter for round 5
0036    21 bf            QMAT  0xbf          ← inverse rotation, round 5
0038    01 01 05 00      MOV  R1, 0x0005     ← threshold = 5 / 1000.0 = 0.005
003c    22               QCOL               ← collapse state → flag bits
003d    ff               HALT
```

### The FAULT Anti-Disassembly Trick

At offset `0x000e`, opcode `0x0F` is `FAULT`. The handler from `vm_run`:

```c
case '\x0f':
    if (uVar13 != 0) {
        uVar1 = _DAT_00000031 + 2;  // extended mode: consume extra byte
    }
    _DAT_00000031 = uVar1;
    uVar1 = _DAT_00000031 + _DAT_00000019;  // IP += R2 (R2 = 1, skip 0xCC)
    uVar17 = _DAT_00000041 ^ 1;             // FLAGS ^= 1
    goto LAB_0010062a;
```

`_DAT_00000019` is R2 = `0x0001` (set by `MOV R2, 0x0001` at `0x000a`). So FAULT advances IP by 1, jumping cleanly over the `0xCC` byte at `0x000f`, and toggles FLAGS to 1. The `0xCC` is pure dead padding  it is never reached. Any linear disassembler decodes it as `INT3` and loses the instruction stream. `SETF 0x00` at `0x0010` immediately resets FLAGS back to 0.

## Understanding the Quantum Opcodes

### QINIT — Loading the State Vector from the Heap

`case ' '` (opcode `0x20`) in `vm_run`:

```c
case ' ':
    bVar15 = *(byte *)(_DAT_00000049 + 1 + _DAT_00000031);
    if ((bVar15 & 0x7f) - 1 < 9) {
        uVar20 = 1 << (bVar15 & 0x1f);   // dim = 1 << log2
    }
    _DAT_00005059 = uVar20;               // store q_dim
    ...
    if ((char)bVar15 < '\0') {            // bit7 set = heap-load mode
        do {
            *(double *)(&DAT_00003059 + lVar10 * 8) =
                (double)*(int *)(&DAT_00001059 + lVar10 * 4) * 9.313225746154785e-10;
            lVar10 = lVar10 + 1;
        } while ((int)lVar10 < (int)uVar20);
    }
```

Operand `0x88`: `bit7=1` → heap-load mode, `log2 = 0x08` → `dim = 256`. The VM reads 256 signed 32-bit integers from `vm_heap` (`DAT_00001059` + index × 4) and multiplies each by `9.313225746154785e-10` = `1 / (1 << 30)`. This is **Q1.30 fixed-point** conversion: a signed 32-bit integer where `1.0` is represented as `1 << 30 = 1073741824`. The converted doubles are stored in `q_real[]` at `DAT_00003059`. Imaginary parts (`DAT_00004051`) are left at zero.

The source of these Q1.30 integers is `QB_REAL`  a 256-element array in `payload.bin`'s `.rodata` at offset `0x1260`. In `payload_entry`, the copy loop `puVar2 = (undefined8 *)((long)&QB_REAL + 7)` copies it into the heap. The `+7` is an alignment offset  `QB_REAL` is 7 bytes into the symbol block. First four values after conversion:

```
heap[0]:  0xfd3a71b9  →  -0.04330785
heap[1]:  0xf9c2c08a  →  -0.09748827
heap[2]:  0xff039b74  →  -0.01540483
heap[3]:  0x031da936  →   0.04868536
```

This is **not** the flag. It is the flag after six forward rotations applied at build time and stored here. `QMAT` will undo those rotations.
### QMAT — Decoding the Operand and Computing the Rotation

`case '!'` (opcode `0x21`) in `vm_run`:

```c
case '!':
    bVar15 = *(byte *)(_DAT_00000049 + 1 + _DAT_00000031);
    dVar22 = (double)(DAT_00000009 ^ bVar15 & 0x7f) * 0.00390625 * 3.141592653589793;
    if ((char)bVar15 < '\0') {
        dVar22 = -dVar22;
    }
```

`DAT_00000009` is **R0**  the first register, at base address `9`. The angle formula:

```
θ = (R0 ^ (operand & 0x7F)) × (1/256) × π
```

`0.00390625` = `1/256`. When `bit7` of the operand is set (`(char)bVar15 < '\0'`), the angle is negated the **inverse flag**. The operand byte therefore encodes three fields:

```
bit 7    : inverse flag  — 1 = apply -θ (undo forward rotation)
bit 6    : layer flag    — selects which index pairs are rotated
bits 0–5 : mutation key  — mk, XORed with R0 to produce the rotation value
```

The `R0` value for each round comes from the **preceding `MOV R0` instruction** in the bytecode  not from the `QMAT` operand itself. This is the critical point: each `QMAT` is a two-instruction pair. The player must read the `MOV R0` immediately before each `QMAT` to get the rotation parameter.

After computing the angle, `sincos` decomposes it:

```c
sincos(dVar22, &local_30, &local_38);   // local_30 = sin(θ), local_38 = cos(θ)
```

The rotation is applied to adjacent element pairs in `q_real[]` and `q_imag[]`:

```c
for (uVar9 = 1; (int)uVar9 < (int)uVar20; uVar9 = (ulong)((int)uVar9 + 2)) {
    dVar22    = *pdVar11;           // q_real[i]
    dVar6     = pdVar11[0x200];     // q_imag[i]  (0x200 doubles = 4096 bytes ahead)
    *pdVar11  = local_38 * dVar22 - local_30 * pdVar11[1];    // cos·r₀ - sin·r₁
    pdVar11[1] = dVar22 * local_30 + pdVar11[1] * local_38;   // sin·r₀ + cos·r₁
    pdVar11[0x200]  = local_38 * dVar6 - local_30 * pdVar11[0x201];
    pdVar11[0x201]  = dVar6  * local_30 + pdVar11[0x201] * local_38;
    pdVar11 = pdVar11 + 2;
}
```

The loop starts at `uVar9 = 1` and steps by 2. This is the **odd pair layer**: pairs `(1,2), (3,4), (5,6)...`  confirmed by bit6 of the operand. When bit6 is `0` (even layer), the loop would start at index `0`: pairs `(0,1), (2,3), (4,5)...` Even-layer and odd-layer rounds share element 1 (in even pair `(0,1)` and odd pair `(1,2)`), making the six rounds non-commutative  order matters and cannot be changed.

### Decoding All Six QMAT Rounds from the Bytecode

Each round is a `MOV R0` (4 bytes) followed by `QMAT` (2 bytes). Reading directly from the plain bytecode:

**Round 0** — bytes at `0x14`–`0x19`:

```
01 00 12 00  →  MOV opcode=0x01, reg=R0, imm = 0x12 | (0x00 << 8) = 0x12
21 fd        →  QMAT operand=0xfd = 11111101b
               bit7=1 (inv)  bit6=1 (odd layer)  bits0-5=0x3d (mk)
               θ = (0x12 ^ 0x3d) × (1/256) × π = 47 × 0.003906 × π = 0.5768 rad
               applied as -0.5768 (inverse)
```

**Round 1** — bytes at `0x1a`–`0x1f`:

```
01 00 7e 00  →  MOV R0, 0x7e
21 b2        →  QMAT operand=0xb2 = 10110010b
               bit7=1 (inv)  bit6=0 (even layer)  bits0-5=0x32 (mk)
               θ = (0x7e ^ 0x32) × (1/256) × π = 76 × 0.003906 × π = 0.9327 rad
               applied as -0.9327
```

**Round 2** — bytes at `0x20`–`0x25`:

```
01 00 70 00  →  MOV R0, 0x70
21 f2        →  QMAT operand=0xf2 = 11110010b
               bit7=1 (inv)  bit6=1 (odd layer)  bits0-5=0x32 (mk)
               θ = (0x70 ^ 0x32) × (1/256) × π = 66 × 0.003906 × π = 0.8099 rad
               applied as -0.8099
```

**Round 3** — bytes at `0x26`–`0x2b`:

```
01 00 5a 00  →  MOV R0, 0x5a
21 92        →  QMAT operand=0x92 = 10010010b
               bit7=1 (inv)  bit6=0 (even layer)  bits0-5=0x12 (mk)
               θ = (0x5a ^ 0x12) × (1/256) × π = 72 × 0.003906 × π = 0.8836 rad
               applied as -0.8836
```

**Round 4** — bytes at `0x2c`–`0x31`:

```
01 00 08 00  →  MOV R0, 0x08
21 d5        →  QMAT operand=0xd5 = 11010101b
               bit7=1 (inv)  bit6=1 (odd layer)  bits0-5=0x15 (mk)
               θ = (0x08 ^ 0x15) × (1/256) × π = 29 × 0.003906 × π = 0.3559 rad
               applied as -0.3559
```

**Round 5** — bytes at `0x32`–`0x37`:

```
01 00 1b 00  →  MOV R0, 0x1b
21 bf        →  QMAT operand=0xbf = 10111111b
               bit7=1 (inv)  bit6=0 (even layer)  bits0-5=0x3f (mk)
               θ = (0x1b ^ 0x3f) × (1/256) × π = 36 × 0.003906 × π = 0.4418 rad
               applied as -0.4418
```

Summary table:

|Round|Bytecode offset|R0 val|Operand|Layer|mk|θ applied|
|---|---|---|---|---|---|---|
|0|`0x14`–`0x19`|`0x12`|`0xfd`|odd|`0x3d`|−0.5768 r|
|1|`0x1a`–`0x1f`|`0x7e`|`0xb2`|even|`0x32`|−0.9327 r|
|2|`0x20`–`0x25`|`0x70`|`0xf2`|odd|`0x32`|−0.8099 r|
|3|`0x26`–`0x2b`|`0x5a`|`0x92`|even|`0x12`|−0.8836 r|
|4|`0x2c`–`0x31`|`0x08`|`0xd5`|odd|`0x15`|−0.3559 r|
|5|`0x32`–`0x37`|`0x1b`|`0xbf`|even|`0x3f`|−0.4418 r|

### QCOL — Tracing the Threshold and Collapsing to Bits

`case '"'` (opcode `0x22`) in `vm_run`:

```c
LAB_00100699:
    Var8 = (unkuint9)_DAT_00000011;    // R1
    ...
    while ((int)lVar10 < (int)uVar20) {
        dVar22 = *(double *)(lVar10 * 8 + 0x3051);   // q_real[i]
        _DAT_0000525d = _DAT_0000525d + 1;
        (&DAT_0000505d)[uVar9] =
            (double)(unkint9)Var8 / 1000.0 <
            dVar22 * dVar22 +
            *(double *)(&DAT_00004051 + lVar10 * 8) *
            *(double *)(&DAT_00004051 + lVar10 * 8);
    }
```

`_DAT_00000011` is **R1**. Tracing back through the bytecode: `MOV R1, 0x0005` at offset `0x0038`:

```
0038: 01 01 05 00
      opcode=0x01 (MOV)
      reg=0x01    (R1)
      imm = 0x05 | (0x00 << 8) = 5
```

So `Var8 = R1 = 5`. The threshold = `5 / 1000.0 = 0.005`.

For each element `i`, QCOL computes `q_real[i]² + q_imag[i]²` (probability amplitude `|ψ[i]|²`) and compares it to `0.005`. The result — `1` if above threshold, `0` otherwise  is written to `flag_bits[]` at `DAT_0000505d`. Every 8 consecutive bits, MSB first, form one byte of the flag.
## Building the Solver

All parameters are now fully traced from the Ghidra decompilation. The solver reproduces the exact VM computation externally.

**Step 1 — Extract the state vector.**

`QB_REAL` is at offset `0x1260` in `payload.bin`'s `.rodata`. `payload_entry` copies it into `vm_heap[0..1023]` via:

```c
puVar2 = (undefined8 *)((long)&QB_REAL + 7);  // +7 = alignment skip
```

Extract directly from the payload:

```python
import struct, math

with open("payload.bin", "rb") as f:
    f.seek(0x1260 + 7)           # QB_REAL in .rodata + 7-byte alignment offset
    raw = f.read(256 * 4)        # 256 × 4 bytes = 1024 bytes

q_real = []
for i in range(256):
    iv = struct.unpack_from("<i", raw, i * 4)[0]       # signed int32 little-endian
    q_real.append(iv * 9.313225746154785e-10)           # Q1.30: × 1/(1<<30)

q_imag = [0.0] * 256                                    # imaginary parts start at zero
```

**Step 2 — Apply the six inverse QMAT rotations.**

Each round's parameters come directly from reading the decoded bytecode pairs. The `MOV R0` provides `R0`; the `QMAT` operand byte provides `inv`, `odd_pair`, and `mk`. The angle formula and rotation logic come verbatim from `case '!'` in `vm_run`:

```python
def apply_qmat(q_real, q_imag, theta, odd_pair):
    # From vm_run case '!': sincos(theta, &sin_out, &cos_out)
    # cos stored in local_38, sin stored in local_30
    # rotation: r0' = cos·r0 - sin·r1
    #           r1' = sin·r0 + cos·r1
    c, s = math.cos(theta), math.sin(theta)
    start = 1 if odd_pair else 0    # bit6: loop at uVar9=1 (odd) or uVar9=0 (even)
    for i in range(start, 255, 2):
        r0, i0 = q_real[i],   q_imag[i]
        r1, i1 = q_real[i+1], q_imag[i+1]
        q_real[i]   = c*r0 - s*r1;  q_imag[i]   = c*i0 - s*i1
        q_real[i+1] = s*r0 + c*r1;  q_imag[i+1] = s*i0 + c*i1

# All six rounds: (R0_value, QMAT_operand_byte)
# R0 from MOV at bytecode offsets 0x14, 0x1a, 0x20, 0x26, 0x2c, 0x32
# operand from QMAT at bytecode offsets 0x18, 0x1e, 0x24, 0x2a, 0x30, 0x36
rounds = [
    (0x12, 0xfd),   # offset 0x14/0x18: R0=0x12 op=0xfd → odd  mk=0x3d θ=−0.5768
    (0x7e, 0xb2),   # offset 0x1a/0x1e: R0=0x7e op=0xb2 → even mk=0x32 θ=−0.9327
    (0x70, 0xf2),   # offset 0x20/0x24: R0=0x70 op=0xf2 → odd  mk=0x32 θ=−0.8099
    (0x5a, 0x92),   # offset 0x26/0x2a: R0=0x5a op=0x92 → even mk=0x12 θ=−0.8836
    (0x08, 0xd5),   # offset 0x2c/0x30: R0=0x08 op=0xd5 → odd  mk=0x15 θ=−0.3559
    (0x1b, 0xbf),   # offset 0x32/0x36: R0=0x1b op=0xbf → even mk=0x3f θ=−0.4418
]

for r0_val, operand in rounds:
    inv      = bool(operand & 0x80)             # bit7: negate angle
    odd_pair = bool(operand & 0x40)             # bit6: loop starts at 1 not 0
    mk       = operand & 0x3F                   # bits0-5: mutation key
    # from vm_run: (double)(R0 ^ (operand & 0x7F)) * 0.00390625 * pi
    theta    = (r0_val ^ mk) * 0.00390625 * math.pi
    if inv:
        theta = -theta                          # inverse: negate
    apply_qmat(q_real, q_imag, theta, odd_pair)
```

**Step 3 — Apply QCOL.**

Threshold from `MOV R1, 0x0005` at bytecode offset `0x0038`: `R1 = 5` → `5 / 1000.0 = 0.005`.
From `vm_run` QCOL: `(double)R1 / 1000.0 < q_real[i]² + q_imag[i]²`

```python
# R1 = 5 from MOV R1, 0x0005 at bytecode offset 0x0038
threshold = 5 / 1000.0    # _DAT_00000011 / 1000.0 in vm_run QCOL handler

bits = []
for i in range(256):
    p = q_real[i]**2 + q_imag[i]**2     # probability amplitude |ψ[i]|²
    bits.append(1 if p > threshold else 0)
```

**Step 4 — Pack bits into bytes and recover the flag.**

Eight bits per byte, MSB first, matching the `flag_bits[]` layout in `vm_run`:

```python
flag = []
for i in range(0, 248, 8):
    byte_val = sum(bits[i + k] << (7 - k) for k in range(8))
    if byte_val:
        flag.append(chr(byte_val))

print("".join(flag))
```

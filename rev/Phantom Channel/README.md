
![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /><font size='10'>phantom channel</font>

14<sup>th</sup> April 2026

Prepared By: `Kailash S`

Challenge Author(s): `Kailash S`

Difficulty: <font color='purple'>Very Easy</font>







## Synopsis

We are given a statically compiled Linux binary that, when executed, appears to do very little. It runs, produces minimal output, and exits cleanly. No obvious secrets. No strings worth noting. No library calls visible through standard tracing tools.

The binary is actually a fileless loader. It decompresses an embedded ELF binary entirely in memory using zlib, writes it into an anonymous file created by the `memfd_create` Linux syscall, and executes it directly from `/proc/self/fd/<N>` without ever touching the filesystem. The flag lives inside the embedded child binary, stored as a plain string in its read-only data section.

To recover the flag, we trace the process at the syscall level using `strace`, identify the `memfd_create` call, research how it works, locate the zlib-compressed blob inside the parent binary using its magic bytes, decompress it, and run `strings` on the result.
## Description

Biggie intercepted a binary floating around NIGHTFALL infrastructure with no author, no metadata, and no file-system footprint when it runs. The intel says it carries something inside, but nothing shows up on disk, nothing shows up in logs. Whatever it launches lives entirely in memory and vanishes the moment the process exits.

The only way in is to catch it mid-execution and figure out exactly what it is loading and where that payload came from.

## Skills Required

- Linux binary analysis basics
- Researching Skills
- Understanding of Linux process mechanics
## Skills Learned

- How `memfd_create` works and why it is used in fileless malware
- Identifying and extracting compressed blobs from binaries
- Syscall-level dynamic analysis using `strace`
- In-memory ELF execution via `/proc/self/fd`

## MITRE Mappings

- **`T1620 — Reflective Code Loading`** — The child ELF is loaded and executed entirely in memory. It is never written to disk at any point.
- **`T1036.005 — Masquerading: Match Legitimate Name or Location`** — The process renames itself to `kworker/u8:2` using `prctl` to blend in with legitimate Linux kernel worker threads.
- **`T1140 — Deobfuscate/Decode Files or Information`** — The embedded ELF is stored zlib-compressed inside the parent binary's read-only data section and decompressed at runtime before execution.
## Enumeration

### Analyzing the Given Files

On unzipping the challenge files, we are provided with one binary: `phantom_channel`.

Running `file` gives us:

```bash
$ file phantom_channel
phantom_channel: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
statically linked, BuildID[sha1]=..., stripped
```

A few things immediately stand out. The binary is **statically linked**, meaning it does not depend on any shared libraries. This matters because tools like `ltrace`, which intercept library function calls, will show us absolutely nothing useful here. It is also **stripped**, so we will not have function names in a decompiler. We are working blind from the start.

Running `strings` gives us something slightly more interesting:

```bash
$ strings phantom_channel
kworker/u8:2
volatile_channel
NIGHTFALL_SESSION=DEADLIGHT
/proc/self/fd/
```

A process name that looks like a Linux kernel thread, a string called `volatile_channel`, an environment variable that references DEADLIGHT, and a path inside `/proc`. None of these are a flag, but they are all clues. We will come back to each of them.

Running the binary:

```bash
$ ./phantom_channel
OPERATION DEADLIGHT
PHANTOM CHANNEL ACTIVE
COALITION ASSET DEPLOYED
```

It runs, prints some operational lines, and exits. Nothing useful on the surface. No prompt, no input expected, nothing that looks like a flag. Time to go deeper.

---

## Dynamic Analysis

### What is the binary actually doing at runtime?

Since `ltrace` is useless against a static binary and the output gives us nothing, the next logical move is `strace`. `strace` works at the kernel level. It intercepts every system call the process makes, regardless of how the binary was compiled or linked. Nothing hides from it.

```bash
$ strace ./phantom_channel
execve("./phantom_channel", ["./phantom_channel"], 0x7fff...) = 0
prctl(PR_SET_NAME, "kworker/u8:2")     = 0
memfd_create("volatile_channel", MFD_CLOEXEC) = 3
write(3, "\x78\xda\xec\xbd...", 14432) = 14432
execve("/proc/self/fd/3", ["kworker/u8:2"], ["NIGHTFALL_SESSION=DEADLIGHT"]) = 0
```

This is the entire picture in five lines.

The binary starts, immediately renames its own process to `kworker/u8:2` using `prctl`. That is why `strings` showed that name. It is disguising itself as a kernel worker thread.

Then it calls something called `memfd_create`. Then it writes a large chunk of data into file descriptor 3. Then it executes `/proc/self/fd/3`, which is that file descriptor, as a brand new process, passing `NIGHTFALL_SESSION=DEADLIGHT` as an environment variable.

The write is 14432 bytes of data. The first two bytes are `\x78\xda`. We will come back to that.

### What is memfd_create?

This is the key question. If we have never seen this syscall before, now is the time to look it up.

From the Linux man pages:

 `memfd_create` creates an anonymous file and returns a file descriptor that refers to it. The file behaves like a regular file, but it lives in RAM and has no path in the filesystem.

In other words, it creates a file that exists only in memory. It has no name visible in the filesystem. No path in `/tmp`, no path anywhere. The only way to reference it is through the `/proc/self/fd/<N>` symlink that the kernel automatically provides for every open file descriptor.

So what the binary is doing is:

1. Creating an invisible RAM-backed file (`memfd_create`)
2. Writing a compressed binary into it (`write`)
3. Executing that file directly from the `/proc` path (`execve /proc/self/fd/3`)

The child process runs entirely from memory. The moment it exits, the file descriptor closes and the file is gone. Nothing lands on disk. This is a real technique used in Linux malware — the payload leaves no filesystem trace.

The `strings` output from the parent binary now makes complete sense. `kworker/u8:2` is the disguise name. `volatile_channel` is the name passed to `memfd_create` (used internally, not visible as a filesystem path). `/proc/self/fd/` is where the in-memory file gets executed from. `NIGHTFALL_SESSION=DEADLIGHT` is the environment variable passed to the child at launch.

## Extracting the Embedded Payload

### Where is the child binary hiding?

The `strace` output showed the binary writing `\x78\xda...` into the memfd before executing it. Those two bytes are not random  `0x78 0xDA` is the **zlib magic header**. It indicates a zlib-compressed stream at maximum compression level.

The child ELF is embedded compressed inside the parent binary, stored in its read-only data section. At runtime, the parent decompresses it and writes it into the anonymous memory file. That is why `strings` on the parent binary found nothing useful — the embedded ELF is not plain text, it is compressed data.

To extract it, we scan the parent binary for those two magic bytes, pull out everything from that offset to the end of the file, try to decompress it with zlib, and see what comes out.

We can verify this with `xxd` before writing the script:

```bash
$ xxd phantom_channel | grep "78da"
0001f340: 78da ecbd 0978 1445 ...
```

There it is. The compressed blob starts at offset `0x1f340`. Now we can write the extractor.

### The Extraction Script

```python
#!/usr/bin/env python3
import zlib
import sys

ZLIB_MAGIC = bytes([0x78, 0xda])

with open("phantom_channel", "rb") as f:
    data = f.read()
```

We read the entire binary into memory. We are going to scan it manually for the zlib magic bytes.

```python
offset = data.find(ZLIB_MAGIC)
if offset == -1:
    print("[-] No zlib magic found")
    sys.exit(1)

print(f"[+] Found zlib magic at offset: {hex(offset)}")
```

We search for the two-byte sequence `0x78 0xDA`. If it is not there, we exit early. In our case it will be found at the offset we confirmed with `xxd`.

```python
compressed_blob = data[offset:]
decompressed = zlib.decompress(compressed_blob)

print(f"[+] Decompressed {len(compressed_blob)} bytes -> {len(decompressed)} bytes")

with open("child_elf.bin", "wb") as f:
    f.write(decompressed)

print("[+] Written to child_elf.bin")
```

We slice from that offset to the end of the file and pass it to `zlib.decompress`. Python's `zlib` module handles RFC 1950 streams natively. The result is the raw child ELF binary. We write it to disk so we can inspect it.

```python
ELF_MAGIC = b'\x7fELF'
if decompressed[:4] == ELF_MAGIC:
    print("[+] Valid ELF header confirmed")
else:
    print("[-] Not a valid ELF")
    sys.exit(1)
```

We verify the first four bytes of the decompressed data match the ELF magic (`\x7fELF`). This confirms we decompressed the right thing and the blob is exactly what we expected — a Linux executable.

---

## Getting the Flag

Once `child_elf.bin` is on disk, we run `strings` against it:

The flag is stored as a plain string in the child ELF's read-only data section. It was never visible in the parent binary because the parent stores the child compressed. It was never written to disk at runtime because `memfd_create` keeps everything in memory. The only way to find it is to either catch the write at runtime with `strace` and reconstruct the stream, or do what we did here: locate the compressed blob statically, decompress it, and inspect the result.

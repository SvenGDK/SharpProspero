---
title: Kernel access
parent: Payloads
nav_order: 5
---

# Kernel access

A payload can read and write kernel structures through the CRT-emitted accessors backed by a single
pipe primitive the loader hands the payload at start-up. Managed code drives the pipe through
`SharpProspero.Payload.PayloadKernel` and `SharpProspero.Payload.PayloadKernelIo`. This page covers
the pipe, the accessors, the per-firmware data table, and the two calling patterns.

## Why a payload can

An application module is a user-space process the loader confined to its own sandbox. A payload
runs inside a host process whose credential set the loader chose — a host with enough authority to
call the pipe primitive back into kernel memory. That is how kernel reads and writes reach through.

## The pipe primitive

The loader constructs a pipe pair, sets one end up with a specific socket-option layout, and hands
the payload the two file descriptors along with a scratch buffer address. The CRT reads these once
from `payload_args` and stores them in BSS:

| Slot | What it holds |
|---|---|
| `pipe_addr` | The scratch buffer's virtual address. |
| `rw_pipe0` / `rw_pipe1` | The pipe pair's file descriptors. |
| `rw_pair0` / `rw_pair1` | The associated overlap pair the socket-option chain relies on. |
| `kdata_base` | The kernel data base, derived from the firmware version. |

Every kernel access afterwards is a single call chain that goes:

1. Write the desired kernel address into the scratch buffer.
2. Read from `rw_pipe0` — the socket-option overlap makes the kernel copy the bytes at that
   address into the scratch buffer.
3. Read the scratch buffer.

Writing is the mirror. The chain is small and stays entirely inside the CRT — managed code never
sees the pipe descriptors.

## The per-firmware data table

The kernel addresses (`allproc`, `text_base`, `bus_data_devices`, `targetid`, `utoken_flags`,
`vmspace_vm_pmap`, `kernel_rootvnode`) are firmware-specific. The CRT carries a per-firmware data
table indexed by the firmware major version. The version byte arrives in BCD form (`0x10` for
firmware 10), so the CRT converts it to a linear row index with a three-instruction sequence before
the lookup. `allproc` alone also looks at the minor version where it changes inside a major: 1.00–1.02 against
1.05 and later, and 13.00–13.20 against 13.40 and later.

Each row holds seven 32-bit column values — offsets from `kdata_base` — one per kernel symbol above.
`__sp_kernel_init` reads the row that matches the running firmware and writes the derived addresses
into BSS. Every kernel-accessing helper reads those BSS slots afterwards.

Adding a firmware means adding a row to the table. See
[Working with module offsets](offsets.md) for the offset-derivation workflow.

## The managed API

### `PayloadKernelIo` — raw read and write

```csharp
using SharpProspero.Payload;

PayloadArgs* args = PayloadEntryPoint.Args;
var io = new PayloadKernelIo(args);

// Read
ulong rootvnode = io.ReadU64(rootVnodeKaddr);
uint  targetId  = io.ReadU32(targetIdKaddr);

// Try-read (returns false on failure)
if (!io.TryReadU64(kaddr, out ulong value)) { /* handle */ }

// Buffer read
byte* buffer = stackalloc byte[64];
io.Read(kaddr, buffer, 64);

// Write
io.WriteU64(kaddr, 0xFFFFFFFFFFFFFFFF);
io.Write(kaddr, buffer, 64);
```

Every method dispatches through the CRT's pipe-primitive call chain. A single instance can be reused
for the lifetime of the payload.

### `PayloadKernel` — process-oriented helpers

`PayloadKernel` sits on top of `PayloadKernelIo` and adds process-oriented helpers:

```csharp
// Walk the process list
ulong proc = PayloadKernel.WalkAllprocForPid(io, targetPid);
ulong proc = PayloadKernel.FindProcessByComm("MyApp"u8);
ulong proc = PayloadKernel.FindProcessByTitleId(io, titleIdBytes, titleIdLen);

// Credential fields
PayloadKernel.RaisePrivileges(pid);
PayloadKernel.SetUcredAuthId(pid, 0x4800000000010003);
PayloadKernel.EscalateCredentials(io, proc);

// Filesystem view
ulong rootvnode = PayloadKernel.GetRootVnode();
PayloadKernel.RemoveJail(io, proc);
bool ok = PayloadKernel.JailbreakByPid(pid, rootvnode);
```

There are two calling patterns:

- **`io`-based** — the method takes a `PayloadKernelIo` and a proc pointer or address. Use this when
  the payload already has a `PayloadKernelIo` and knows the proc pointer.
- **`pid`-based** — the method takes only a `pid` and dispatches directly into the CRT-emitted
  accessors, which do the process walk and the field write in a single call. Use this for the
  credential and filesystem-view helpers.

The pid-based path is the preferred one for credential and filesystem-view operations, because it
lets the CRT hold the pipe primitive across the two-step read-then-write without a managed round
trip.

## The credential-write set

`PayloadKernel.EscalateCredentials(io, proc)` writes nine fields on the target process's ucred:
`uid = 0`, `ruid = 0`, `svuid = 0`, `rgid = 0`, `svgid = 0`, `prison = prison0`, `sceAuthId =
0xFFFF_FFFF_FFFF_FFFF`, and both slots of `sceCaps` set to `0xFFFF_FFFF_FFFF_FFFF`. Combined with
`RemoveJail(io, proc)` (which writes `fd_rdir` and `fd_jdir` to the root vnode), the target
process gains a full-authorization view.

`PayloadKernel.JailbreakByPid(pid, rootvnode)` is the daemon-shaped variant: eleven writes through
the CRT-emitted pid-based accessors that name the process on every write. The set is `uid = 0`,
`ruid = 0`, `svuid = 0`, `ngroups = 0`, `rgid = 0`, `sceAuthId = 0x4801000000000013`, both slots
of `sceCaps` filled with `0xFF` bytes, `sceAttr0 = 0x80`, `fd_rdir = rootvnode`, and
`fd_jdir = rootvnode`. It is the write the unjail daemon applies for every request. See
[Promoting a running application](payload-promotion.md) for the daemon.

## Failure modes

| Symptom | Cause |
|---|---|
| Every read returns zero | The pipe primitive was not initialised. `PayloadArgs* args` was null, or the loader did not populate the pipe descriptors. Check `sp:kernel:init:done` in the log. |
| A single read returns zero, others succeed | The target address is on a page the kernel does not have mapped, or the row in the per-firmware data table is wrong for the running firmware. Confirm the firmware major version. |
| The console page-faults immediately after a write | The target address is wrong, or the value written is not what the kernel expects for that field. Read the current value first with `ReadU64`, then compute the desired value with the read as a reference. |
| The write appears to succeed but the observable state does not change | The write went to the wrong process (a stale proc pointer) or the field is not the one the kernel reads. Re-walk the process list before every write, and read back the field to confirm. |

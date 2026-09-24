---
title: Hashing and checksums
parent: Data and utilities
grand_parent: Application Modules
nav_order: 6
---

# Hashing and checksums

The `SharpProspero.Security` namespace computes message digests and checksums with no system module, so a
build can verify a downloaded file against a published checksum, compare two files, or authenticate a
message with a shared secret. The digests share one small base type, `HashAlgorithm`, and offer the same
one-shot, file, and streaming forms. `Crc32` names its one-shot helpers `Compute` and `ComputeFileValue`
instead, and `Hmac` stands outside the base type with static helpers and a streaming form but no file
helper. Each returns the identical result on the device and in tests.

<details open markdown="block">
  <summary>On this page</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Choose an algorithm

Pick by what the check needs to catch. `Sha256` (or `Sha512` for a wider digest) guards against deliberate
tampering. `Md5` and `Sha1` exist to match sums that other tools still publish, not to resist an attacker.
`Crc32` is a fast integer check for accidental corruption. `Sha3` is the Keccak-based alternative to the
SHA-2 family for a build that requires it.

| Type | Digest | Use it for |
|------|--------|-----------|
| `Crc32` | 4 bytes | fast check against accidental corruption |
| `Md5` | 16 bytes | matching MD5 sums other tools publish |
| `Sha1` | 20 bytes | matching SHA-1 sums other tools publish |
| `Sha256` | 32 bytes | verifying a file against a published checksum |
| `Sha512` | 64 bytes | the same, with a wider digest |
| `Sha3` | 32, 48 or 64 bytes | the Keccak alternative, width set by `Sha3Variant` |
| `Hmac` | matches the chosen hash | proving a message was not changed without the key |

{: .warning }
> `Crc32`, `Md5` and `Sha1` do not resist a deliberate change. When the check has to survive an attacker,
> reach for `Sha256`, `Sha512`, `Sha3`, or a keyed `Hmac`.

## One-shot digests

The common case needs no object. Each hash exposes static helpers that take a block of bytes or a file
path and return either raw bytes or a lowercase hexadecimal string.

```csharp
using SharpProspero.Security;

string checksum = Sha256.HashFileHex("/app0/data.bin");   // lowercase hex
bool matches = checksum == published;

byte[] digest = Sha256.Hash(payload);                     // 32 raw bytes
string hex = Sha256.HashHex(payload);

uint crc = Crc32.ComputeFileValue("/app0/archive.bin");
```

`Sha1`, `Sha512` and `Md5` carry the same four helpers — `Hash`, `HashHex`, `HashFile`, `HashFileHex`.
The `HashFile*` forms read the file in fixed-size blocks, so a file of any size is hashed without holding
all of it in memory.

## Stream a digest in chunks

When the data arrives in pieces, construct the hash, feed it with `Update` as many times as needed in any
chunk sizes, then read the result. `Finish()` returns a new array, `FinishHex()` returns hexadecimal, and
`Finish(Span<byte>)` writes into a buffer you own.

```csharp
var sha = new Sha256();
sha.Update(header);
sha.Update(body);
string tag = sha.FinishHex();
```

```csharp
Span<byte> digest = stackalloc byte[32];      // Sha256.HashSize
var sha = new Sha256();
sha.Update(payload);
sha.Finish(digest);
```

{: .note }
> A hasher accumulates state and finalizes with a length pad, so a single instance computes one digest.
> Use a fresh object for each value rather than reusing one after `Finish`.

## The hashing base type

Every digest derives from `HashAlgorithm`, so code can accept any of them through the base. It defines
`HashSize`, `Update`, the two `Finish` overloads and `FinishHex`, and `ComputeFile(string)`, which
streams a file through the running digest and returns the result.

```csharp
static string Checksum(HashAlgorithm hash, ReadOnlySpan<byte> data)
{
    hash.Update(data);
    return hash.FinishHex();
}

string a = Checksum(new Sha256(), payload);
string b = Checksum(new Sha3(Sha3Variant.Bits512), payload);
```

`Md5`, `Sha1` and `Sha256` also share `BlockHashAlgorithm`, the machinery for digests that process data in
64-byte blocks and finish with a length pad. `Sha512` works in 128-byte blocks and `Sha3` absorbs a
variable-size rate, so both derive from `HashAlgorithm` directly. You rarely touch these two intermediate
types; they exist so the concrete hashes only supply their block transform.

## CRC-32

`Crc32` is the reflected variant that zip archives and PNG files use. Read the running value at any time
from `Value`, or take a one-shot checksum with `Compute` or `ComputeFileValue`.

```csharp
uint value = Crc32.Compute(payload);

var running = new Crc32();
running.Update(chunk1);
running.Update(chunk2);
uint total = running.Value;
```

## SHA-3

`Sha3` computes the Keccak sponge (FIPS 202). Pick the width with `Sha3Variant` — `Bits256`, `Bits384` or
`Bits512`, which name the digest size in bits. The default is SHA3-256.

```csharp
string sha3 = Sha3.HashHex(payload, Sha3Variant.Bits512);       // SHA3-512, 64 bytes
byte[] digest = Sha3.HashFile("/app0/data.bin", Sha3Variant.Bits256);

var streaming = new Sha3(Sha3Variant.Bits384);
streaming.Update(part1);
streaming.Update(part2);
byte[] result = streaming.Finish();
```

## Keyed digests (HMAC)

`Hmac` is a hash that also depends on a secret key, so a matching tag proves a message was not changed by
anyone without that key. The static helpers cover the common hashes:

```csharp
string tag = Hmac.Sha256Hex(key, message);   // also Sha512Hex, Sha1Hex, Md5Hex
bool authentic = tag == expected;
```

`Hmac.Sha256`, `Sha512`, `Sha1` and `Md5` take the same arguments and return the tag as raw bytes, for a
caller comparing against bytes from a protocol rather than against text.

For a keyed stream, construct one over any hash factory and its internal block size, then feed it with
`Update`:

```csharp
var mac = new Hmac(key, static () => new Sha256(), blockSize: 64);
mac.Update(part1);
mac.Update(part2);
byte[] tag = mac.Finish();
```

`HashSize` reports the tag width in bytes, the same as the underlying hash, and sizes a buffer for
`Finish(Span<byte>)`.

The `blockSize` argument is the underlying hash's internal block size in bytes, not its digest size. It is
64 for SHA-256, SHA-1 and MD5, and 128 for SHA-512. The static helpers pass the right value for you.

## Block sizes

The internal block size is the width of one transform step and the value `Hmac` needs. It differs from the
digest size and, for `Sha3`, changes with the chosen width (the sponge rate).

| Algorithm | Digest | Internal block |
|-----------|--------|----------------|
| MD5 | 16 bytes | 64 bytes |
| SHA-1 | 20 bytes | 64 bytes |
| SHA-256 | 32 bytes | 64 bytes |
| SHA-512 | 64 bytes | 128 bytes |
| SHA3-256 | 32 bytes | 136 bytes |
| SHA3-384 | 48 bytes | 104 bytes |
| SHA3-512 | 64 bytes | 72 bytes |

## Symmetric encryption

`Aes128` lives in the same namespace as the digests and implements the full 10-round Rijndael cipher
with pre-computed T-tables. Construct it with a 16-byte key, then encrypt or decrypt in place a block
at a time or a whole buffer in CBC or XTS mode. XTS needs a second `Aes128` for the tweak cipher, so
two keys and two instances go together; the 16-byte initialisation vector or tweak block is written
back through so a caller running a chain of buffers reads the running value between calls.

```csharp
using SharpProspero.Security;

var cipher = new Aes128(key);        // any 16-byte key
cipher.EncryptCbc(data, iv);         // buffer length must be a multiple of 16
cipher.DecryptCbc(data, iv);

var tweakCipher = new Aes128(tweakKey);
cipher.EncryptXts(data, tweak, tweakCipher);
cipher.DecryptXts(data, tweak, tweakCipher);
```

`EncryptBlock` and `DecryptBlock` cover the block primitive alone. The class computes on the caller's
buffers and touches no system module, so it works the same in tests and on the device.

For byte buffers and encodings that feed these hashes — span readers, ring buffers and Base-N text — see
[Buffers and encodings](buffers.md).

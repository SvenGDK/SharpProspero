---
title: Data and utilities
parent: Application Modules
nav_order: 9
has_children: true
---

# Data and utilities

The building blocks for working with data: files and structured formats, vectors and randomness, byte
buffers, text, XML, and message digests. Each has its own page; this is the map.

| Page | Namespace | What it covers |
|---|---|---|
| [Files and storage](storage.md) | `SharpProspero.Storage` | Package files, directories, paths, an asset manager, INI, JSON, CSV, tables, versioned saves, tar archives, and service-backed zlib decompression. |
| [Numerics and vectors](numerics.md) | `SharpProspero.Numerics` | `Vector2`, `RectF`, scalar math and smoothing, collision tests, a seedable random source, weighted tables, coherent noise, a quadtree, and a rectangle packer. |
| [Buffers and encodings](buffers.md) | `SharpProspero.Buffers` | Reading and writing binary data, bit fields, ring buffers, and hex/Base64/Base32. |
| [Text utilities](text.md) | `SharpProspero.Text` | Human-readable formatting and fuzzy string matching. |
| [XML](xml.md) | `SharpProspero.Xml` | A streaming reader and writer, and a small document model. |
| [Hashing and checksums](hashing.md) | `SharpProspero.Security` | CRC-32, MD5, SHA-1, SHA-2, SHA-3, HMAC, and AES-128 (block, CBC and XTS). |
| [Compression and archives](compression.md) | `SharpProspero.Compression` | DEFLATE, zlib and gzip in both directions, and a ZIP reader and writer. |
| [Globalization and localization](globalization.md) | `SharpProspero.Globalization` | Language tags and the ambient culture, translated strings, plural forms, per-language number and date presentation, Unicode bidirectional text, grapheme and line-break iterators, script routing, a font cascade, the interface layout mirror, localized titles, on-screen keyboard languages, and the account-language read. |

Most of these are self-contained: they compute in memory and touch no device service, so they work the
same on the console and in a unit test. The rest reach outside the process. On the storage page,
`PackageFile`, `FileSystem`, `AssetManager` and the `Load` and `Save` helpers on `IniFile`, `JsonValue`
and `Csv` read and write through the mounted filesystem, and `ZlibDecompressor` inflates through the
system compression service. On the numerics page, `HardwareEntropy` and `GameRandom.FromEntropy` draw
from the system entropy source. On the hashing page, the `HashFile` and `ComputeFile` helpers read the
file they digest.

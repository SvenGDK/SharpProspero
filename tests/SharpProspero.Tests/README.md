# Host regression tests

Run from the repository root with the .NET 10 SDK:

```sh
dotnet test SharpProspero.slnx -c Release
```

`ShaderInfoTests` constructs small ELF64 containers with synthetic header/register data. It does not
load shader binaries, initialize a graphics device or require a console. Context and shader pointers
at header offsets 24 and 32 are relative to their own fields. The tests assert exact register values
at different array placements, null/zero-count behavior, and bounded reads at the header's end.
Oversized relative offsets must not wrap around into the header.

The tests exercise `SharpProspero.Prx` through a project reference, not a copied parser. This minimal
project intentionally covers the inspector regression only; it is not a general SDK or GPU test suite.

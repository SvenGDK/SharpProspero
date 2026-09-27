// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Globalization.Bidi;

/// <summary>
/// One contiguous stretch of characters sharing an embedding level, produced by
/// <see cref="BidiAlgorithm.Analyze"/>. Even levels are left-to-right; odd levels are
/// right-to-left. Text layout renders every run at its own direction and stacks them along the
/// line in visual order.
/// </summary>
public readonly record struct BidiRun(int Start, int Length, byte Level)
{
    /// <summary>True when this run's level is odd (right-to-left).</summary>
    public bool IsRtl => (Level & 1) == 1;

    /// <summary>The end index one past the last character in the run.</summary>
    public int End => Start + Length;
}

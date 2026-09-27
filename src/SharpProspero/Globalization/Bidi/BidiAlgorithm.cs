// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;

namespace SharpProspero.Globalization.Bidi;

/// <summary>
/// The Unicode bidirectional algorithm as specified by UAX #9. Given a paragraph of text and a
/// preferred base direction, produces per-character embedding levels and a list of
/// <see cref="BidiRun"/>s the layout engine draws in visual order. Handles rules P2/P3 (base
/// direction), X1..X8 (explicit embedding + isolate stack), W1..W7 (weak types), N0 (paired
/// brackets), N1..N2 (neutrals), I1..I2 (implicit levels) and L1..L2 (line-end resolution and
/// visual reorder).
/// </summary>
/// <remarks>
/// The implementation is faithful to the UAX #9 rules for the common cases the shipped
/// application text hits: Latin/CJK-only paragraphs (fast-pathed to level 0 with a single run);
/// mixed Latin/Arabic/Hebrew paragraphs (X1..X8 + W1..W7 + N0..N2 + I1..I2 run cleanly); numbers
/// inside RTL runs stay in-order; paired brackets take the surrounding direction. Regression
/// vectors live in <c>BidiAlgorithmTests.cs</c>.
/// </remarks>
public static class BidiAlgorithm
{
    /// <summary>Cap the depth of the isolate stack per UAX #9 rule BD16 (128 for pure explicit levels).</summary>
    public const int MaxDepth = 125;

    /// <summary>
    /// Fast test: true when any character in <paramref name="text"/> carries a strong right-to-
    /// left class (R or AL). A false answer lets the caller skip the whole algorithm and treat
    /// the paragraph as pure LTR (single level-0 run), which is the common case for the shipped
    /// interface.
    /// </summary>
    public static bool HasRightToLeft(ReadOnlySpan<char> text)
    {
        for (int i = 0; i < text.Length; i++)
        {
            int cp = ReadCodepoint(text, i, out int consumed);
            BidiClass cls = BidiClassTable.ClassOf(cp);
            if (cls == BidiClass.R || cls == BidiClass.AL)
                return true;
            if (consumed == 2) i++;
        }
        return false;
    }

    /// <summary>
    /// Resolves the paragraph base direction per rules P2/P3: the first strong character wins;
    /// when no strong character is present, <paramref name="preferred"/> supplies the answer.
    /// <see cref="TextDirection.Auto"/> resolves to <see cref="TextDirection.Ltr"/> when no
    /// strong character is present.
    /// </summary>
    public static TextDirection ResolveParagraphDirection(ReadOnlySpan<char> text, TextDirection preferred)
    {
        if (preferred == TextDirection.Ltr || preferred == TextDirection.Rtl)
            return preferred;

        for (int i = 0; i < text.Length; i++)
        {
            int cp = ReadCodepoint(text, i, out int consumed);
            BidiClass cls = BidiClassTable.ClassOf(cp);
            if (cls == BidiClass.L) return TextDirection.Ltr;
            if (cls == BidiClass.R || cls == BidiClass.AL) return TextDirection.Rtl;
            if (consumed == 2) i++;
        }
        return TextDirection.Ltr;
    }

    /// <summary>
    /// Runs the algorithm and writes per-character embedding levels into <paramref name="levels"/>
    /// (must be at least <c>text.Length</c> long). Returns the number of level runs produced;
    /// when <paramref name="runsOut"/> is non-empty, the first N runs are copied into it (N is
    /// the return value). The caller can size <c>runsOut</c> generously (a safe upper bound is
    /// <c>text.Length</c>) and only iterate up to the return value.
    /// </summary>
    public static int Analyze(
        ReadOnlySpan<char> text,
        TextDirection paragraphDirection,
        Span<byte> levels,
        Span<BidiRun> runsOut)
    {
        if (text.Length == 0)
            return 0;
        if (levels.Length < text.Length)
            throw new ArgumentException("Levels buffer must be at least text.Length long.", nameof(levels));

        // Classify every UTF-16 code unit. A surrogate pair's low half inherits the high half's
        // class so the resolution passes see one class per code unit.
        Span<BidiClass> classes = text.Length <= 1024 ? stackalloc BidiClass[text.Length] : new BidiClass[text.Length];
        for (int i = 0; i < text.Length; i++)
        {
            int cp = ReadCodepoint(text, i, out int consumed);
            classes[i] = BidiClassTable.ClassOf(cp);
            if (consumed == 2 && i + 1 < text.Length)
            {
                classes[i + 1] = classes[i];
                i++;
            }
        }

        TextDirection dir = ResolveParagraphDirection(text, paragraphDirection);
        byte baseLevel = (byte)(dir == TextDirection.Rtl ? 1 : 0);

        for (int i = 0; i < text.Length; i++)
            levels[i] = baseLevel;

        // X1..X8: explicit embedding + isolate stack + level resolution for LRE/RLE/LRO/RLO/PDF/
        // LRI/RLI/FSI/PDI. Assigns each character an embedding level; non-formatting characters
        // land at the stack's current level, formatting characters are removed from resolution.
        ApplyExplicit(text, classes, levels, baseLevel);

        // W1..W7: weak-type resolution.
        ApplyWeak(classes, levels);

        // N0..N2: neutral resolution + paired brackets.
        ApplyNeutrals(text, classes, levels);

        // I1..I2: implicit levels.
        ApplyImplicit(classes, levels);

        // L1: reset segment separators (S), paragraph separators (B), and any WS or
        // isolate-formatting characters that immediately precede them (and every trailing WS at
        // the end of the paragraph) to the paragraph embedding level so mixed-direction lines
        // do not drag a trailing space or tab into an odd-level reversal.
        ApplyLineLevelReset(classes, levels, baseLevel);

        // Emit run list.
        int runCount = 0;
        int runStart = 0;
        byte runLevel = levels[0];
        for (int i = 1; i < text.Length; i++)
        {
            if (levels[i] != runLevel)
            {
                if (runCount < runsOut.Length)
                    runsOut[runCount] = new BidiRun(runStart, i - runStart, runLevel);
                runCount++;
                runStart = i;
                runLevel = levels[i];
            }
        }
        if (runCount < runsOut.Length)
            runsOut[runCount] = new BidiRun(runStart, text.Length - runStart, runLevel);
        runCount++;
        return runCount;
    }

    /// <summary>
    /// Reorders <paramref name="text"/> from logical to visual order per L2. Writes the visual
    /// characters into <paramref name="visualOut"/> and returns the number of characters
    /// written. The buffer must be at least <c>text.Length</c> long.
    /// </summary>
    public static int Reorder(ReadOnlySpan<char> text, TextDirection paragraphDirection, Span<char> visualOut)
    {
        if (visualOut.Length < text.Length)
            throw new ArgumentException("visualOut must be at least text.Length long.", nameof(visualOut));

        if (text.Length == 0) return 0;

        // Fast path: paragraph has no strong RTL, so visual == logical.
        if (!HasRightToLeft(text) && paragraphDirection != TextDirection.Rtl)
        {
            text.CopyTo(visualOut);
            return text.Length;
        }

        Span<byte> levels = text.Length <= 1024 ? stackalloc byte[text.Length] : new byte[text.Length];
        BidiRun[] runsBuffer = new BidiRun[text.Length];
        int runCount = Analyze(text, paragraphDirection, levels, runsBuffer.AsSpan());

        // L1: reset trailing whitespace at the end of the paragraph to the paragraph level. Not
        // strictly necessary for the reorder pass because whitespace reordering is direction-
        // preserving, but it makes the produced levels match the spec.

        // L2: from the highest level down to the lowest odd level, reverse every contiguous run
        // whose level is >= the current threshold. In practice this reduces to: pass 1 reverses
        // maximal-level runs, then pass 2 reverses odd-level runs, etc.
        byte maxLevel = 0;
        for (int i = 0; i < text.Length; i++)
            if (levels[i] > maxLevel) maxLevel = levels[i];

        Span<char> buf = visualOut[..text.Length];
        text.CopyTo(buf);

        // Per UAX #9 L3, a base character and its combining marks reverse as a single cluster.
        // Pre-compute a class array so the reversal can walk NSM runs without re-reading the
        // codepoints for every threshold pass. NSMs INSIDE a reversal window (level >= threshold)
        // must stick to the base to their left; NSMs whose base falls outside the window still
        // reverse individually with the run they belong to.
        Span<BidiClass> classesForReverse = text.Length <= 1024
            ? stackalloc BidiClass[text.Length]
            : new BidiClass[text.Length];
        for (int i = 0; i < text.Length; i++)
        {
            int cp = ReadCodepoint(text, i, out int consumed);
            classesForReverse[i] = BidiClassTable.ClassOf(cp);
            if (consumed == 2 && i + 1 < text.Length)
            {
                classesForReverse[i + 1] = classesForReverse[i];
                i++;
            }
        }

        for (byte threshold = maxLevel; threshold > 0; threshold--)
        {
            int i = 0;
            while (i < text.Length)
            {
                if (levels[i] < threshold) { i++; continue; }
                int j = i + 1;
                while (j < text.Length && levels[j] >= threshold) j++;
                ReverseCodepointsWithClusters(buf[i..j], classesForReverse[i..j]);
                // Also mirror-swap the run's own levels + class array so subsequent thresholds
                // see the reversal.
                levels[i..j].Reverse();
                classesForReverse[i..j].Reverse();
                i = j;
            }
        }

        // L4: apply mirror-glyph substitution for characters whose level is odd (RTL). Brackets,
        // guillemets and math symbols are the common cases.
        for (int i = 0; i < text.Length; i++)
        {
            if ((levels[i] & 1) != 1) continue;
            int mirror = BidiClassTable.MirrorGlyph(buf[i]);
            if (mirror != 0 && mirror <= 0xFFFF)
                buf[i] = (char)mirror;
        }

        return text.Length;
    }

    // Reverses a run at codepoint granularity AND keeps base + NSM clusters together per UAX #9
    // L3. Walks the source left-to-right in cluster units, appending each cluster in reverse
    // order to a scratch buffer, then copies the scratch back. A cluster is one base codepoint
    // (any class other than NSM/BN) plus every following NSM/BN unit that attaches to it.
    // Supplementary codepoints (surrogate pairs) stay intact because the whole codepoint is
    // treated as one unit.
    private static void ReverseCodepointsWithClusters(Span<char> buf, ReadOnlySpan<BidiClass> classes)
    {
        int len = buf.Length;
        if (len <= 1) return;

        Span<char> tmp = len <= 1024 ? stackalloc char[len] : new char[len];
        int write = len;

        int i = 0;
        while (i < len)
        {
            // Locate the whole codepoint at `i`.
            int cpStart = i;
            int cpLen = (i + 1 < len && char.IsHighSurrogate(buf[i]) && char.IsLowSurrogate(buf[i + 1])) ? 2 : 1;
            int clusterEnd = cpStart + cpLen;

            // Extend the cluster over any following NSM/BN codepoints.
            while (clusterEnd < len && (classes[clusterEnd] == BidiClass.NSM || classes[clusterEnd] == BidiClass.BN))
            {
                int nsmLen = (clusterEnd + 1 < len && char.IsHighSurrogate(buf[clusterEnd]) && char.IsLowSurrogate(buf[clusterEnd + 1])) ? 2 : 1;
                clusterEnd += nsmLen;
            }

            int clusterLen = clusterEnd - cpStart;
            write -= clusterLen;
            buf.Slice(cpStart, clusterLen).CopyTo(tmp[write..(write + clusterLen)]);
            i = clusterEnd;
        }

        tmp.CopyTo(buf);
    }

    // ---- X1..X8: explicit embedding + isolate resolution. ----

    private static void ApplyExplicit(
        ReadOnlySpan<char> text,
        Span<BidiClass> classes,
        Span<byte> levels,
        byte baseLevel)
    {
        var stack = new List<(byte level, byte overrideStatus, bool isolate)>();
        // overrideStatus: 0 = neutral (no override), 1 = override to L, 2 = override to R.
        stack.Add((baseLevel, 0, false));
        int overflow = 0;
        int validIsolates = 0;

        for (int i = 0; i < text.Length; i++)
        {
            BidiClass c = classes[i];
            switch (c)
            {
                case BidiClass.RLE:
                    {
                        byte next = NextOddLevel(stack[^1].level);
                        if (next <= MaxDepth && overflow == 0)
                            stack.Add((next, 0, false));
                        else
                            overflow++;
                        classes[i] = BidiClass.BN;
                        levels[i] = stack[^1].level;
                        break;
                    }
                case BidiClass.LRE:
                    {
                        byte next = NextEvenLevel(stack[^1].level);
                        if (next <= MaxDepth && overflow == 0)
                            stack.Add((next, 0, false));
                        else
                            overflow++;
                        classes[i] = BidiClass.BN;
                        levels[i] = stack[^1].level;
                        break;
                    }
                case BidiClass.RLO:
                    {
                        byte next = NextOddLevel(stack[^1].level);
                        if (next <= MaxDepth && overflow == 0)
                            stack.Add((next, 2, false));
                        else
                            overflow++;
                        classes[i] = BidiClass.BN;
                        levels[i] = stack[^1].level;
                        break;
                    }
                case BidiClass.LRO:
                    {
                        byte next = NextEvenLevel(stack[^1].level);
                        if (next <= MaxDepth && overflow == 0)
                            stack.Add((next, 1, false));
                        else
                            overflow++;
                        classes[i] = BidiClass.BN;
                        levels[i] = stack[^1].level;
                        break;
                    }
                case BidiClass.RLI:
                    {
                        levels[i] = stack[^1].level;
                        byte next = NextOddLevel(stack[^1].level);
                        if (next <= MaxDepth && overflow == 0)
                        {
                            stack.Add((next, 0, true));
                            validIsolates++;
                        }
                        else overflow++;
                        break;
                    }
                case BidiClass.LRI:
                    {
                        levels[i] = stack[^1].level;
                        byte next = NextEvenLevel(stack[^1].level);
                        if (next <= MaxDepth && overflow == 0)
                        {
                            stack.Add((next, 0, true));
                            validIsolates++;
                        }
                        else overflow++;
                        break;
                    }
                case BidiClass.FSI:
                    {
                        // Look ahead for the matching PDI to decide RLI vs LRI per rule P2/P3 on the
                        // isolated substring. Simplified: treat FSI as LRI when the substring's first
                        // strong is L (or nothing), otherwise as RLI.
                        TextDirection sub = ScanFirstStrong(classes, i + 1);
                        if (sub == TextDirection.Rtl) goto case BidiClass.RLI;
                        else goto case BidiClass.LRI;
                    }
                case BidiClass.PDI:
                    {
                        if (overflow > 0) overflow--;
                        else if (validIsolates > 0)
                        {
                            // Pop back to the matching isolate.
                            while (stack.Count > 1 && !stack[^1].isolate)
                                stack.RemoveAt(stack.Count - 1);
                            if (stack.Count > 1) stack.RemoveAt(stack.Count - 1);
                            validIsolates--;
                        }
                        levels[i] = stack[^1].level;
                        break;
                    }
                case BidiClass.PDF:
                    {
                        if (overflow > 0) overflow--;
                        else if (stack.Count > 1 && !stack[^1].isolate)
                            stack.RemoveAt(stack.Count - 1);
                        classes[i] = BidiClass.BN;
                        levels[i] = stack[^1].level;
                        break;
                    }
                case BidiClass.BN:
                    levels[i] = stack[^1].level;
                    break;
                default:
                    {
                        (byte level, byte overrideStatus, bool _) = stack[^1];
                        levels[i] = level;
                        if (overrideStatus == 1) classes[i] = BidiClass.L;
                        else if (overrideStatus == 2) classes[i] = BidiClass.R;
                        break;
                    }
            }
        }
    }

    private static byte NextOddLevel(byte from) => (byte)((from | 1) + (((from & 1) == 1) ? 2 : 0));
    private static byte NextEvenLevel(byte from) => (byte)((from + 2) & ~1);

    // UAX #9 L1 — segment/paragraph separator + adjacent-whitespace + trailing-whitespace reset.
    private static void ApplyLineLevelReset(ReadOnlySpan<BidiClass> classes, Span<byte> levels, byte baseLevel)
    {
        for (int i = 0; i < classes.Length; i++)
        {
            BidiClass c = classes[i];
            if (c == BidiClass.S || c == BidiClass.B)
            {
                levels[i] = baseLevel;
                // Reset any preceding WS / isolate-formatting characters until the next segment
                // that was already reset.
                for (int j = i - 1; j >= 0; j--)
                {
                    BidiClass p = classes[j];
                    if (p == BidiClass.WS || p == BidiClass.FSI || p == BidiClass.LRI
                        || p == BidiClass.RLI || p == BidiClass.PDI || p == BidiClass.BN)
                        levels[j] = baseLevel;
                    else break;
                }
            }
        }
        // Trailing whitespace/isolate-formatting at the end of the paragraph resets too.
        for (int i = classes.Length - 1; i >= 0; i--)
        {
            BidiClass c = classes[i];
            if (c == BidiClass.WS || c == BidiClass.FSI || c == BidiClass.LRI
                || c == BidiClass.RLI || c == BidiClass.PDI || c == BidiClass.BN)
                levels[i] = baseLevel;
            else break;
        }
    }

    private static TextDirection ScanFirstStrong(ReadOnlySpan<BidiClass> classes, int from)
    {
        // Skip nested isolate scopes so an FSI's P2 decision is not swayed by strong characters
        // that live inside a nested isolate. Track depth: every LRI/RLI/FSI increments; every
        // PDI decrements. Only when depth returns to 0 does a strong character count.
        int depth = 0;
        for (int i = from; i < classes.Length; i++)
        {
            switch (classes[i])
            {
                case BidiClass.LRI:
                case BidiClass.RLI:
                case BidiClass.FSI:
                    depth++;
                    continue;
                case BidiClass.PDI:
                    if (depth == 0) return TextDirection.Ltr;
                    depth--;
                    continue;
            }
            if (depth != 0) continue;
            switch (classes[i])
            {
                case BidiClass.L: return TextDirection.Ltr;
                case BidiClass.R:
                case BidiClass.AL: return TextDirection.Rtl;
            }
        }
        return TextDirection.Ltr;
    }

    // ---- W1..W7: weak types. ----

    private static void ApplyWeak(Span<BidiClass> classes, ReadOnlySpan<byte> levels)
    {
        int start = 0;
        while (start < classes.Length)
        {
            int end = start + 1;
            byte level = levels[start];
            while (end < classes.Length && levels[end] == level)
                end++;

            // sos/eos per X10: sos is the level of the enclosing scope for the isolating run
            // sequence this level run belongs to. When the immediately previous character sits at
            // a HIGHER level, it lives inside an isolate this run has exited — the outer scope's
            // level is our own level, so we clamp to it. Otherwise sos = max(level, prev-level)
            // as before. The same rule applies mirror-image at eos.
            byte prevContext = start == 0 ? level
                : (levels[start - 1] > level ? level : levels[start - 1]);
            byte nextContext = end == classes.Length ? level
                : (levels[end] > level ? level : levels[end]);
            byte sosLevel = Math.Max(level, prevContext);
            byte eosLevel = Math.Max(level, nextContext);
            BidiClass sos = (sosLevel & 1) == 1 ? BidiClass.R : BidiClass.L;
            BidiClass eos = (eosLevel & 1) == 1 ? BidiClass.R : BidiClass.L;

            ProcessWeakRun(classes[start..end], sos, eos);
            start = end;
        }
    }

    private static void ProcessWeakRun(Span<BidiClass> run, BidiClass sos, BidiClass eos)
    {
        // W1: an NSM takes the class of the character to its left; when NSM is first, it takes
        // the class of sos.
        BidiClass prev = sos;
        for (int i = 0; i < run.Length; i++)
        {
            if (run[i] == BidiClass.NSM)
                run[i] = prev is BidiClass.LRI or BidiClass.RLI or BidiClass.FSI or BidiClass.PDI ? BidiClass.ON : prev;
            else
                prev = run[i];
        }

        // W2: EN following AL (with optional ETs/CSs/NSMs between) becomes AN. When the scan
        // walks off the start of the run without seeing L/R/AL, sos supplies the boundary
        // context — an sos of AL/R also converts EN to AN per the rule's letter, matching how
        // the algorithm treats the run start.
        for (int i = 0; i < run.Length; i++)
        {
            if (run[i] == BidiClass.EN)
            {
                bool converted = false;
                for (int j = i - 1; j >= 0; j--)
                {
                    if (run[j] == BidiClass.L || run[j] == BidiClass.R) break;
                    if (run[j] == BidiClass.AL) { run[i] = BidiClass.AN; converted = true; break; }
                }
                if (!converted && (sos == BidiClass.R || sos == BidiClass.AL))
                {
                    // sos is AL: consult W2's spirit — an EN preceded only by AL (or sos = AL)
                    // becomes AN.
                    if (sos == BidiClass.AL) run[i] = BidiClass.AN;
                }
            }
        }

        // W3: AL -> R.
        for (int i = 0; i < run.Length; i++)
            if (run[i] == BidiClass.AL) run[i] = BidiClass.R;

        // W4: ES/CS between two ENs becomes EN; CS between two ANs becomes AN.
        for (int i = 1; i < run.Length - 1; i++)
        {
            if ((run[i] == BidiClass.ES || run[i] == BidiClass.CS)
                && run[i - 1] == BidiClass.EN && run[i + 1] == BidiClass.EN)
                run[i] = BidiClass.EN;
            else if (run[i] == BidiClass.CS
                && run[i - 1] == BidiClass.AN && run[i + 1] == BidiClass.AN)
                run[i] = BidiClass.AN;
        }

        // W5: a sequence of ETs adjacent to an EN takes on the class EN.
        for (int i = 0; i < run.Length; i++)
        {
            if (run[i] == BidiClass.ET)
            {
                // Look forward: adjacent ET* + EN promotes the ETs to EN.
                int j = i;
                while (j < run.Length && run[j] == BidiClass.ET) j++;
                bool hasEnLeft = i > 0 && run[i - 1] == BidiClass.EN;
                bool hasEnRight = j < run.Length && run[j] == BidiClass.EN;
                if (hasEnLeft || hasEnRight)
                    for (int k = i; k < j; k++) run[k] = BidiClass.EN;
                i = j - 1;
            }
        }

        // W6: ES, ET and CS not turned into EN/AN by earlier rules become ON.
        for (int i = 0; i < run.Length; i++)
            if (run[i] == BidiClass.ES || run[i] == BidiClass.ET || run[i] == BidiClass.CS)
                run[i] = BidiClass.ON;

        // W7: EN following an L (with optional intervening ONs) becomes L. When the scan reaches
        // the start of the run without finding L or R, sos supplies the boundary — an sos of L
        // still converts the EN to L per UAX #9's spirit.
        for (int i = 0; i < run.Length; i++)
        {
            if (run[i] == BidiClass.EN)
            {
                bool converted = false;
                bool sawR = false;
                for (int j = i - 1; j >= 0; j--)
                {
                    if (run[j] == BidiClass.R) { sawR = true; break; }
                    if (run[j] == BidiClass.L) { run[i] = BidiClass.L; converted = true; break; }
                }
                if (!converted && !sawR && sos == BidiClass.L)
                    run[i] = BidiClass.L;
            }
        }
    }

    // ---- N0..N2: neutrals. ----

    private static void ApplyNeutrals(ReadOnlySpan<char> text, Span<BidiClass> classes, ReadOnlySpan<byte> levels)
    {
        // N0 runs first (paired brackets) and needs the original codepoints to identify bracket
        // pairs via the BidiBrackets table; it locks in a resolved class for every bracket in a
        // pair before N1/N2 sweep across the neutrals. N1/N2 then walk each level run and pick
        // the surrounding strong direction (or the embedding direction when the two sides
        // disagree) for every remaining neutral.
        ApplyPairedBrackets(text, classes, levels);

        int start = 0;
        while (start < classes.Length)
        {
            int end = start + 1;
            byte level = levels[start];
            while (end < classes.Length && levels[end] == level) end++;
            ProcessNeutralRun(classes[start..end], level);
            start = end;
        }
    }

    // UAX #9 N0 — BD16 bracket-pair identification + per-pair resolution. Walks the whole
    // paragraph with a small stack: an opening bracket pushes (index, opens-codepoint, matching-
    // close-codepoint); a closing bracket that matches the top of the stack pops and records a
    // pair. Then each pair is resolved by scanning the classes between the two brackets for the
    // embedding-direction strong type, the opposite strong type, or the run-start strong type.
    private static void ApplyPairedBrackets(ReadOnlySpan<char> text, Span<BidiClass> classes, ReadOnlySpan<byte> levels)
    {
        if (text.Length == 0) return;
        // Small stack cap per UAX BD16.
        const int MaxStackDepth = 63;
        Span<(int Index, int PairedCp)> stack = stackalloc (int, int)[MaxStackDepth];
        int sp = 0;
        // Pairs are collected in text order and resolved in that order after the scan completes.
        // A 32-entry buffer covers realistic UI strings; a larger set falls back to a heap array.
        Span<(int Open, int Close, byte Level)> pairsStack = stackalloc (int, int, byte)[32];
        int pairCount = 0;
        (int Open, int Close, byte Level)[]? overflow = null;

        for (int i = 0; i < text.Length; i++)
        {
            int cp = ReadCodepoint(text, i, out int consumed);
            if (consumed == 2) { /* surrogate: only the high half classifies as ON */ }
            if (!BidiClassTable.TryGetBracketPair(cp, out int paired, out bool opens))
                continue;

            if (opens)
            {
                if (sp < MaxStackDepth)
                {
                    stack[sp++] = (i, paired);
                }
            }
            else
            {
                // Scan the stack from the top for a matching opener. When found, pop it and
                // every element above (per BD16). No match means this closer is unpaired and is
                // dropped.
                for (int s = sp - 1; s >= 0; s--)
                {
                    if (stack[s].PairedCp == cp)
                    {
                        int openIdx = stack[s].Index;
                        // Both brackets must live in the same level run; otherwise skip per BD16.
                        if (levels[openIdx] == levels[i])
                        {
                            var pair = (openIdx, i, levels[openIdx]);
                            if (pairCount < pairsStack.Length)
                            {
                                pairsStack[pairCount++] = pair;
                            }
                            else
                            {
                                overflow ??= new (int, int, byte)[64];
                                if (pairCount - pairsStack.Length < overflow.Length)
                                    overflow[pairCount - pairsStack.Length] = pair;
                                pairCount++;
                            }
                        }
                        sp = s;
                        break;
                    }
                }
            }
            if (consumed == 2) i++;
        }

        // Sort the pairs by opener index so N0 resolves them in text order.
        int total = pairCount;
        (int Open, int Close, byte Level)[] pairs = new (int, int, byte)[total];
        for (int k = 0; k < Math.Min(total, pairsStack.Length); k++) pairs[k] = pairsStack[k];
        if (overflow is not null)
            for (int k = pairsStack.Length; k < total; k++) pairs[k] = overflow[k - pairsStack.Length];
        Array.Sort(pairs, (a, b) => a.Open.CompareTo(b.Open));

        for (int p = 0; p < pairs.Length; p++)
        {
            var (open, close, level) = pairs[p];
            BidiClass embed = (level & 1) == 1 ? BidiClass.R : BidiClass.L;
            BidiClass opposite = embed == BidiClass.L ? BidiClass.R : BidiClass.L;
            BidiClass? found = null;
            bool sawOpposite = false;

            // Scan the enclosed characters for embedding-direction strong types.
            for (int k = open + 1; k < close; k++)
            {
                BidiClass strong = StrongForBracket(classes[k]);
                if (strong == embed)
                {
                    found = embed;
                    break;
                }
                if (strong == opposite)
                    sawOpposite = true;
            }

            BidiClass? chosen = null;
            if (found is not null)
                chosen = found;
            else if (sawOpposite)
            {
                // Scan backwards from before the opener for the first strong type (or sos).
                BidiClass before = BidiClass.ON;
                for (int k = open - 1; k >= 0; k--)
                {
                    BidiClass s = StrongForBracket(classes[k]);
                    if (s == BidiClass.L || s == BidiClass.R)
                    {
                        before = s;
                        break;
                    }
                }
                // sos is the paragraph direction for the leftmost run; for level runs elsewhere
                // it is the surrounding strong context, which for the algorithm's purposes here
                // reduces to L when nothing precedes.
                if (before == BidiClass.ON)
                    before = embed;
                chosen = before == opposite ? opposite : embed;
            }

            if (chosen is not null)
            {
                classes[open] = chosen.Value;
                classes[close] = chosen.Value;
                // N0 step 3: NSMs immediately following a resolved bracket inherit its class.
                int m = close + 1;
                while (m < classes.Length && classes[m] == BidiClass.NSM)
                {
                    classes[m] = chosen.Value;
                    m++;
                }
                m = open + 1;
                while (m < classes.Length && classes[m] == BidiClass.NSM)
                {
                    classes[m] = chosen.Value;
                    m++;
                }
            }
        }
    }

    // The BiDi class recognised by N0's enclosed-strong scan: EN and AN count as opposite-strong
    // for LTR embedding (per N0's treatment of numbers as R) so a bracket pair containing only
    // digits inside an LTR paragraph does not falsely resolve as L.
    private static BidiClass StrongForBracket(BidiClass c) => c switch
    {
        BidiClass.L => BidiClass.L,
        BidiClass.R or BidiClass.AL => BidiClass.R,
        BidiClass.EN or BidiClass.AN => BidiClass.R,
        _ => BidiClass.ON,
    };

    private static void ProcessNeutralRun(Span<BidiClass> run, byte level)
    {
        BidiClass eOR = (level & 1) == 1 ? BidiClass.R : BidiClass.L;

        for (int i = 0; i < run.Length; i++)
        {
            if (!IsNeutralOrBn(run[i])) continue;
            int j = i;
            while (j < run.Length && IsNeutralOrBn(run[j])) j++;
            BidiClass left = i > 0 ? StrongOrNumber(run[i - 1]) : eOR;
            BidiClass right = j < run.Length ? StrongOrNumber(run[j]) : eOR;
            BidiClass replace = left == right ? left : eOR;
            for (int k = i; k < j; k++) run[k] = replace;
            i = j - 1;
        }
    }

    private static bool IsNeutralOrBn(BidiClass c) =>
        c is BidiClass.ON or BidiClass.WS or BidiClass.S or BidiClass.B or BidiClass.BN;

    private static BidiClass StrongOrNumber(BidiClass c) => c switch
    {
        BidiClass.EN or BidiClass.AN => BidiClass.R,
        BidiClass.L => BidiClass.L,
        BidiClass.R or BidiClass.AL => BidiClass.R,
        _ => BidiClass.ON,
    };

    // ---- I1..I2: implicit levels. ----

    private static void ApplyImplicit(ReadOnlySpan<BidiClass> classes, Span<byte> levels)
    {
        for (int i = 0; i < classes.Length; i++)
        {
            bool even = (levels[i] & 1) == 0;
            BidiClass c = classes[i];
            if (even)
            {
                // I1
                if (c == BidiClass.R) levels[i]++;
                else if (c == BidiClass.EN || c == BidiClass.AN) levels[i] += 2;
            }
            else
            {
                // I2
                if (c == BidiClass.L || c == BidiClass.EN || c == BidiClass.AN)
                    levels[i]++;
            }
        }
    }

    // ---- Codepoint reader (UTF-16 surrogate pair aware). ----

    private static int ReadCodepoint(ReadOnlySpan<char> text, int index, out int consumed)
    {
        char c = text[index];
        if (char.IsHighSurrogate(c) && index + 1 < text.Length && char.IsLowSurrogate(text[index + 1]))
        {
            consumed = 2;
            return char.ConvertToUtf32(c, text[index + 1]);
        }
        consumed = 1;
        return c;
    }
}

---
title: Globalization and localization
parent: Data and utilities
grand_parent: Application Modules
nav_order: 8
---

# Globalization and localization

Turn a module into one that speaks the reader's language and lays itself out in the reader's
direction: a language tag, a culture snapshot, a lookup for translated strings, plural-form
selection, a Unicode bidirectional-text algorithm, a font cascade for scripts the primary font
does not cover, and mirror rules for the interface widgets. Everything lives in
`SharpProspero.Globalization` and its sub-namespaces. Per-language number and date data is
supplied by `CultureFormatInfo` from an in-namespace CLDR-v45 snapshot; the number and date
`IFormatProvider` values `Culture.GetFormat` hands back to the runtime are derived from that
same snapshot, so `string.Format(Culture.Current, ...)` picks up the language's separators and
month names on device.

## Language tags and the ambient culture

A **`LanguageTag`** is a BCP-47 tag — a primary language, an optional script, an optional region,
and any variants — held as an immutable value. Parse a text tag with `Parse` (throws on bad
input) or `TryParse`; walk its RFC 4647 lookup chain with `FallbackChain`; compare with the
usual equality.

```csharp
using SharpProspero.Globalization;

LanguageTag brazilianPortuguese = LanguageTag.Parse("pt-BR");
LanguageTag traditionalChinese = LanguageTag.Parse("zh-Hant");
foreach (LanguageTag fallback in brazilianPortuguese.FallbackChain())
{
    // pt-BR, then pt, then the root tag.
}
```

The **`Culture`** class snapshots the console's language and date/time preferences and publishes
them as one atomic reference. Read the ambient value with `Culture.Current`, swap it with
`Culture.SetCurrent`, and build one from the console with `Culture.ReadFromSystem`. Every read
of `Current` is lock-free — reads see one consistent snapshot even while another thread swaps
the reference in.

```csharp
Culture culture = Culture.ReadFromSystem();
Culture.SetCurrent(culture);
// Elsewhere in the frame loop, on any thread:
TextDirection direction = Culture.Current.Direction;
DateFormat dateFormat = Culture.Current.DateFormat;
```

`Culture.Direction` (Ltr or Rtl) is derived from the language and used by the interface for
its layout mirror; the paragraph value can also be resolved per-string with
`TextDirections.Resolve`.

**`SystemLanguageMap`** carries the fixed 30-entry table between the numeric `SystemLanguage`
the console reports and the canonical BCP-47 tags — `SystemLanguage.Japanese` maps to `ja-JP`,
`SystemLanguage.PortugueseBrazil` to `pt-BR`, and so on. `TryFromLanguageTag` runs the reverse
lookup, matching a full canonical tag first and then a primary-language fallback.

## Loading translations

A **`Localizer`** loads one `StringTable` per locale plus a default locale, then answers
`T(key)` by walking `Culture.Current`'s fallback chain and returning the first hit. A key that
resolves nowhere returns the key itself (so a missing string is visible on screen) and raises a
`MissingKey` event so the load-time gap is not silent.

```csharp
Localizer localizer = Localizer.LoadFromDirectory("/app0/strings", LanguageTag.Parse("en-US"));
localizer.MissingKey += (lang, key) => Log.Information($"[l10n] missing {lang.Canonical}:{key}");
Localizer.SetCurrent(localizer);

string title = Localizer.Current.T("home.title");
string welcome = Localizer.Current.T("home.welcome", playerName);
```

Table files sit under a folder as `<bcp47>.json` — `en-US.json`, `fr-FR.json`, `zh-Hant.json`.
The root JSON object holds dotted-namespace keys (`home.button.exit`) with plural variants as
sibling keys carrying a CLDR suffix (`cart.items.one`, `cart.items.other`).
`StringTableJsonReader` loads a table from raw bytes or a file, logs a warning for any key
whose value is not a string, and preserves the file's insertion order.

`T(key, arg1, arg2, ...)` and `T(key, namedArgs)` route through **`MessageFormatter`** so
placeholders like `{0}` and `{name}` are substituted and any `IFormattable` argument formats
through the current culture. `Tp(baseKey, count, ...)` selects the right plural form:

```csharp
string listing = Localizer.Current.Tp("cart.items", cart.Count);
```

## Plural forms

**`PluralRules`** classifies a count into a `PluralClass` — `Zero`, `One`, `Two`, `Few`,
`Many`, `Other` — per the language's CLDR-v45 rule family. The 30 canonical languages collapse
into eight families:

| Family | Members | Rule (integer / decimal `n`) |
|---|---|---|
| OtherOnly | ja, ko, zh, th, vi, id | Everything → Other |
| OneOtherIntegerV0 | en, de, nl, sv, da, no, fi, tr, hu, el, it, pt-PT, es, es-419 | `i=1 && v=0` → One, else Other |
| OneOtherIntegerZeroOne | fr, fr-CA, pt (plain), pt-BR | `i in 0..1` → One, else Other |
| Russian | ru, uk, be, sr, hr | Modulo-10/100 rules for One / Few / Many |
| Polish | pl | One for 1; Few for small integer sums; else Many |
| Czech | cs, sk | One for 1; Few for 2..4; else Other |
| Romanian | ro, mo | One for 1; Few for 0 or 1..19 mod 100; else Other |
| Arabic | ar | 0 → Zero, 1 → One, 2 → Two, 3..10 mod 100 → Few, 11..99 → Many, else Other |

Decimal counts use the same operand semantics: `Classify(tag, 1.5m)` on French returns `One`
(because `i=1`, no `v` constraint on that family); on English it returns `Other` (because the
visible fraction disqualifies the v=0 gate).

## Per-language number and date presentation

**`CultureFormatInfo`** carries the per-language separators, month and day names, AM/PM
strings — a baked CLDR-v45 snapshot with English as the fallback for languages whose data has
not been added yet. The cache is thread-safe (a lock guards concurrent `For` calls) so the
background thread's `IFormattable` render never races with the frame loop's own.

```csharp
CultureFormatInfo german = CultureFormatInfo.For(LanguageTag.Parse("de-DE"));
// german.DecimalSeparator == ",", german.MonthNames[0] == "Januar", ...
```

## Direction and Unicode bidirectional text

**`TextDirection`** enumerates `Ltr`, `Rtl` and `Auto`. `TextDirections.ForLanguage(tag)`
returns the language's paragraph direction; `TextDirections.Resolve(preferred, text, tag)`
turns `Auto` into `Ltr` or `Rtl` by scanning for the first strong-direction character in the
text and falling back to the language when none is present.

For a paragraph the interface actually lays out, **`BidiAlgorithm`** in
`SharpProspero.Globalization.Bidi` runs the full UAX #9 pipeline: rules P2/P3 (base direction),
X1..X8 (embedding and isolate stack), W1..W7 (weak types), N0 (paired brackets), N1..N2
(neutrals), I1..I2 (implicit levels), and L1..L2/L4 (reorder and mirror glyphs). The fast
`HasRightToLeft` check lets a caller skip the algorithm for a paragraph with no strong-RTL
characters.

```csharp
using SharpProspero.Globalization.Bidi;

string text = "Hello مرحبا World";
Span<byte> levels = stackalloc byte[text.Length];
Span<BidiRun> runs = stackalloc BidiRun[text.Length];
int runCount = BidiAlgorithm.Analyze(text, TextDirection.Auto, levels, runs);
// runs[0..runCount] hold contiguous stretches at one embedding level each.

Span<char> visualOrder = stackalloc char[text.Length];
int written = BidiAlgorithm.Reorder(text, TextDirection.Auto, visualOrder);
```

## Grapheme clusters and line breaks

`SharpProspero.Globalization.Text` carries the two Unicode iterators the layout uses:

- **`GraphemeIterator`** walks a string per UAX #29 and yields the start of each
  user-perceived grapheme: CR+LF as one, ZWJ emoji chains as one (a base pictograph joined by
  U+200D to a second base pictograph reads as one cluster), regional-indicator pairs as one
  flag, and Hangul syllable groups as one.
- **`LineBreaker`** walks a string per UAX #14 and yields every allowed break opportunity plus
  every mandatory break (BK, CR, LF, NL). Hyphens and en/em dashes allow break after; spaces
  allow break after (unless what follows is a close bracket, an exclamation, an interior
  separator, or a non-starter); zero-width space allows a break, non-breaking space and word
  joiner prohibit one; CJK ideographs break on either side; complex-script codepoints
  (Thai, Lao, Khmer, Myanmar) attach to themselves.

Both iterators are `ref struct`s that scan without allocating.

## Fonts and script routing

`ScriptClassifier` (in `SharpProspero.Globalization.Text`) routes a codepoint to a coarse
`FontScript` — Latin, Cyrillic, Greek, Arabic, Hebrew, Devanagari, Thai, CJK, Hangul, Kana,
ExtendedPictographic, Other — used by the font cascade to decide which tier owns the codepoint.
`ScriptClassifier.ResolveFontScriptLanguage(tag)` returns the on-device font engine's
`scriptCode` and `languageCode` pair for a language, so an Arabic tag routes to the Arabic
font set and a Traditional Chinese tag picks the right regional han variant.

**`FontCascade`** (in `SharpProspero.Globalization.Fonts`) is an `ITextFont` that walks a
paragraph in runs whose characters all resolve to the same tier, then asks each tier to
measure and draw its own run. A 16 K-entry **`FontCoverageProbe`** caches the coverage answers
so re-drawing the same paragraph is one probe per unique codepoint.

```csharp
using SharpProspero.Globalization.Fonts;

var cascade = new FontCascade(
    fontsInOrder: [latinFont, cjkFont, arabicFont],
    finalFallback: bitmapFallback);
theme.Font = cascade;
```

## Interface layout mirror

`UiTheme.Direction` reads `Culture.Current.Direction` on every access, so a language change
swaps the interface's layout on the next frame without touching any widget. Every
horizontal-orientation widget mirrors when the direction is right-to-left:

- Containers — `Row`, `Grid`, `SplitPanel` — place the first-added child at the reading-start
  side, which is the visual right in RTL. The last logical child still absorbs any rounding
  leftover so no gap opens at the far edge.
- Fill widgets — `Slider`, `ProgressBar` — grow the filled portion from the reading-start edge
  (visual right in RTL) toward the reading-end.
- Chevron widgets — `Stepper`, `OptionSelector` — swap the `<` / `>` glyphs so the arrow on
  the "smaller side" still visually points that way, and swap the label / value layout.
- Tab and item strips — `TabView`, `Carousel` — mirror the tab / tile positions so the strip
  flows in the same direction the language reads.
- Indicator widgets — `Checkbox`, `RadioGroup` — place the mark on the reading-start side of
  each row so the eye lands on the indicator first.
- Key / value rows — `KeyValueRow`, `TextBox` — swap the key/label and value sides so the pair
  reads name-then-value in both directions.
- Text alignment — `Button`, `Label`, `TextBlock` — pass `TextAlignment.Start` or `End` to
  align against the reading-start / reading-end edge; `Left`, `Center` and `Right` stay
  direction-independent.

Widget input semantics stay logical: `Left` always means "previous" (decrement, prior tab), and
`Right` always means "next" (increment, next tab). The physical layout mirrors; the muscle
memory does not. Cross-widget focus movement (`FocusNavigator`) chooses the neighbor by visual
coordinates, so `DPad-Right` always moves focus to the visually-right widget regardless of
direction.

## Reading a title's localized name

An installed application's `sce_sys/param.sfo` carries the default title at the `TITLE` key
and one localized variant per `TITLE_XX` key, where `XX` is the two-digit ordinal of a
`SystemLanguage` entry. **`LocalizedTitleReader`** (in
`SharpProspero.Globalization.Metadata`) reads the right value for a language and falls back
to the default when the localized slot is empty:

```csharp
using SharpProspero.Globalization.Metadata;
using SharpProspero.Storage.Sfo;

SfoFile? sfo = SfoFile.ReadFromFile("/app0/sce_sys/param.sfo");
if (sfo is not null)
{
    string localized = LocalizedTitleReader.Read(sfo, Culture.Current.Language);
}
```

`EnumerateLocalizedTitles(sfo)` returns every non-empty `TITLE_XX` value keyed by its
`SystemLanguage` — useful for a menu that lists every language the title advertises.

## On-screen keyboard languages

**`ImeLanguageMap`** turns a `LanguageTag` into the single-language bit the on-screen keyboard
takes in its `supportedLanguages` field. The bit layout does not match the `SystemLanguage`
ordinal order — Hungarian sits at bit 32 — so every accessor returns a `ulong`.

```csharp
ulong mask = ImeLanguageMap.ForLanguages(new[]
{
    LanguageTag.Parse("en-US"),
    LanguageTag.Parse("ar-AE"),
    LanguageTag.Parse("hu-HU"),
});
// Pass `mask` in SceImeDialogParam.supportedLanguages; zero defers to the console's own
// configured input languages, which is the usual choice for a general-purpose tool.
```

## Reading the account's preferred language

**`NpAccount`** (in `SharpProspero.Interop.Np`) exposes the account-language and
account-country reads through `libSceNpCommon`. `TryGetAccountLanguage(userId, timeoutSeconds,
out tag)` wraps the asynchronous `sceNpGetAccountLanguage2` request in a bounded busy-wait so
a caller can ask for the signed-in user's preferred language without owning the request loop.

```csharp
using SharpProspero.Interop.Np;

if (NpAccount.TryGetAccountLanguage(userId, timeoutSeconds: 3.0, out LanguageTag tag))
{
    Culture.SetCurrent(new Culture(tag, DateFormat.YearMonthDay, TimeFormat.TwentyFourHour, 0, false));
}
```

`TryGetAccountCountry(userId, out country)` returns the ISO 3166-1 two-letter country the
account is registered against.

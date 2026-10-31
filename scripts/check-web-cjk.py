#!/usr/bin/env python3
"""Checks the statically-exported web UI (`web/out`) HTML for leaked CJK text.

This fork's core property, and what distinguishes it, is "no non-English text
leaks into the user-facing screen" (originally a zero-hanzi invariant on the
`out` HTML for the Korean edition; widened here to zero-hanzi-and-zero-hangul
now that ARTEX-MUTANT is English-only). Leaving that to manual review alone
means a contributor's hardcoded foreign-language string, or a missing
translation, can regress silently until someone happens to notice it by eye.
This script blocks that regression at the merge gate.

How it checks
--------------
It scans the **raw content** of every `.html` file under `web/out` (not just
the rendered markup, but inline scripts and React Server Components flight
data too) for any CJK character and exits 1 if it finds one. It looks at the
raw content because user-visible text also travels inside flight data
(JSON-shaped strings) embedded in the HTML - stripping tags first would miss
a leak that takes that path.

Out of scope (an honest limitation)
------------------------------------
This gate only looks at the static export's output, so it cannot check
**what the browser renders at runtime in MOCK mode** (`NEXT_PUBLIC_MOCK=1`,
the mode the public demo uses). `web/src/lib/mock/data.ts`/`handler.ts` and
each page's hardcoded sample data are fetched via `mockHandle()` and rendered
into React state by a post-hydration `useEffect`, so they only ever land in
the runtime JS bundle, never in the `out` HTML. Foreign-language text that
enters through that path passes this gate (the public demo's `/system/logs`
sample log once carried leftover Chinese exactly this way, silently, until it
was fixed - see the repository's own commit history for that incident).

That surface is guarded by source review instead. Any CJK character still
present in a rendered file (`.tsx` under `web/src`, or its client-side data)
must be one of: a code comment, an i18n fallback gated by `t.has(...)` that's
never actually reached, a backend wire-format token (a chat-mention
classification label, the `[모델]`/`[模型]` decision-source sentinel), a
locale-gated literal that only shows when locale is `ko`/`zh`, or a mirror of
the agent's own brain (section [A]) prompts, which are deliberately left
untranslated to preserve benchmarked performance. Anything outside those
categories that's simply foreign-language text visible on screen should be
translated to English.

Scope of detection
-------------------
- **Hangul (`가-힣` etc.) is now also flagged**, not allowed - ARTEX-MUTANT
  dropped the Korean UI along with the other non-English locales, so Hangul
  leaking into the UI is exactly the same class of regression this gate
  already caught for hanzi. Detects the Hangul syllable block (U+AC00-D7A3)
  and Hangul Jamo (U+1100-11FF, U+3130-318F).
- **Only Han (CJK ideograph) characters are flagged** for the Chinese side:
  Unified + Extension A (U+3400-U+9FFF), Compatibility Ideographs
  (U+F900-U+FAFF), and Extension B and above in the supplementary plane
  (U+20000-). Kana and full-width punctuation are not "Han" and aren't this
  gate's concern (scope is kept to Han specifically to avoid false positives
  from preserved-original code blocks or quoted evidence).

Intentional CJK that needs preserving
---------------------------------------
`out` HTML currently has zero CJK characters, so the allowlist below is
empty. If a future case needs to deliberately keep original-language text on
screen for performance preservation (e.g. a language switcher's native-name
label), add that character to `ALLOWED_CJK` below with a comment explaining
why - that keeps the gate strict while narrowly admitting only the intended
exception.

Standard library only, no network access.
Run: `python3 -I scripts/check-web-cjk.py [out directory]`
(default is `web/out` at the repository root. CI calls it from the `web`
working directory as `python3 -I ../scripts/check-web-cjk.py`.)
"""
import os
import re
import subprocess
import sys

# CJK Han ideograph blocks (Extension A + Unified U+3400-U+9FFF, Compatibility
# Ideographs U+F900-U+FAFF, supplementary-plane Extension B+ U+20000-U+2FFFF)
# plus the Hangul syllable and Jamo blocks. Kana and full-width punctuation
# are intentionally excluded (see the module docstring).
HAN = re.compile(
    r"[㐀-鿿豈-﫿\U00020000-\U0002ffff"
    r"가-힣ᄀ-ᇿ㄰-㆏]"
)

# Characters deliberately left on screen (e.g. a language switcher's native
# name label). Empty means any match here fails the gate. Add an entry with
# the character and the reason when a genuine exception is needed.
# e.g. ALLOWED_CJK = {"中", "文"}  # language-switcher '中文' label (for comparison against upstream)
ALLOWED_CJK: set = set()


def find_out_dir() -> str:
    """Determines which `out` directory to check.

    Uses the argument path if given, otherwise `web/out` at the git
    repository root.
    """
    if len(sys.argv) > 1:
        return os.path.abspath(sys.argv[1])
    root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True
    ).strip()
    return os.path.join(root, "web", "out")


def main() -> int:
    out_dir = find_out_dir()
    if not os.path.isdir(out_dir):
        print(
            f"Error: nothing to check - {out_dir} does not exist\n"
            "Run `npm run build:static` first to produce the static export."
        )
        return 2

    checked = 0
    offenders = []  # (relative path, character count, preview)
    for dirpath, _dirnames, filenames in os.walk(out_dir):
        for name in filenames:
            if not name.endswith(".html"):
                continue
            checked += 1
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            found = [ch for ch in HAN.findall(text) if ch not in ALLOWED_CJK]
            if found:
                rel = os.path.relpath(path, out_dir)
                kinds = "".join(sorted(set(found)))
                offenders.append((rel, len(found), kinds))

    print(f"Checked {checked} HTML file(s) under {out_dir}")
    if offenders:
        print(f"CJK leak in {len(offenders)} file(s) - user-facing HTML contains CJK text:")
        for rel, count, kinds in offenders:
            preview = kinds if len(kinds) <= 30 else kinds[:30] + "…"
            print(f"  out/{rel}: {count} character(s) - {preview}")
        print(
            "\nTranslate to English, or if this is genuinely intentional CJK that "
            "must be preserved, add it to ALLOWED_CJK in scripts/check-web-cjk.py "
            "with a reason."
        )
        return 1
    if checked == 0:
        print("Warning: no HTML files were checked - verify the build actually produced output.")
        return 2
    print("No CJK leak - user-facing HTML contains no CJK text.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

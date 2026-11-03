#!/usr/bin/env python3
"""Check whether the external (http/https) links that tracked Markdown docs
point to are still alive.

The sibling script `check-doc-links.py` only checks internal links/anchors
within the repository and deliberately skips external URLs (network-
dependent, so flaky - not something the merge gate should cover). This
script owns that separate check. External links that the top of the
README, the defense guide, and the detections README point readers and
defenders at ("go here") - incident-reporting contacts (boho.or.kr,
privacy.go.kr, pipc.go.kr, fsec.or.kr), CISA KEV, OWASP/SigmaHQ/
Suricata/MITRE/MISP, the original demo (artex-demo.vercel.app), GitHub
badges, etc. - can silently rot (moved, renamed, taken down), and this
catches that periodically and manually.

How URLs to check are chosen
- Every tracked `.md` file is scanned, but URLs inside a fenced code block
  (``` or ~~~) or an inline code span (`` `...` ``) are skipped - those are
  command examples, config values, or a quoted external asset (e.g.
  `id.redhaze.top` in the side-question verification doc), not "a reference
  link the reader is meant to follow."
- http/https URLs are collected from Markdown links/images
  (`[text](url)` / `![alt](url)`), autolinks (`<url>`), and bare URLs left
  in the remaining prose.
- Reserved/placeholder hosts are excluded: localhost, private/loopback IPs
  (127., 10., 192.168., 169.254., 172.16-31., 0.0.0.0, ::1), RFC 2606/6761
  reserved names (example.com/org/net/edu, `*.example.*`, `.test`,
  `.invalid`, `.local`, `.tld`), and bare names that aren't an FQDN at all
  (e.g. `target`).

How "still alive" is checked (MAINTAINING.md 8.2's lesson, in code form)
Domestic public-sector/security-agency sites often reject HEAD requests and
a default User-Agent, or redirect several times, so a naive check mistakes
a perfectly fine link for a dead one. So this script checks **with a
browser User-Agent, via GET, following redirects**. Status falls into one
of three buckets:
- OK: final status is 2xx/3xx. The link is valid.
- RESTRICTED: 401/403/405/429. The host is alive - the check method itself
  is just blocked by the server's own access policy (bot blocking, method
  rejection, rate limiting), not a broken link. Reported, but not counted
  as a failure.
- DOWN: 404/410/5xx (even after retrying)/DNS/connection/timeout/SSL error
  (even after retrying). Likely actually broken.

Network errors, 5xx and 429 are retried with a short delay to tell a
transient blip from a real outage apart. Standard library only. This script
only sends a GET to confirm liveness of reference URLs the repository's
**own public docs already point at** - it never scans or probes any target.

Known exceptions (allowlist)
A URL listed in `scripts/external-links-allowlist.txt` that comes back DOWN
is classified separately as "ALLOWED" and excluded from the strict exit
code. This transparently records a dead link inherited from an upstream-
preserved file (e.g. upstream's CHANGELOG.zh.md) that we don't own and
can't fix, so the periodic strict check doesn't stay permanently red over
that one entry - it only goes red when a **newly** broken link shows up.

Usage
- Default (report, exit code 0): `python3 -I scripts/check-external-links.py`
- Periodic/release check, not a merge gate (red if anything newly broke):
  `--strict` (exit code 1 if any DOWN URL isn't on the allowlist).
  RESTRICTED/ALLOWED never count as a failure, even under --strict.
- Preview the extracted URL set with no network calls: `--list` (prints
  each checkable URL and where it came from, without probing it).
"""
import argparse
import http.client
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from urllib.parse import urlsplit

# [text](url) body links (not images) and ![alt](url) images. The path runs
# up to whitespace or the closing paren.
MD_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)")
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)")
# <https://...> autolinks.
AUTOLINK = re.compile(r"<(https?://[^>\s]+)>")
# Bare URLs left in prose. Trailing punctuation is stripped afterward.
BARE_URL = re.compile(r"https?://[^\s)>\]\"'`]+")
# Inline code spans `...` (single backtick). Blanked out before extraction.
INLINE_CODE = re.compile(r"`[^`]*`")
# Punctuation commonly stuck to the end of a prose URL.
TRAILING_PUNCT = ".,;:!?\"'»)]}>"

# IPv4 private/loopback/link-local ranges (172.16-31. is its own pattern).
PRIVATE_IPV4 = re.compile(r"^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0$)")
PRIVATE_IPV4_172 = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
)

# Host is alive, but the check method itself is blocked by server policy (not broken).
RESTRICTED_CODES = {401, 403, 405, 429}

ALLOWLIST_PATH = os.path.join("scripts", "external-links-allowlist.txt")


def load_allowlist(root: str) -> set:
    """Read the set of known-DOWN URLs we can't fix (empty set if absent).

    One URL per line. Anything after `#` is a comment; blank/comment-only
    lines are ignored.
    """
    path = os.path.join(root, ALLOWLIST_PATH)
    allow = set()
    if not os.path.exists(path):
        return allow
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                allow.add(line)
    return allow


def strip_code(line: str) -> str:
    """Blank out inline code spans in a line outside a fence (a URL in one isn't a reference)."""
    return INLINE_CODE.sub(" ", line)


def is_checkable(url: str) -> bool:
    """Filter out reserved/placeholder hosts, keeping only real external URLs worth checking."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = parts.hostname
    if not host:
        return False
    host = host.lower()
    if host == "localhost" or host.endswith(".localhost"):
        return False
    if host == "::1":
        return False
    if PRIVATE_IPV4.match(host) or PRIVATE_IPV4_172.match(host):
        return False
    if host in ("example.com", "example.org", "example.net", "example.edu"):
        return False
    if host.endswith((".example.com", ".example.org", ".example.net", ".example")):
        return False
    if host.endswith((".test", ".invalid", ".local", ".localdomain", ".tld")):
        return False
    if "." not in host:  # a bare name that isn't an FQDN (e.g. target)
        return False
    return True


def extract(root: str, md_files: list) -> dict:
    """Build a dict of external URL to check -> [(file, line number), ...] from tracked .md files."""
    found = defaultdict(list)
    for md in md_files:
        with open(os.path.join(root, md), encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        in_fence = False
        for lineno, raw in enumerate(lines, 1):
            stripped = raw.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            line = strip_code(raw)
            candidates = []
            for pattern in (MD_LINK, MD_IMAGE, AUTOLINK):
                candidates.extend(m.group(1) for m in pattern.finditer(line))
            for m in BARE_URL.finditer(line):
                candidates.append(m.group(0).rstrip(TRAILING_PUNCT))
            for url in candidates:
                url = url.strip().rstrip(TRAILING_PUNCT)
                if is_checkable(url):
                    where = (md, lineno)
                    if where not in found[url]:
                        found[url].append(where)
    return found


def probe(url: str, timeout: float, retries: int, delay: float):
    """Send a GET with a browser UA to url and return (verdict, detail).

    verdict is one of "OK", "RESTRICTED", "DOWN". Network errors, 5xx and
    429 are retried.
    """
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": BROWSER_UA,
            "Accept": "*/*",
            "Accept-Language": "en,ko;q=0.8",
        },
    )
    last = ""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = resp.getcode()
                if code in RESTRICTED_CODES:
                    return "RESTRICTED", f"HTTP {code}"
                return "OK", f"HTTP {code}"
        except urllib.error.HTTPError as exc:
            code = exc.code
            if code in RESTRICTED_CODES:
                return "RESTRICTED", f"HTTP {code}"
            if code >= 500 or code == 408:
                last = f"HTTP {code}"  # may be transient, retry
            else:
                return "DOWN", f"HTTP {code}"  # 404/410 etc. are final, no retry needed
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            ssl.SSLError,
            socket.timeout,
            ConnectionError,
            TimeoutError,
            OSError,
        ) as exc:
            reason = getattr(exc, "reason", exc)
            last = f"{type(exc).__name__}: {reason}"
        if attempt < retries:
            time.sleep(delay * (attempt + 1))
    return "DOWN", last


def main() -> int:
    ap = argparse.ArgumentParser(description="Check external links in tracked Markdown for liveness")
    ap.add_argument("--strict", action="store_true",
                    help="exit code 1 if any URL is DOWN (for periodic/release checks)")
    ap.add_argument("--list", action="store_true",
                    help="print the URLs to check and where they're from, with no network calls")
    ap.add_argument("--timeout", type=float, default=15.0, help="request timeout (seconds)")
    ap.add_argument("--retries", type=int, default=2, help="retries for network errors/5xx/429")
    ap.add_argument("--delay", type=float, default=0.5, help="base delay between calls/retries (seconds)")
    args = ap.parse_args()

    root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True
    ).strip()
    tracked = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
    md_files = [f for f in tracked if f.endswith(".md")]

    allow = load_allowlist(root)
    found = extract(root, md_files)
    urls = sorted(found)
    print(f"Collected {len(urls)} external URL(s) to check from {len(md_files)} tracked Markdown file(s)")

    if args.list:
        for url in urls:
            where = ", ".join(f"{f}:{ln}" for f, ln in found[url])
            tag = " [allowlist]" if url in allow else ""
            print(f"  {url}{tag}  ({where})")
        return 0

    results = {"OK": [], "RESTRICTED": [], "ALLOWED": [], "DOWN": []}
    for i, url in enumerate(urls):
        if i:
            time.sleep(args.delay)  # small delay between calls (avoids tripping sandbox rate limits)
        verdict, detail = probe(url, args.timeout, args.retries, args.delay)
        if verdict == "DOWN" and url in allow:
            verdict = "ALLOWED"  # known, unfixable upstream-inherited DOWN
        results[verdict].append((url, detail))
        print(f"  [{verdict:10}] {url} — {detail}")

    print(
        f"\nSummary: OK {len(results['OK'])} · RESTRICTED {len(results['RESTRICTED'])} · "
        f"ALLOWED {len(results['ALLOWED'])} · DOWN {len(results['DOWN'])}"
    )
    if results["RESTRICTED"]:
        print("RESTRICTED (host is alive, check method is blocked - not a broken link):")
        for url, detail in results["RESTRICTED"]:
            print(f"  {url} — {detail}")
    if results["ALLOWED"]:
        print("ALLOWED (known DOWN on the allowlist - excluded from strict, we can't fix it):")
        for url, detail in results["ALLOWED"]:
            where = ", ".join(f"{f}:{ln}" for f, ln in found[url])
            print(f"  {url} — {detail}  (referenced: {where})")
    if results["DOWN"]:
        print("DOWN (likely actually broken - needs checking):")
        for url, detail in results["DOWN"]:
            where = ", ".join(f"{f}:{ln}" for f, ln in found[url])
            print(f"  {url} — {detail}  (referenced: {where})")

    if args.strict and results["DOWN"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

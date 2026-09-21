#!/usr/bin/env python3
"""
GeoServer version checker.

Produces versions.json describing all recently active GeoServer release
series, cross-referencing two sources:

  1. GitHub Releases (api.github.com) - fastest signal that a version
     exists, but carries no reliable vulnerability information beyond
     the coincidence of multiple series releasing at once.
  2. geoserver.org blog posts (raw.githubusercontent.com/geoserver/
     geoserver.github.io, _posts/*.md) - authoritative for security
     content: frontmatter categories include "Vulnerability" and the
     body lists GEOS-xxxx / CVE-xxxx-xxxxx identifiers under a
     "Security Considerations" heading.

Design notes:
  - All HTTP requests are unauthenticated. No token is used, no
    identifying User-Agent beyond a generic project string, so GitHub's
    access logs cannot associate requests with any particular
    organisation. This script is intended to run on GitHub Actions'
    own runners, so from GitHub's point of view the traffic originates
    from GitHub infrastructure, not from any requester-identifiable
    network.
  - This script only ever reads public release/blog data. It has
    nothing to do with the (separate, opt-in, not-yet-built) mechanism
    for instances to self-report their running version.
  - Output is intentionally conservative: if blog confirmation for a
    version is not yet available, the release is still listed with
    security_confirmed: false rather than omitted, so a client never
    silently misses a security release just because the blog post
    lagged behind GitHub.
"""

import json
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

GITHUB_API = "https://api.github.com/repos/geoserver/geoserver/releases?per_page=40"
GITHUB_ADVISORIES = "https://api.github.com/repos/geoserver/geoserver/security-advisories?per_page=40"
BLOG_POSTS_API = "https://api.github.com/repos/geoserver/geoserver.github.io/contents/_posts"
RAW_POST_BASE = "https://raw.githubusercontent.com/geoserver/geoserver.github.io/main/_posts/"

USER_AGENT = "geoserver-version-checker/1.0 (+https://geoserver.org)"
SCRIPT_DIR = Path(__file__).parent
SERIES_CONFIG = SCRIPT_DIR / "series.json"
OUTPUT_PATH = SCRIPT_DIR.parent / "versions.json"

# Only look at posts from the last N days when scanning the blog index,
# to keep each run fast. Cross-checked against GitHub releases which
# only report versions anyway, so this never causes a real release to
# be missed - it just limits how far back we search for the matching post.
BLOG_LOOKBACK_DAYS = 240

VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(-RC\d*)?$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
GEOS_RE = re.compile(r"GEOS-\d+")


def http_get_json(url, retries=3, backoff=2.0):
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    })
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 403 and "rate limit" in e.read().decode("utf-8", "ignore").lower():
                raise RuntimeError(
                    "GitHub rate limit hit on unauthenticated request. "
                    "This script deliberately runs unauthenticated for "
                    "privacy reasons; if this becomes a persistent problem, "
                    "reduce poll frequency rather than adding a token."
                )
            if attempt == retries - 1:
                raise
            time.sleep(backoff * (attempt + 1))
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
            time.sleep(backoff * (attempt + 1))
    return None


def http_get_text(url, retries=3, backoff=2.0):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if attempt == retries - 1:
                raise
            time.sleep(backoff * (attempt + 1))
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
            time.sleep(backoff * (attempt + 1))
    return None


def parse_version_tag(tag):
    """Normalize a GitHub release tag to (series, version, is_rc)."""
    tag = tag.lstrip("v")
    m = VERSION_RE.match(tag)
    if not m:
        return None
    major, minor, patch, rc = m.groups()
    series = f"{major}.{minor}.x"
    version = tag
    return series, version, bool(rc)


def fetch_github_releases():
    """Fastest source: what versions exist right now, and when."""
    data = http_get_json(GITHUB_API)
    releases = []
    for r in data:
        if r.get("draft"):
            continue
        parsed = parse_version_tag(r["tag_name"])
        if not parsed:
            continue
        series, version, is_rc = parsed
        releases.append({
            "series": series,
            "version": version,
            "is_rc": is_rc,
            "published_at": r.get("published_at"),
            "release_url": r.get("html_url"),
            "prerelease": r.get("prerelease", False),
        })
    return releases


def fetch_github_advisories():
    """Cross-check source for CVE IDs, independent of blog post timing."""
    try:
        data = http_get_json(GITHUB_ADVISORIES)
    except Exception:
        return []
    advisories = []
    for a in data or []:
        advisories.append({
            "ghsa_id": a.get("ghsa_id"),
            "cve_id": a.get("cve_id"),
            "summary": a.get("summary"),
            "severity": a.get("severity"),
            "published_at": a.get("published_at"),
            "vulnerable_versions": [
                v.get("vulnerable_version_range")
                for v in a.get("vulnerabilities", []) or []
            ],
        })
    return advisories


def fetch_blog_post_index():
    """List recent _posts filenames without downloading every post body."""
    listing = http_get_json(BLOG_POSTS_API)
    cutoff = time.time() - BLOG_LOOKBACK_DAYS * 86400
    names = []
    for entry in listing:
        name = entry.get("name", "")
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})-.*\.md$", name)
        if not m:
            continue
        try:
            post_date = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
        except ValueError:
            continue
        if post_date.timestamp() >= cutoff:
            names.append(name)
    return names


def parse_frontmatter(md_text):
    """Very small YAML-frontmatter parser, good enough for this fixed schema."""
    if not md_text.startswith("---"):
        return {}, md_text
    parts = md_text.split("---", 2)
    if len(parts) < 3:
        return {}, md_text
    raw_fm, body = parts[1], parts[2]
    fm = {}
    categories = []
    in_categories = False
    for line in raw_fm.splitlines():
        stripped = line.strip()
        if stripped.startswith("categories:"):
            in_categories = True
            continue
        if in_categories:
            if stripped.startswith("- "):
                categories.append(stripped[2:].strip())
                continue
            else:
                in_categories = False
        if ":" in stripped and not stripped.startswith("-"):
            key, _, val = stripped.partition(":")
            fm[key.strip()] = val.strip().strip('"')
    if categories:
        fm["categories"] = categories
    return fm, body


def match_blog_post_for_version(version, post_names):
    """geoserver-X-Y-Z-released.md naming convention."""
    dotted = version.replace(".", "-").lower()
    candidates = [n for n in post_names if f"geoserver-{dotted}-released" in n.lower()]
    return candidates[0] if candidates else None


def extract_security_info(body):
    cves = sorted(set(CVE_RE.findall(body)))
    geos_ids = sorted(set(GEOS_RE.findall(body)))
    has_section = "Security Considerations" in body
    return {
        "cve_ids": cves,
        "geos_ids": geos_ids,
        "has_security_section": has_section,
    }


def load_series_config():
    with open(SERIES_CONFIG) as f:
        return json.load(f)["series"]


def build_blog_url(post_filename, categories, frontmatter):
    """
    Reconstruct the public geoserver.org URL for a _posts/YYYY-MM-DD-slug.md
    file. Jekyll's URL scheme is /<category-path>/<year>/<month>/<day>/<slug>.html,
    with categories lowercased and joined by '/'. We saw both plain
    "announcements" posts and "announcements/vulnerability" posts in the
    wild, so use whatever categories the post itself declares (falling back
    to "announcements" if none are usable) rather than hardcoding one path.
    """
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})-(.+)\.md$", post_filename)
    if not m:
        return None
    year, month, day, slug = m.groups()
    usable_categories = [c for c in categories if c not in ("release",)] or ["announcements"]
    category_path = "/".join(c.lower() for c in usable_categories)
    return f"https://geoserver.org/{category_path}/{year}/{month}/{day}/{slug}.html"


def series_status_for(series_id, series_config):
    for s in series_config:
        if s["series"] == series_id:
            return s["status"], s.get("eol")
    return "unknown", None


def build_report():
    releases = fetch_github_releases()
    advisories = fetch_github_advisories()
    post_names = fetch_blog_post_index()
    series_config = load_series_config()

    # group by series -> list of releases, to detect simultaneous
    # multi-series releases (same published date/day across series)
    by_date = {}
    for r in releases:
        day = (r["published_at"] or "")[:10]
        by_date.setdefault(day, []).append(r["series"])

    cve_by_version_hint = {}
    for adv in advisories:
        for vr in adv["vulnerable_versions"]:
            if vr:
                cve_by_version_hint.setdefault(vr, []).append(adv["cve_id"])

    versions_out = []
    for r in releases:
        day = (r["published_at"] or "")[:10]
        coordinated = len(set(by_date.get(day, []))) > 1

        post_name = match_blog_post_for_version(r["version"], post_names)
        security = {
            "cve_ids": [],
            "geos_ids": [],
            "has_security_section": False,
        }
        blog_url = None
        blog_confirmed = False

        if post_name:
            raw = http_get_text(RAW_POST_BASE + post_name)
            if raw:
                fm, body = parse_frontmatter(raw)
                security = extract_security_info(body)
                categories = [c.lower() for c in fm.get("categories", [])]
                if "vulnerability" in categories:
                    security["has_security_section"] = True
                blog_confirmed = True
                blog_url = build_blog_url(post_name, categories, fm)

        status, eol = series_status_for(r["series"], series_config)

        versions_out.append({
            "series": r["series"],
            "version": r["version"],
            "is_release_candidate": r["is_rc"],
            "series_status": status,
            "series_eol": eol,
            "published_at": r["published_at"],
            "release_url": r["release_url"],
            "blog_confirmed": blog_confirmed,
            "blog_url": blog_url,
            "security": {
                "flagged": security["has_security_section"] or bool(security["cve_ids"]),
                "cve_ids": security["cve_ids"],
                "geos_ids": security["geos_ids"],
                "pending_blog_confirmation": not blog_confirmed,
            },
            "probable_coordinated_security_release": coordinated,
        })

    versions_out.sort(key=lambda v: v["published_at"] or "", reverse=True)

    latest_per_series = {}
    for v in versions_out:
        if v["is_release_candidate"]:
            continue
        s = v["series"]
        if s not in latest_per_series or v["published_at"] > latest_per_series[s]["published_at"]:
            latest_per_series[s] = v

    report = {
        "schema_version": 1,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_note": (
            "Generated by an unauthenticated, anonymous checker run on GitHub "
            "Actions infrastructure. No requester identity is logged by this "
            "process; GitHub release and blog data are both public. This feed "
            "has no connection to any per-instance version reporting mechanism."
        ),
        "latest_by_series": {
            s: {"version": v["version"], "published_at": v["published_at"]}
            for s, v in latest_per_series.items()
        },
        "versions": versions_out,
        "advisories": advisories,
    }
    return report


def main():
    try:
        report = build_report()
    except Exception as e:
        print(f"ERROR: version check failed: {e}", file=sys.stderr)
        sys.exit(1)

    OUTPUT_PATH.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Wrote {OUTPUT_PATH} with {len(report['versions'])} version entries "
          f"across {len(report['latest_by_series'])} series.")


if __name__ == "__main__":
    main()

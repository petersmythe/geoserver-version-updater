#!/usr/bin/env python3
"""
GeoServer version feed generator (schema v1).

Reads public GeoServer release, security-advisory and blog data and writes
versions.json: one entry per release series (with an inferred lifecycle phase)
plus the published security advisories.

All requests are unauthenticated and use a generic User-Agent. The script runs
on GitHub-hosted runners and has no dependency beyond the Python standard
library.

Phase inference (no configuration file):
  1. Group proper releases into events: releases within 24 hours of the
     earliest release in the group.
  2. The most recent event containing two or more series is the coordinated
     event. Its N distinct series are the maintained set.
  3. Series newer than anything in that set (for example a new series released
     on its own) join the pool. The top N of the pool by version are active:
     the highest is "stable", the rest "maintenance". Every other series is
     "archive". A new series therefore displaces the oldest maintained one.
  4. With no coordinated event at all: highest = stable, next = maintenance,
     the rest archive.
"""

import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple

GITHUB_RELEASES = "https://api.github.com/repos/geoserver/geoserver/releases?per_page=100"
GITHUB_ADVISORIES = "https://api.github.com/repos/geoserver/geoserver/security-advisories?per_page=100"
BLOG_POSTS_API = "https://api.github.com/repos/geoserver/geoserver.github.io/contents/_posts"
RAW_POST_BASE = "https://raw.githubusercontent.com/geoserver/geoserver.github.io/main/_posts/"

USER_AGENT = "gs-updates-checker-feed"
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "versions.json"

SCHEMA_VERSION = 1
COORDINATION_WINDOW = timedelta(hours=24)
BLOG_LOOKBACK_DAYS = 240
MAX_ADVISORY_PAGES = 3

RELEASE_TAG_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
PATCHED_TOKEN_RE = re.compile(r"(?<![\d.])(\d+)\.(\d+)\.(\d+)(?![\d.])")
VERSION_IN_RANGE_RE = re.compile(r"\d+\.\d+")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Release(NamedTuple):
    version: str
    major: int
    minor: int
    patch: int
    published: datetime
    published_at: str
    url: str

    @property
    def series(self):
        return (self.major, self.minor)


def series_name(series):
    return f"{series[0]}.{series[1]}.x"


def parse_timestamp(value):
    return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)


def parse_release(raw):
    """A proper release only: MAJOR.MINOR.PATCH, not a draft. RCs, milestones and
    four-part tags such as 2.7.1.1 are ignored."""
    if raw.get("draft") or not raw.get("published_at"):
        return None
    match = RELEASE_TAG_RE.match(raw.get("tag_name", ""))
    if not match:
        return None
    major, minor, patch = (int(g) for g in match.groups())
    return Release(
        version=f"{major}.{minor}.{patch}",
        major=major,
        minor=minor,
        patch=patch,
        published=parse_timestamp(raw["published_at"]),
        published_at=raw["published_at"],
        url=raw.get("html_url") or "",
    )


def cluster_releases(releases):
    """Group releases into events. A window opens at its earliest release and
    takes every release within COORDINATION_WINDOW of it."""
    clusters = []
    current = []
    for release in sorted(releases, key=lambda r: r.published):
        if current and release.published - current[0].published > COORDINATION_WINDOW:
            clusters.append(current)
            current = []
        current.append(release)
    if current:
        clusters.append(current)
    return clusters


def is_coordinated(cluster):
    return len({r.series for r in cluster}) >= 2


def infer_phases(releases):
    """Return {series tuple: phase}."""
    all_series = {r.series for r in releases}
    if not all_series:
        return {}
    coordinated = [c for c in cluster_releases(releases) if is_coordinated(c)]
    if coordinated:
        members = {r.series for r in coordinated[-1]}
        size = len(members)
        pool = members | {s for s in all_series if s > max(members)}
    else:
        size = 2
        pool = all_series
    active = sorted(pool, reverse=True)[:size]
    phases = {}
    for series in all_series:
        if series not in active:
            phases[series] = "archive"
        elif series == active[0]:
            phases[series] = "stable"
        else:
            phases[series] = "maintenance"
    return phases


def synchronized_versions(releases):
    """Versions that were released inside any coordinated event."""
    result = set()
    for cluster in cluster_releases(releases):
        if is_coordinated(cluster):
            result.update(r.version for r in cluster)
    return result


def latest_per_series(releases):
    latest = {}
    for release in releases:
        current = latest.get(release.series)
        if current is None or release.patch > current.patch:
            latest[release.series] = release
    return latest


def derive_patched_versions(vulnerabilities):
    """Map series to the lowest patched version found across all entries."""
    best = {}
    for vulnerability in vulnerabilities or []:
        for match in PATCHED_TOKEN_RE.finditer(vulnerability.get("patched_versions") or ""):
            version = tuple(int(g) for g in match.groups())
            series = version[:2]
            if series not in best or version < best[series]:
                best[series] = version
    return {
        series_name(series): ".".join(str(part) for part in version)
        for series, version in sorted(best.items(), reverse=True)
    }


def transform_advisory(raw):
    ranges = []
    for vulnerability in raw.get("vulnerabilities") or []:
        version_range = vulnerability.get("vulnerable_version_range")
        if version_range and version_range not in ranges:
            ranges.append(version_range)
    return {
        "ghsa_id": raw.get("ghsa_id"),
        "cve_id": raw.get("cve_id"),
        "summary": raw.get("summary"),
        "severity": (raw.get("severity") or "unknown").lower(),
        "published_at": raw.get("published_at"),
        "vulnerable_versions": ranges,
        "patched_versions": derive_patched_versions(raw.get("vulnerabilities")),
    }


def applies_to_releases(advisory):
    """False when every range is something other than a version (for example a
    commit hash in the project's own CI): it can never match a running release.
    An advisory with no ranges at all is kept, so a human can review it."""
    ranges = advisory["vulnerable_versions"]
    return not ranges or any(VERSION_IN_RANGE_RE.search(r) for r in ranges)


def transform_advisories(raw_advisories):
    advisories = [transform_advisory(a) for a in raw_advisories]
    advisories = [a for a in advisories if applies_to_releases(a)]
    advisories.sort(key=lambda a: a["ghsa_id"] or "")
    advisories.sort(key=lambda a: a["published_at"] or "", reverse=True)
    return advisories


def build_series_entries(releases, blog_lookup, previous_entries):
    phases = infer_phases(releases)
    latest = latest_per_series(releases)
    synchronized = synchronized_versions(releases)
    previous = {(e["series"], e["latest_version"]): e for e in previous_entries}
    phase_order = {"stable": 0, "maintenance": 1, "archive": 2}

    entries = []
    for series in sorted(latest, key=lambda s: (phase_order[phases[s]], -s[0], -s[1])):
        release = latest[series]
        known = previous.get((series_name(series), release.version))
        if known and known.get("blog_confirmed"):
            blog = {key: known[key] for key in ("blog_confirmed", "blog_url", "security_flagged", "cve_ids")}
        else:
            blog = blog_lookup(release) or {
                "blog_confirmed": False,
                "blog_url": None,
                "security_flagged": False,
                "cve_ids": [],
            }
        entries.append(
            {
                "series": series_name(series),
                "phase": phases[series],
                "latest_version": release.version,
                "published_at": release.published_at,
                "release_url": release.url,
                "blog_confirmed": blog["blog_confirmed"],
                "blog_url": blog["blog_url"],
                "security_flagged": blog["security_flagged"],
                "synchronized_release": release.version in synchronized,
                "cve_ids": blog["cve_ids"],
            }
        )
    return entries


def build_feed(releases, raw_advisories, blog_lookup, previous, now):
    """previous is the prior feed (or None). `generated` only moves when the
    content changes, so an unchanged feed produces no commit."""
    previous_entries = (previous or {}).get("series") or []
    feed = {
        "schema_version": SCHEMA_VERSION,
        "generated": None,
        "series": build_series_entries(releases, blog_lookup, previous_entries),
        "advisories": transform_advisories(raw_advisories),
    }
    if previous and {k: v for k, v in previous.items() if k != "generated"} == {
        k: v for k, v in feed.items() if k != "generated"
    }:
        feed["generated"] = previous["generated"]
    else:
        feed["generated"] = now.strftime(TIMESTAMP_FORMAT)
    return feed


def http_get(url, accept, retries=3, backoff=2.0, allow_404=False):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            if allow_404 and error.code == 404:
                return None
            if error.code == 403 and "rate limit" in error.read().decode("utf-8", "ignore").lower():
                raise RuntimeError(
                    "GitHub rate limit hit on an unauthenticated request. The script is "
                    "deliberately unauthenticated; reduce the run frequency instead of adding a token."
                )
            if attempt == retries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
        time.sleep(backoff * (attempt + 1))
    return None


def http_get_json(url):
    return json.loads(http_get(url, "application/vnd.github+json"))


def fetch_releases():
    releases = []
    for raw in http_get_json(GITHUB_RELEASES):
        release = parse_release(raw)
        if release:
            releases.append(release)
    return releases


def fetch_raw_advisories():
    """Any failure aborts the run: a feed whose advisories silently vanished
    would stop warning every client."""
    advisories = []
    for page in range(1, MAX_ADVISORY_PAGES + 1):
        batch = http_get_json(f"{GITHUB_ADVISORIES}&page={page}")
        advisories.extend(batch)
        if len(batch) < 100:
            break
    return advisories


def parse_frontmatter(markdown):
    if not markdown.startswith("---"):
        return {}, markdown
    parts = markdown.split("---", 2)
    if len(parts) < 3:
        return {}, markdown
    categories = []
    in_categories = False
    for line in parts[1].splitlines():
        stripped = line.strip()
        if stripped.startswith("categories:"):
            in_categories = True
        elif in_categories and stripped.startswith("- "):
            categories.append(stripped[2:].strip().lower())
        elif in_categories:
            in_categories = False
    return {"categories": categories}, parts[2]


def build_blog_url(post_filename, categories):
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})-(.+)\.md$", post_filename)
    if not match:
        return None
    year, month, day, slug = match.groups()
    usable = [c for c in categories if c != "release"] or ["announcements"]
    return f"https://geoserver.org/{'/'.join(usable)}/{year}/{month}/{day}/{slug}.html"


class BlogLookup:
    """Finds the blog post for a release. The post index is fetched at most once
    per run, and only when a recent release has no confirmed post yet."""

    def __init__(self, now):
        self.now = now
        self.names = None

    def _index(self):
        if self.names is None:
            cutoff = self.now - timedelta(days=BLOG_LOOKBACK_DAYS)
            self.names = []
            for entry in http_get_json(BLOG_POSTS_API):
                name = entry.get("name", "")
                match = re.match(r"^(\d{4})-(\d{2})-(\d{2})-.*\.md$", name)
                if match:
                    posted = datetime(*(int(g) for g in match.groups()), tzinfo=timezone.utc)
                    if posted >= cutoff:
                        self.names.append(name)
        return self.names

    def __call__(self, release):
        if self.now - release.published > timedelta(days=BLOG_LOOKBACK_DAYS):
            return None
        needle = f"geoserver-{release.version.replace('.', '-')}-released"
        matches = [n for n in self._index() if needle in n.lower()]
        if not matches:
            return None
        body = http_get(RAW_POST_BASE + matches[0], "text/plain", allow_404=True)
        if body is None:
            return None
        frontmatter, text = parse_frontmatter(body)
        categories = frontmatter.get("categories", [])
        cve_ids = sorted(set(CVE_RE.findall(text)))
        return {
            "blog_confirmed": True,
            "blog_url": build_blog_url(matches[0], categories),
            "security_flagged": bool(
                cve_ids or "vulnerability" in categories or "Security Considerations" in text
            ),
            "cve_ids": cve_ids,
        }


def load_previous():
    if not OUTPUT_PATH.exists():
        return None
    try:
        previous = json.loads(OUTPUT_PATH.read_text())
    except ValueError:
        return None
    if previous.get("schema_version") != SCHEMA_VERSION or "series" not in previous:
        return None
    return previous


def main():
    now = datetime.now(timezone.utc)
    try:
        feed = build_feed(
            fetch_releases(), fetch_raw_advisories(), BlogLookup(now), load_previous(), now
        )
    except Exception as error:
        print(f"ERROR: version check failed: {error}", file=sys.stderr)
        sys.exit(1)

    text = json.dumps(feed, indent=2) + "\n"
    if not OUTPUT_PATH.exists() or OUTPUT_PATH.read_text() != text:
        OUTPUT_PATH.write_text(text)
    print(f"{len(feed['series'])} series, {len(feed['advisories'])} advisories, generated {feed['generated']}")


if __name__ == "__main__":
    main()

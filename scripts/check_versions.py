#!/usr/bin/env python3
"""
GeoServer version feed generator (schema v1).

Reads public GeoServer release, security-advisory and blog data and writes
versions.json: one entry per release series (with an inferred lifecycle phase)
plus the published security advisories.

The upstream data is untrusted. Every output object is built by copying only
allow-listed fields, every value is type- and format-checked (never coerced),
free text is cleaned to plain text, URLs are built rather than copied, and any
limit or validation failure fails the run so that nothing is published. The
output is checked again by scripts/validate_feed.py, which shares no code with
this file.

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

import html
import json
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple

GITHUB_RELEASES = "https://api.github.com/repos/geoserver/geoserver/releases?per_page=100"
GITHUB_ADVISORIES = "https://api.github.com/repos/geoserver/geoserver/security-advisories?per_page=100"
BLOG_POSTS_API = "https://api.github.com/repos/geoserver/geoserver.github.io/contents/_posts"
RAW_POST_BASE = "https://raw.githubusercontent.com/geoserver/geoserver.github.io/main/_posts/"
RELEASE_URL_BASE = "https://github.com/geoserver/geoserver/releases/tag/"

USER_AGENT = "gs-updates-checker-feed"
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "versions.json"

SCHEMA_VERSION = 1
SOURCE_NOTE = (
    "Generated from public GitHub data by an anonymous script on GitHub Actions. "
    "Served by the jsDelivr CDN. The GeoServer team does not run the feed host, "
    "receives no request logs, and cannot see which versions are being run."
)
COORDINATION_WINDOW = timedelta(hours=24)
BLOG_LOOKBACK_DAYS = 240
MAX_ADVISORY_PAGES = 3

MAX_SERIES = 100
MAX_ADVISORIES = 500
MAX_RANGES = 50
MAX_FILE_BYTES = 1024 * 1024
MAX_STRING = 2000
MAX_SUMMARY = 500
MAX_URL = 500
MAX_API_BYTES = 10 * 1024 * 1024
MAX_JSON_DEPTH = 20

SEVERITIES = ("critical", "high", "medium", "low")
URL_HOSTS = ("github.com", "geoserver.org", "cdn.jsdelivr.net")

RELEASE_TAG_RE = re.compile(r"v?([0-9]+)\.([0-9]+)\.([0-9]+)")
PATCHED_TOKEN_RE = re.compile(r"(?<![0-9.])([0-9]+)\.([0-9]+)\.([0-9]+)(?![0-9.])")
GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
CVE_FIND_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
RANGE_RE = re.compile(r"[0-9A-Za-z.<>=,~^ +\-]{1,200}")
RANGE_CLAUSE_RE = re.compile(r"\s*(?:<=|>=|<|>|=|~|\^)?\s*[0-9][0-9A-Za-z.+\-]*\s*")
HASH_RE = re.compile(r"[0-9a-fA-F]{7,64}")
TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
POST_NAME_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})-([a-z0-9-]+)\.md")
CATEGORY_RE = re.compile(r"[a-z0-9-]{1,40}")

_SPACE_LIKE = re.compile("[\t\n\r\v\f\x85  ]")
_MARKDOWN_LINK = re.compile(r"!?\[([^\]]*)\]\((?:[^()]|\([^()]*\))*\)")
_TAG = re.compile(r"<[^>]*>")
_SCHEME = re.compile(r"(javascript|vbscript|data)\s*:", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s+")
_UNSAFE_CATEGORIES = ("Cc", "Cf", "Cs", "Co")


class FeedError(Exception):
    """The run must fail and publish nothing. Messages never echo raw input."""


def safe_repr(value, limit=60):
    text = ascii(value)
    return text if len(text) <= limit else text[:limit] + "..."


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


def checked_timestamp(value, label):
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise FeedError(f"{label}: invalid timestamp {safe_repr(value)}")
    try:
        parse_timestamp(value)
    except ValueError:
        raise FeedError(f"{label}: not a real date {safe_repr(value)}")
    return value


# ---------------------------------------------------------------- strict JSON

def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FeedError("duplicate key in an API response")
        result[key] = value
    return result


def _reject_constant(name):
    raise FeedError("non-finite number in an API response")


def _checked_float(text):
    value = float(text)
    if value in (float("inf"), float("-inf")) or value != value:
        raise FeedError("non-finite number in an API response")
    return value


def _check_depth(data):
    stack = [(data, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise FeedError("an API response is nested too deeply")
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)


def parse_api_json(text):
    if len(text) > MAX_API_BYTES:
        raise FeedError("an API response is too large")
    try:
        data = json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_checked_float,
        )
    except RecursionError:
        raise FeedError("an API response is nested too deeply")
    except ValueError:
        raise FeedError("an API response is not valid JSON")
    _check_depth(data)
    return data


# ------------------------------------------------------------------ cleaning

def _remove_unsafe(text):
    return "".join(ch for ch in text if unicodedata.category(ch) not in _UNSAFE_CATEGORIES)


def _strip_tags(text):
    while True:
        stripped = _TAG.sub("", text)
        if stripped == text:
            return text
        text = stripped


def clean_text(value, max_len=MAX_STRING):
    """Reduce untrusted text to plain text: no control, line-separator, zero-width
    or bidirectional characters, no markup, no <, > or script-scheme text, NFC,
    single spaces, truncated to max_len characters."""
    if not isinstance(value, str):
        raise FeedError("a text field is not a string")
    text = _SPACE_LIKE.sub(" ", value)
    text = _remove_unsafe(text)
    text = unicodedata.normalize("NFC", text)
    text = _MARKDOWN_LINK.sub(r"\1", text)
    text = text.replace("`", "").replace("**", "").replace("~~", "")
    text = _strip_tags(text)
    text = html.unescape(text)
    text = _SPACE_LIKE.sub(" ", text)
    text = _remove_unsafe(text)
    text = _strip_tags(text)
    text = text.replace("<", "").replace(">", "")
    previous = None
    while previous != text:
        previous = text
        text = _SCHEME.sub(r"\1 ", text)
    text = unicodedata.normalize("NFC", text)
    text = _WHITESPACE.sub(" ", text).strip()
    text = text[:max_len].rstrip()
    if "<" in text or ">" in text or _SCHEME.search(text) or _remove_unsafe(text) != text:
        raise FeedError("text could not be cleaned")
    return text


def clean_range(value):
    """Keep the GitHub wording only if it is plainly a version range; otherwise
    publish an empty string so the plugin shows the advisory for manual review."""
    if not isinstance(value, str):
        raise FeedError("a version range is not a string")
    if not RANGE_RE.fullmatch(value):
        return ""
    if HASH_RE.fullmatch(value) or all(RANGE_CLAUSE_RE.fullmatch(c) for c in value.split(",")):
        return value
    return ""


def checked_url(url):
    if (
        not isinstance(url, str)
        or len(url) > MAX_URL
        or not url.startswith("https://")
        or any(ch.isspace() for ch in url)
        or "@" in url.split("/")[2]
    ):
        return None
    host = url.split("/")[2].lower()
    return url if host in URL_HOSTS else None


# ------------------------------------------------------------------ releases

def parse_release(raw):
    """A proper release only: MAJOR.MINOR.PATCH, not a draft. RCs, milestones and
    four-part tags such as 2.7.1.1 are ignored. The URL is built from the tag."""
    if not isinstance(raw, dict):
        raise FeedError("a release is not an object")
    draft = raw.get("draft")
    if draft is not None and not isinstance(draft, bool):
        raise FeedError("a release has a non-boolean draft flag")
    tag = raw.get("tag_name")
    if not isinstance(tag, str):
        raise FeedError("a release tag is not a string")
    published_at = raw.get("published_at")
    if published_at is not None and not isinstance(published_at, str):
        raise FeedError("a release publish time is not a string")
    if draft or not published_at:
        return None
    match = RELEASE_TAG_RE.fullmatch(tag)
    if not match:
        return None
    checked_timestamp(published_at, f"release {tag}")
    major, minor, patch = (int(g) for g in match.groups())
    return Release(
        version=f"{major}.{minor}.{patch}",
        major=major,
        minor=minor,
        patch=patch,
        published=parse_timestamp(published_at),
        published_at=published_at,
        url=RELEASE_URL_BASE + tag,
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


# ---------------------------------------------------------------- advisories

def derive_patched_versions(patched_strings):
    """Map series to the lowest patched version found across all strings."""
    best = {}
    for patched in patched_strings:
        for match in PATCHED_TOKEN_RE.finditer(patched):
            version = tuple(int(g) for g in match.groups())
            series = version[:2]
            if series not in best or version < best[series]:
                best[series] = version
    return {
        series_name(series): ".".join(str(part) for part in version)
        for series, version in sorted(best.items(), reverse=True)
    }


def transform_advisory(raw, index=0):
    if not isinstance(raw, dict):
        raise FeedError(f"advisory #{index}: not an object")
    ghsa_id = raw.get("ghsa_id")
    if not isinstance(ghsa_id, str) or not GHSA_RE.fullmatch(ghsa_id):
        raise FeedError(f"advisory #{index}: invalid ghsa_id {safe_repr(ghsa_id)}")
    label = f"advisory {ghsa_id}"

    cve_id = raw.get("cve_id")
    if cve_id is not None and not (isinstance(cve_id, str) and CVE_RE.fullmatch(cve_id)):
        cve_id = False

    summary = raw.get("summary")
    if not isinstance(summary, str):
        raise FeedError(f"{label}: summary is not a string")
    severity = raw.get("severity")
    if severity not in SEVERITIES:
        raise FeedError(f"{label}: invalid severity {safe_repr(severity)}")
    published_at = checked_timestamp(raw.get("published_at"), label)

    vulnerabilities = raw.get("vulnerabilities")
    if vulnerabilities is None:
        vulnerabilities = []
    if not isinstance(vulnerabilities, list):
        raise FeedError(f"{label}: vulnerabilities is not a list")
    ranges = []
    patched_strings = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            raise FeedError(f"{label}: a vulnerability is not an object")
        version_range = vulnerability.get("vulnerable_version_range")
        if version_range is not None:
            try:
                cleaned = clean_range(version_range)
            except FeedError:
                raise FeedError(f"{label}: a version range is not a string")
            if cleaned not in ranges:
                ranges.append(cleaned)
        patched = vulnerability.get("patched_versions")
        if patched is not None:
            if not isinstance(patched, str):
                raise FeedError(f"{label}: patched_versions is not a string")
            patched_strings.append(patched)
    if len(ranges) > MAX_RANGES:
        raise FeedError(f"{label}: more than {MAX_RANGES} version ranges")

    try:
        cleaned_summary = clean_text(summary, MAX_SUMMARY)
    except FeedError:
        raise FeedError(f"{label}: summary could not be cleaned")

    advisory = {"ghsa_id": ghsa_id}
    if cve_id is not False:
        advisory["cve_id"] = cve_id
    advisory["summary"] = cleaned_summary
    advisory["severity"] = severity
    advisory["published_at"] = published_at
    advisory["vulnerable_versions"] = ranges
    advisory["patched_versions"] = derive_patched_versions(patched_strings)
    return advisory


def applies_to_releases(advisory):
    """False when every range is a commit hash (for example a flaw in the
    project's own CI): it can never match a running release. Anything else that
    names no version, including an empty or rejected range, is kept so a human
    can review it."""
    ranges = advisory["vulnerable_versions"]
    return not ranges or not all(HASH_RE.fullmatch(r) for r in ranges)


def transform_advisories(raw_advisories, log=print):
    if not isinstance(raw_advisories, list):
        raise FeedError("the advisory list is not a list")
    if len(raw_advisories) > MAX_ADVISORIES:
        raise FeedError(f"more than {MAX_ADVISORIES} advisories")
    advisories = []
    for index, raw in enumerate(raw_advisories):
        advisory = transform_advisory(raw, index)
        if applies_to_releases(advisory):
            advisories.append(advisory)
        else:
            log(f"excluded {advisory['ghsa_id']}: its only ranges are commit hashes")
    advisories.sort(key=lambda a: a["ghsa_id"])
    advisories.sort(key=lambda a: a["published_at"], reverse=True)
    ids = [a["ghsa_id"] for a in advisories]
    if len(set(ids)) != len(ids):
        raise FeedError("duplicate advisory ids")
    return advisories


# -------------------------------------------------------------------- series

def valid_blog(known):
    """Revalidate blog data reused from the previous feed; never trust it."""
    try:
        return (
            known["blog_confirmed"] is True
            and (known["blog_url"] is None or checked_url(known["blog_url"]) == known["blog_url"])
            and isinstance(known["security_flagged"], bool)
            and isinstance(known["cve_ids"], list)
            and all(isinstance(c, str) and CVE_RE.fullmatch(c) for c in known["cve_ids"])
        )
    except (KeyError, TypeError):
        return False


def build_series_entries(releases, blog_lookup, previous_entries):
    phases = infer_phases(releases)
    latest = latest_per_series(releases)
    synchronized = synchronized_versions(releases)
    previous = {}
    for entry in previous_entries if isinstance(previous_entries, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("series"), str):
            previous[(entry["series"], entry.get("latest_version"))] = entry
    phase_order = {"stable": 0, "maintenance": 1, "archive": 2}
    if len(latest) > MAX_SERIES:
        raise FeedError(f"more than {MAX_SERIES} series")

    entries = []
    for series in sorted(latest, key=lambda s: (phase_order[phases[s]], -s[0], -s[1])):
        release = latest[series]
        known = previous.get((series_name(series), release.version))
        if known and valid_blog(known):
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


def build_feed(releases, raw_advisories, blog_lookup, previous, now, log=print):
    """previous is the prior feed (or None). `generated` only moves when the
    content changes, so an unchanged feed produces no commit."""
    if not isinstance(previous, dict):
        previous = None
    previous_entries = (previous or {}).get("series") or []
    feed = {
        "source_note": SOURCE_NOTE,
        "schema_version": SCHEMA_VERSION,
        "generated": None,
        "series": build_series_entries(releases, blog_lookup, previous_entries),
        "advisories": transform_advisories(raw_advisories, log),
    }
    if previous and {k: v for k, v in previous.items() if k != "generated"} == {
        k: v for k, v in feed.items() if k != "generated"
    }:
        feed["generated"] = previous["generated"]
    else:
        feed["generated"] = now.strftime(TIMESTAMP_FORMAT)
    return feed


def serialize(feed):
    """UTF-8, stable key order, one document, with <, > and & escaped inside
    strings. Fails if the file would exceed the size limit."""
    text = json.dumps(feed, indent=2, ensure_ascii=False, allow_nan=False)
    text = text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e") + "\n"
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise FeedError("the feed would exceed 1 MiB")
    return text


# ------------------------------------------------------------------- network

def http_get(url, accept, retries=3, backoff=2.0, allow_404=False):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read(MAX_API_BYTES + 1)
                if len(body) > MAX_API_BYTES:
                    raise FeedError("a response is too large")
                return body.decode("utf-8")
        except urllib.error.HTTPError as error:
            if allow_404 and error.code == 404:
                return None
            if error.code == 403 and "rate limit" in error.read(4096).decode("utf-8", "ignore").lower():
                raise FeedError(
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
    return parse_api_json(http_get(url, "application/vnd.github+json"))


def fetch_releases():
    raw_releases = http_get_json(GITHUB_RELEASES)
    if not isinstance(raw_releases, list):
        raise FeedError("the release list is not a list")
    return [r for r in (parse_release(raw) for raw in raw_releases) if r]


def fetch_raw_advisories():
    """Any failure aborts the run: a feed whose advisories silently vanished
    would stop warning every client."""
    advisories = []
    for page in range(1, MAX_ADVISORY_PAGES + 1):
        batch = http_get_json(f"{GITHUB_ADVISORIES}&page={page}")
        if not isinstance(batch, list):
            raise FeedError("the advisory list is not a list")
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
    """Built from a validated post name and validated categories, never copied."""
    match = POST_NAME_RE.fullmatch(post_filename)
    if not match:
        return None
    year, month, day, slug = match.groups()
    usable = [c for c in categories if c != "release" and CATEGORY_RE.fullmatch(c)] or ["announcements"]
    return checked_url(f"https://geoserver.org/{'/'.join(usable)}/{year}/{month}/{day}/{slug}.html")


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
            listing = http_get_json(BLOG_POSTS_API)
            if not isinstance(listing, list):
                raise FeedError("the blog post index is not a list")
            for entry in listing:
                name = entry.get("name") if isinstance(entry, dict) else None
                match = POST_NAME_RE.fullmatch(name) if isinstance(name, str) else None
                if match:
                    year, month, day = (int(g) for g in match.groups()[:3])
                    try:
                        posted = datetime(year, month, day, tzinfo=timezone.utc)
                    except ValueError:
                        continue
                    if posted >= cutoff:
                        self.names.append(name)
        return self.names

    def __call__(self, release):
        if self.now - release.published > timedelta(days=BLOG_LOOKBACK_DAYS):
            return None
        needle = f"geoserver-{release.version.replace('.', '-')}-released"
        matches = [n for n in self._index() if needle in n]
        if not matches:
            return None
        body = http_get(RAW_POST_BASE + matches[0], "text/plain", allow_404=True)
        if body is None:
            return None
        frontmatter, text = parse_frontmatter(body)
        categories = frontmatter.get("categories", [])
        cve_ids = sorted(set(CVE_FIND_RE.findall(text)))[:50]
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
        previous = parse_api_json(OUTPUT_PATH.read_text(encoding="utf-8"))
    except (FeedError, UnicodeDecodeError, OSError):
        return None
    if (
        not isinstance(previous, dict)
        or previous.get("schema_version") != SCHEMA_VERSION
        or not isinstance(previous.get("series"), list)
        or not isinstance(previous.get("generated"), str)
    ):
        return None
    return previous


def main():
    now = datetime.now(timezone.utc)
    try:
        feed = build_feed(
            fetch_releases(), fetch_raw_advisories(), BlogLookup(now), load_previous(), now
        )
        text = serialize(feed)
    except FeedError as error:
        print(f"ERROR: version check failed: {error}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.HTTPError as error:
        print(f"ERROR: version check failed: HTTP {error.code} from GitHub", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(f"ERROR: version check failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)

    existing = OUTPUT_PATH.read_bytes().decode("utf-8", "replace") if OUTPUT_PATH.exists() else None
    if existing != text:
        OUTPUT_PATH.write_bytes(text.encode("utf-8"))
    print(f"{len(feed['series'])} series, {len(feed['advisories'])} advisories, generated {feed['generated']}")


if __name__ == "__main__":
    main()

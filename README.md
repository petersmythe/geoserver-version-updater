# GeoServer version feed

A small, PSC-run background job that publishes a machine-readable summary
of recent GeoServer releases across all active series, so that any
GeoServer instance (or monitoring tool) can check whether it's up to
date and whether a security release is relevant to it.

## Why this exists

- GitHub Releases for `geoserver/geoserver` are usually the first public
  signal a new version exists, but by themselves carry no reliable
  indication of whether a release addresses a security vulnerability.
- The [geoserver.org blog](https://geoserver.org/blog) is the
  authoritative source for that: release posts carry a `Vulnerability`
  category and list `GEOS-xxxx` / `CVE-xxxx-xxxxx` identifiers under a
  "Security Considerations" heading — but posts typically follow the
  GitHub release by roughly an hour.
- GeoServer maintains multiple concurrent series (currently a stable,
  a maintenance, and sometimes an archived series still receiving
  security-only backports — see the
  [release schedule](https://github.com/geoserver/geoserver/wiki/Release-Schedule)).
  A client needs to know the latest version *for its own series*, not
  just the single newest tag overall.

This job merges both sources every 15 minutes and publishes a single
`versions.json`, so consumers don't need to know about any of the above
— they just read the feed.

## Privacy model

This is deliberately a **one-way, read-only, anonymous** pipeline:

- All requests to the GitHub API are unauthenticated (no token), so
  nothing ties them to any particular AfriGIS, PSC, or individual
  identity.
- The job runs on GitHub-hosted Actions runners, so from GitHub's
  point of view the traffic against `api.github.com` originates from
  GitHub's own infrastructure, not from any externally-identifiable
  network.
- The output file is served from a public repo via
  [jsDelivr](https://www.jsdelivr.com/) rather than directly from
  GitHub Pages or the API, so **nobody — including the GeoServer
  project itself — can see which organisations, IPs, or instances are
  checking for updates.** jsDelivr's own logs are the only place any
  request trace exists, and it's a well-known CDN, not project
  infrastructure.

This is intentionally separate from (and not a prerequisite for) any
future opt-in mechanism that lets an instance self-report its running
version — that would be a distinct, explicitly-consented pipeline, not
bolted onto this one.

## Consuming the feed

```
https://cdn.jsdelivr.net/gh/<org>/<repo>@<branch>/versions.json
```

jsDelivr caches aggressively at the edge and does **not** automatically
notice a new commit — without intervention, clients could keep getting
a stale (possibly pre-security-fix) `versions.json` for hours. To avoid
that, the workflow purges jsDelivr's cache for this exact path
immediately after every commit that actually changes `versions.json`:

```
POST https://purge.jsdelivr.net/gh/<org>/<repo>@<branch>/versions.json
```

This is unauthenticated, takes effect across jsDelivr's edges within
roughly a minute, and is retried a few times on transient failure. If
it still fails, the workflow logs a warning but does not fail the run
— the commit has already succeeded, and the CDN will fall back to
expiring the entry on its normal TTL. In practice this means a client
polling the jsDelivr URL should see a new release reflected within
about a minute of the commit landing, not hours later.

### Output shape

```jsonc
{
  "schema_version": 1,
  "checked_at": "2026-08-14T10:15:00Z",
  "latest_by_series": {
    "3.0.x":  { "version": "3.0.1",  "published_at": "..." },
    "2.28.x": { "version": "2.28.5", "published_at": "..." },
    "2.27.x": { "version": "2.27.6", "published_at": "..." }
  },
  "versions": [
    {
      "series": "3.0.x",
      "version": "3.0.1",
      "series_status": "stable",       // stable | maintenance | archived
      "series_eol": "2027-04",
      "published_at": "...",
      "release_url": "https://github.com/geoserver/geoserver/releases/tag/3.0.1",
      "blog_confirmed": true,
      "blog_url": "https://geoserver.org/announcements/vulnerability/...",
      "security": {
        "flagged": true,
        "cve_ids": ["CVE-2026-11111"],
        "geos_ids": ["GEOS-12200"],
        "pending_blog_confirmation": false
      },
      "probable_coordinated_security_release": true
    }
  ],
  "advisories": [ /* raw GHSA entries, cross-reference */ ]
}
```

`pending_blog_confirmation: true` means GitHub shows the release but
the matching blog post hasn't been indexed yet — treat this as "update
available, security relevance not yet confirmed" rather than "no
security issue." `probable_coordinated_security_release: true` means
multiple series released on the same day, which historically has
correlated with a shared security fix even before the blog post
confirms it explicitly.

## Running it yourself

```bash
python3 scripts/check_versions.py
```

Writes `versions.json` in the repo root. No dependencies beyond the
Python 3 standard library.

## Series lifecycle configuration

`scripts/series.json` tracks which series is currently stable,
maintenance, or archived. This changes roughly every six months and
isn't reliably scrapeable from the wiki, so it's maintained by hand —
update it when a series transitions, per the release schedule.

# gs-updates-checker

A machine-readable feed of GeoServer releases and security advisories, and the
job that generates it. It is the data source for the GeoServer
`updates-checker` community module (Maven artifactId `gs-updates-checker`),
which tells a GeoServer administrator when a newer version, a new release
series, or a relevant security advisory is available.

The feed is generated automatically from public sources. No one has to edit it
by hand.

> **Status: alpha.** The feed and its generator are under development on the
> `alpha` branch, so the format may still change. This repository was formerly
> named `geoserver-version-updater`.

## Feed URLs

| Branch | URL | Use |
|---|---|---|
| `main` | `https://cdn.jsdelivr.net/gh/petersmythe/gs-updates-checker@main/versions.json` | Default for the plugin |
| `alpha` | `https://cdn.jsdelivr.net/gh/petersmythe/gs-updates-checker@alpha/versions.json` | Development and testing |

**Use branch URLs only.** jsDelivr caches tag URLs (`@v1`) indefinitely and
ignores purge requests for them, so a tag would serve a stale feed for ever.
Compatibility is signalled by the `schema_version` field inside the JSON, not by
the URL.

## What the feed tells you

- The **latest patch of every release series**, and the series' **phase**:
  `stable`, `maintenance` or `archive`.
- Whether a release was part of a **coordinated multi-series release**, which is
  a strong early sign of a security release.
- **Security advisories** (GHSA/CVE), with the affected version ranges and the
  first patched version per series.

### How the phase is inferred

Phase is never configured. It is derived from the release history:

1. Releases are grouped into events: every release within 24 hours of the
   earliest release in the group.
2. The most recent event that contains two or more series defines how many
   series are **actively maintained** (N) and which ones.
3. A series newer than all of those (for example a new series released on its
   own) joins them. The top N by version are active: the highest is `stable`,
   the others are `maintenance`. A new series therefore displaces the oldest
   maintained one.
4. Every other series is `archive`.

When a new series is released, or a series stops appearing in coordinated
releases, its phase changes by itself. Pre-releases (`-RC`, `-M`, `-beta`,
`-alpha`, `-SNAPSHOT`) and four-part tags such as `2.7.1.1` are ignored. No
end-of-life dates are published or calculated.

## Output shape (schema v1)

```jsonc
{
  "source_note": "Generated from public GitHub data by an anonymous script ...",
  "schema_version": 1,
  "generated": "2026-10-19T10:15:00Z",   // when the content last changed
  "series": [
    {
      "series": "2.28.x",
      "phase": "maintenance",              // stable | maintenance | archive
      "latest_version": "2.28.5",
      "published_at": "2026-08-14T23:41:43Z",
      "release_url": "https://github.com/geoserver/geoserver/releases/tag/2.28.5",
      "blog_url": "https://geoserver.org/announcements/...",   // null if no post was found
      "security_flagged": true,           // the blog post flags it as a security release
      "synchronized_release": true,       // released within 24h of another series
      "recent_releases": [                // every release of the last 180 days, newest first
        {
          "version": "2.28.5",
          "published_at": "2026-08-14T23:41:43Z",
          "blog_url": "https://geoserver.org/announcements/...",
          "security_flagged": true,
          "synchronized_release": true
        },
        {
          "version": "2.28.4",
          "published_at": "2026-05-27T10:43:49Z",
          "blog_url": null,
          "security_flagged": false,
          "synchronized_release": false
        }
      ]
    }
  ],
  "advisories": [
    {
      "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
      "cve_id": "CVE-2026-00000",         // null until assigned
      "summary": "...",
      "severity": "critical",             // critical | high | medium | low
      "published_at": "2026-10-19T12:00:00Z",
      "vulnerable_versions": [">= 2.28.0", "3.0.0"],
      "patched_versions": { "3.0.x": "3.0.1", "2.28.x": "2.28.5" }
    }
  ]
}
```

Notes for anyone consuming the feed directly:

- Check `schema_version` first and refuse a version you do not understand.
- Compare versions numerically, never as strings (`2.9` is older than `2.10`).
- `vulnerable_versions` entries are GitHub's own wording, kept only when they
  are plainly a version range (or a commit hash), otherwise published as `""`.
  They can still be ambiguous (a bare `3.0.0`) or impossible (an empty range).
  Do not silently ignore an advisory you cannot parse; ask a human to review it.
- `patched_versions` may be `{}` when GitHub gives no usable data.
- An advisory whose only ranges are not versions (for example a commit hash in
  the project's own CI) can never apply to a running release, so it is left out
  of the feed.
- `blog_url: null` means no blog post was found yet. It does not mean "not a
  security release": a post can follow its release by hours or days, and the
  release is looked up again on every run until its post appears.
- The series-level `blog_url`, `security_flagged` and `synchronized_release`
  describe the latest release only. `recent_releases` lists every release of the
  last 180 days, so a consumer that is several releases behind can see a
  security release in between. A release older than 180 days is no longer
  listed; the advisories are the long-term record. The feed carries no CVE ids in
  `series`: vulnerabilities are in `advisories`.
- Treat all strings in the feed as untrusted input.

## Where the data comes from

All requests are unauthenticated and read-only.

| Source | Used for |
|---|---|
| GitHub Releases, `geoserver/geoserver` | Versions, publish times, release URLs |
| GitHub Security Advisories, `geoserver/geoserver` | GHSA/CVE ids, severity, version ranges, patched versions |
| `geoserver/geoserver.github.io` blog posts | Whether a release is flagged as a security release, and its blog link |

## How it is updated

The workflow in `.github/workflows/update-versions.yml` runs the unit tests,
then `scripts/check_versions.py`, and commits `versions.json` only if it
changed. After a commit it purges the jsDelivr cache for that path. If either
GitHub API request fails, the run fails and the published feed is left as it
was; it is never published without its advisories.

There are three triggers on the default branch:

1. **External cron (primary).** An outside scheduler sends an authenticated
   `repository_dispatch` event every 15 minutes, because GitHub's own scheduler
   is unreliable under load.

   ```http
   POST https://api.github.com/repos/petersmythe/gs-updates-checker/dispatches
   Authorization: Bearer <fine-grained-token>
   Content-Type: application/json

   {"event_type": "update-versions"}
   ```

   The token needs only **Actions: read and write** on this repository. Store
   it in the scheduling service, never in this repository.
2. **GitHub schedule (fallback).** Cron at minutes 7, 22, 37 and 52 of each hour.
3. **Manual.** The **Run workflow** button in the Actions tab.

A change to a release or an advisory reaches the feed within about 15 minutes
when the external cron is running, plus up to about a minute for the CDN purge.

`repository_dispatch` and the GitHub schedule only run on the default branch.
The `alpha` branch regenerates its feed when its generator, tests or workflow are
pushed, and on a manual run. To keep `alpha` fresh from an external scheduler
too, call the workflow-dispatch endpoint instead, with the branch as the ref:

```http
POST https://api.github.com/repos/petersmythe/gs-updates-checker/actions/workflows/update-versions.yml/dispatches
Authorization: Bearer <fine-grained-token>

{"ref": "alpha"}
```

## Privacy

The feed is a one-way, anonymous pipeline.

- The generator sends no token and no identifying header, and runs on
  GitHub-hosted runners.
- The plugin only downloads the feed. It never reports its version or any
  identity, and there is no per-instance reporting mechanism in this project.
- The feed is served by the [jsDelivr](https://www.jsdelivr.com/) CDN, not by
  this project. jsDelivr is the only party that can see request logs for the
  feed. This project has no connection to jsDelivr, no access to its logs, and
  no way of knowing who downloads the feed.

## Running it yourself

```bash
python3 -m unittest discover -s tests     # unit and hostile-input tests
python3 scripts/check_versions.py         # writes versions.json
python3 scripts/validate_feed.py          # independent validator; exit 0 = valid
```

It needs only the Python 3 standard library. The generator makes a handful of
unauthenticated GitHub API requests, so do not run it in a tight loop (the limit
is 60 requests per hour per address).

## Hardening

The generator treats all upstream data as untrusted. It copies only allow-listed
fields (no names, e-mail addresses or other personal data), checks every type
and format, builds URLs instead of copying them, and reduces free text to plain
text.

One bad item never blocks the feed. A value that cannot be used is replaced by a
safe neutral one, the advisory is still published (for manual review), and a
warning is logged. The run fails only if GitHub cannot be reached, or there is
nothing usable and nothing previously published to fall back on. A separate
validator, which shares no code with the generator, re-checks the written file
before it is committed and again before it is published. The workflow's actions
are pinned to commit SHAs, and only the publish step has write permission. The
full rules are in section 12 of the feed specification.

Maintainers: in the repository settings, protect `main`, require the **Checks**
workflow and code-owner review (`.github/CODEOWNERS`), and let only the
`github-actions` bot bypass the pull-request requirement so it can commit
`versions.json`.

## Limitations

- GitHub publishes a release up to about a day before its blog post. Until the
  post appears the release is still listed, flagged as unconfirmed.
- GitHub Security Advisories are sometimes published days or weeks after the fix.
  `synchronized_release` is the earlier signal.
- Only the most recent GitHub releases are read, so very old series may be
  missing. A consumer must treat an unknown series as `archive`.
- Java and Tomcat requirements, end-of-life dates and GeoTools or GeoWebCache
  versions are not part of this feed.

## License

GNU General Public License, version 2 (GPL-2.0), the same license as GeoServer.

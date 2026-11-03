"""Tests for lab_scout.discovery: source parsers, filters, ranking.

SAFETY: no network. Parsers run on fixtures captured from the real endpoints
on 2026-10-18 and trimmed (tests/fixtures); HTTP goes through fake openers;
the awesome-selfhosted clone is a local bare repo over file://, which only
the test seam allows. Fixture-based tests pin "now" to the capture date.
"""

from __future__ import annotations

import datetime as dt
import importlib
import json
import logging
import os
import subprocess
import sys
import urllib.error
import urllib.parse
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
import yaml

import lab_scout.discovery as discovery_module
import lab_scout.scout as scout_module

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = dt.datetime(2026, 10, 18, 17, 0, tzinfo=dt.timezone.utc)
FAKE_GITHUB_TOKEN = "ghp_FAKEgithubTOKENcanary0123456789"


class CurrentStderr:
    """Writes to whatever sys.stderr is now, so capsys sees every record."""

    def write(self, text: str) -> int:
        return sys.stderr.write(text)

    def flush(self) -> None:
        sys.stderr.flush()


@pytest.fixture()
def ds() -> Any:
    importlib.reload(scout_module)
    module = importlib.reload(discovery_module)
    scout_module.setup_logging(CurrentStderr())
    yield module
    logging.getLogger("lab-scout").handlers.clear()


class FakeResponse(BytesIO):
    status = 200
    headers: dict[str, str] = {}


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://example.invalid/x", code, "err", {}, BytesIO(b"{}"))  # type: ignore[arg-type]


class Opener:
    """Answers by URL prefix. Each value is bytes, an exception, or a callable."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.requests: list[Any] = []

    def __call__(self, request: Any, timeout: float | None = None) -> Any:
        assert timeout is not None and timeout > 0, "every request needs a timeout"
        self.requests.append(request)
        for prefix, answer in self.routes.items():
            if request.full_url.startswith(prefix):
                if callable(answer) and not isinstance(answer, type):
                    answer = answer(request)
                if isinstance(answer, BaseException):
                    raise answer
                response = FakeResponse(answer if isinstance(answer, bytes) else json.dumps(answer).encode())
                return response
        raise urllib.error.URLError("sandbox: no route")

    def urls(self) -> list[str]:
        return [r.full_url for r in self.requests]


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def iso(value: dt.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def repo(owner: str, name: str, stars: int = 500, created_days: int = 60, pushed_days: int = 2, spdx: str | None = "MIT",
         topics: list[str] | None = None, **over: Any) -> dict[str, Any]:
    data = {
        "name": name, "full_name": f"{owner}/{name}", "html_url": f"https://github.com/{owner}/{name}",
        "description": f"{name} does a thing.", "fork": False, "archived": False, "disabled": False,
        "created_at": iso(NOW - dt.timedelta(days=created_days)), "pushed_at": iso(NOW - dt.timedelta(days=pushed_days)),
        "stargazers_count": stars, "topics": topics or [],
        "license": {"spdx_id": spdx} if spdx else None,
    }
    data.update(over)
    return data


def make_cfg(sources: tuple[str, ...], **over: Any) -> Any:
    fields = dict(state_dir=Path("/nonexistent"), profile="/nonexistent", inventory=[], extra_inventory=[],
                  claude_bin="claude", claude_model="opus", claude_timeout=60, max_ideas=5, max_stale_days=180,
                  sources=sources)
    fields.update(over)
    return scout_module.Config(**fields)


def make_deps(**over: Any) -> Any:
    fields: dict[str, Any] = dict(source_opener=Opener({}), github_opener=Opener({}), sleep=lambda secs: None)
    fields.update(over)
    return scout_module.Deps(**fields)


# ---------------------------------------------------------------------------
# GitHub search
# ---------------------------------------------------------------------------


def test_github_search_fixture_parses_into_leads_with_facts(ds: Any) -> None:
    data = json.loads(fixture_bytes("github_search_self_hosted.json"))
    leads = ds.parse_github_search(data, "self-hosted")
    assert [(lead.name, lead.url) for lead in leads] == [
        ("Concat", "https://github.com/jub0t/Concat"), ("utopia", "https://github.com/deeplethe/utopia"),
        ("AIHOT", "https://github.com/KKKKhazix/AIHOT"), ("OpenMausBot", "https://github.com/milind-soni/OpenMausBot")]
    assert all(lead.sources == ["github"] and lead.category == "self-hosted" and lead.repo for lead in leads)
    lead = leads[0]
    ds.apply_repo(lead, NOW, 180)
    assert lead.facts.stars == 8868 and lead.facts.license == "AGPL-3.0"
    assert lead.created_at == dt.datetime(2026, 8, 25, 18, 34, 47, tzinfo=dt.timezone.utc)
    assert lead.description.startswith("The truly free, open-source, local-first")
    with pytest.raises(ds.SourceError, match="no items"):
        ds.parse_github_search({"message": "Validation Failed"}, "os")


def test_github_search_urls_are_encoded_and_dated(ds: Any) -> None:
    queries = ds.github_queries(NOW)
    assert queries[0] == ("topic:self-hosted created:>2026-07-20 stars:>50", "self-hosted")
    assert {category for _, category in queries} >= {"self-hosted", "kubernetes", "observability", "security",
                                                      "robotics", "os"}
    url = ds.github_search_url(queries[0][0])
    assert url.startswith("https://api.github.com/search/repositories?q=topic%3Aself-hosted+created%3A%3E2026-07-20")
    assert ">" not in url and " " not in url
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(url).query) == {
        "q": ["topic:self-hosted created:>2026-07-20 stars:>50"], "sort": ["stars"], "order": ["desc"], "per_page": ["30"]}


def test_token_goes_to_the_github_api_only(ds: Any) -> None:
    api = ds.source_request("https://api.github.com/search/repositories?q=x", FAKE_GITHUB_TOKEN)
    assert api.get_header("Authorization") == f"Bearer {FAKE_GITHUB_TOKEN}"
    assert api.get_header("Accept") == "application/vnd.github+json"
    for other in ("https://hn.algolia.com/api/v1/search_by_date", "https://distrowatch.com/news/dwd.xml",
                  "https://raw.githubusercontent.com/cncf/landscape/master/landscape.yml",
                  "http://api.github.com/search/repositories", "https://api.github.com.evil.example/x",
                  "https://api.github.com:8443/search/repositories"):
        assert ds.source_request(other, FAKE_GITHUB_TOKEN).get_header("Authorization") is None, other


def search_routes(per_topic: dict[str, list[dict[str, Any]]], headers: dict[str, str] | None = None,
                  fail_from: int | None = None, code: int = 403) -> Opener:
    count = {"n": 0}

    def answer(request: Any) -> Any:
        count["n"] += 1
        if fail_from is not None and count["n"] >= fail_from:
            return http_error(code)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)["q"][0]
        topic = query.split()[0].split(":", 1)[1]
        response = FakeResponse(json.dumps({"items": per_topic.get(topic, [])}).encode())
        response.headers = headers or {}
        return response

    class Routed(Opener):
        def __call__(self, request: Any, timeout: float | None = None) -> Any:
            assert timeout
            self.requests.append(request)
            result = answer(request)
            if isinstance(result, BaseException):
                raise result
            return result

    return Routed({})


def test_search_rate_limit_midway_keeps_what_was_found(ds: Any, capsys: pytest.CaptureFixture[str]) -> None:
    opener = search_routes({"self-hosted": [repo("o", "first")]}, fail_from=2)
    leads = ds.github_source(make_cfg(("github",)), make_deps(source_opener=opener), NOW)
    assert [lead.name for lead in leads] == ["first"]
    assert len(opener.requests) == 2, "the first refusal stops the queries"
    assert "HTTP 403 (rate limited or forbidden) on query 2 of 7; keeping 1 result(s)" in capsys.readouterr().err


def test_search_waits_for_a_near_reset_and_stops_for_a_far_one(ds: Any, capsys: pytest.CaptureFixture[str]) -> None:
    import time
    slept: list[float] = []
    near = search_routes({}, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(time.time()) + 10)})
    ds.github_source(make_cfg(("github",)), make_deps(source_opener=near, sleep=slept.append), NOW)
    assert len(near.requests) == 7 and len(slept) == 6
    assert all(9 <= secs <= 12 for secs in slept), slept
    far = search_routes({}, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(time.time()) + 3000)})
    slept.clear()
    ds.github_source(make_cfg(("github",)), make_deps(source_opener=far, sleep=slept.append), NOW)
    assert len(far.requests) == 1 and slept == []
    assert "search quota spent; skipping the last 6 query(ies)" in capsys.readouterr().err
    plenty = search_routes({}, headers={"X-RateLimit-Remaining": "5", "X-RateLimit-Reset": "1"})
    ds.github_source(make_cfg(("github",)), make_deps(source_opener=plenty, sleep=slept.append), NOW)
    assert len(plenty.requests) == 7 and slept == [], "no blind spacing while calls remain"


# ---------------------------------------------------------------------------
# Hacker News
# ---------------------------------------------------------------------------


def test_hn_fixture_keeps_only_github_repos(ds: Any) -> None:
    leads = ds.parse_hn(json.loads(fixture_bytes("hn_show_hn.json")), NOW)
    assert [(lead.url, lead.hn_points) for lead in leads] == [
        ("https://github.com/volotat/mini-AGI", 277),
        ("https://github.com/arnegiacomo/fugleramme", 2391),
        ("https://github.com/gioblu/NPC-Forge", 225),  # a deep link becomes the repository
    ]
    assert leads[1].description == "An e-ink frame that hears birds and draws them as 1800s illustrations"
    assert all(lead.name == "" and lead.sources == ["hn"] for lead in leads), "the name comes from the repo"
    assert ds.parse_hn(json.loads(fixture_bytes("hn_show_hn.json")), NOW + dt.timedelta(days=365)) == [], "window"
    with pytest.raises(ds.SourceError):
        ds.parse_hn([], NOW)


def test_hn_url_filters_are_encoded(ds: Any) -> None:
    url = ds.hn_url(NOW)
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    since = int((NOW - dt.timedelta(days=90)).timestamp())
    assert params == {"tags": ["show_hn"], "numericFilters": [f"points>100,created_at_i>{since}"], "hitsPerPage": ["100"]}
    assert ">" not in url


# ---------------------------------------------------------------------------
# awesome-selfhosted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["awesome_trek.yml", "awesome_sparkyfitness.yml", "awesome_drawdb.yml", "awesome_0ad.yml"])
def test_awesome_entry_reader_agrees_with_pyyaml(ds: Any, name: str) -> None:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    mine, ref = ds.parse_awesome_entry(text), yaml.safe_load(text)
    for key in ("name", "description", "source_code_url", "licenses", "tags", "archived", "stargazers_count"):
        expected = ref.get(key)
        expected = str(expected).lower() if isinstance(expected, bool) else str(expected) if isinstance(expected, int) else expected
        assert mine.get(key) == expected, key


def test_awesome_entry_reader_handles_quotes_folding_and_junk(ds: Any) -> None:
    text = ("name: 'It''s Here'\ndescription: \"Says \\\"hi\\\"\"\nsource_code_url: https://github.com/o/r # comment\n"
            "tags:\n  - Media Streaming\n  - 'Quoted'\nlong: first line\n  continued here\nblock: >-\n  folded\n"
            "flow: [a, b]\n")
    entry = ds.parse_awesome_entry(text)
    assert entry["name"] == "It's Here" and entry["description"] == 'Says "hi"'
    assert entry["source_code_url"] == "https://github.com/o/r"
    assert entry["tags"] == ["Media Streaming", "Quoted"]
    assert entry["long"] == yaml.safe_load(text)["long"] == "first line continued here"
    assert entry["block"] is None and entry["flow"] is None, "unsupported forms are unknown, not guessed"


def test_awesome_leads_need_github_and_an_osi_license(ds: Any) -> None:
    def lead(name: str) -> Any:
        return ds.awesome_lead(ds.parse_awesome_entry((FIXTURES / name).read_text(encoding="utf-8")))

    trek = lead("awesome_trek.yml")
    assert (trek.name, trek.url, trek.sources) == ("TREK", "https://github.com/liketrek/TREK", ["awesome-selfhosted"])
    assert trek.rank_hint == 14810 and trek.repo is None, "their count orders lookups; facts still come from the API"
    assert lead("awesome_sparkyfitness.yml") is None, "listed as proprietary"
    assert lead("awesome_0ad.yml") is None, "not on GitHub, so no facts to check"
    assert lead("awesome_drawdb.yml").url == "https://github.com/drawdb-io/drawdb"
    assert ds.awesome_lead({"name": "X", "licenses": ["MIT"], "source_code_url": "https://github.com/o/x",
                            "archived": "true"}) is None
    hostile = ds.awesome_lead({"name": "Pinger @everyone", "licenses": ["MIT"], "source_code_url": "https://github.com/o/p",
                               "description": "x" * 1000})
    assert hostile.name == "Pinger" and len(hostile.description) == ds.DESCRIPTION_MAX_CHARS
    numbered = ds.awesome_lead({"name": "Tool 2", "licenses": ["MIT"], "source_code_url": "https://github.com/o/tool"})
    assert numbered.name == "", "a name that breaks the rules falls back to the repo name later"


def git(cwd: Path, *args: str, when: dt.datetime | None = None) -> str:
    stamp = (when or NOW).strftime("%Y-%m-%dT%H:%M:%S+0000")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(cwd), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout


@pytest.fixture()
def awesome_origin(tmp_path: Path) -> str:
    """file:// URL of a bare repo shaped like awesome-selfhosted-data, with
    commits dated relative to NOW."""
    seed = tmp_path / "seed"
    (seed / "software").mkdir(parents=True)
    git(seed, "init", "-q", "-b", "master")

    def commit(days_ago: int, **files: str | None) -> None:
        for name, content in files.items():
            path = seed / "software" / name.replace("__", ".")
            if content is None:
                path.unlink()
            else:
                path.write_text(content, encoding="utf-8")
        git(seed, "add", "-A")
        git(seed, "commit", "-q", "-m", f"{days_ago} days ago", when=NOW - dt.timedelta(days=days_ago))

    drawdb = (FIXTURES / "awesome_drawdb.yml").read_text(encoding="utf-8")
    trek = (FIXTURES / "awesome_trek.yml").read_text(encoding="utf-8")
    sparky = (FIXTURES / "awesome_sparkyfitness.yml").read_text(encoding="utf-8")
    commit(300, ancient__yml=drawdb.replace("drawDB", "Ancient").replace("drawdb-io/drawdb", "o/ancient"))
    commit(100, margin__yml=drawdb.replace("drawDB", "Margin").replace("drawdb-io/drawdb", "o/margin"))
    commit(20, trek__yml=trek, sparkyfitness__yml=sparky)
    commit(15, gone__yml=drawdb.replace("drawDB", "Gone").replace("drawdb-io/drawdb", "o/gone"),
           Upper__yml=drawdb.replace("drawDB", "Upper"))
    commit(10, gone__yml=None, ancient__yml=drawdb.replace("drawDB", "Ancient2").replace("drawdb-io/drawdb", "o/ancient"))
    origin = tmp_path / "origin.git"
    git(tmp_path, "clone", "-q", "--bare", str(seed), str(origin))
    return f"file://{origin}"


def test_awesome_source_reads_only_entries_added_in_the_window(ds: Any, awesome_origin: str) -> None:
    calls: list[list[str]] = []

    def runner(argv: list[str], timeout: int) -> str:
        calls.append(argv)
        return scout_module.run_git(argv, timeout, allow_protocols="file")

    deps = make_deps(git_runner=runner, awesome_selfhosted_url=awesome_origin, repo_url_ok=lambda u: u.startswith("file:///"))
    leads = ds.awesome_source(make_cfg(("awesome-selfhosted",)), deps, NOW)
    # trek was added in the window; sparkyfitness too but it is proprietary;
    # gone was added and removed; ancient was only modified; margin was added
    # before the window; Upper.yml is not a valid entry path.
    assert [lead.name for lead in leads] == ["TREK"]
    assert calls[0] == ["git", "clone", "--shallow-since=2026-06-20", "--no-checkout", "--single-branch",
                        "--branch", "master", "--", awesome_origin, calls[0][-1]]
    assert calls[1][3:6] == ["-c", "log.showRoot=false", "log"]
    assert not Path(calls[0][-1]).exists(), "the clone is removed afterwards"
    shown = [argv[-1] for argv in calls if argv[3] == "show"]
    assert sorted(shown) == ["HEAD:software/gone.yml", "HEAD:software/sparkyfitness.yml", "HEAD:software/trek.yml"]


def test_awesome_source_shallow_boundary_is_not_an_addition(ds: Any, awesome_origin: str) -> None:
    # Clone from inside the window: its oldest commit (20 days ago) becomes
    # the shallow boundary, which looks like a root commit adding every file.
    with_root: list[str] = []

    def runner(argv: list[str], timeout: int) -> str:
        if argv[1] == "clone":
            argv = [a if not a.startswith("--shallow-since=") else "--shallow-since=2026-09-25" for a in argv]
        out = scout_module.run_git(argv, timeout, allow_protocols="file")
        if "log" in argv:
            # Control: the same query with showRoot left on.
            loose = [a for a in argv if a not in ("-c", "log.showRoot=false")]
            with_root.append(scout_module.run_git(loose, timeout, allow_protocols="file"))
        return out

    deps = make_deps(git_runner=runner, awesome_selfhosted_url=awesome_origin, repo_url_ok=lambda u: u.startswith("file:///"))
    assert ds.awesome_source(make_cfg(("awesome-selfhosted",)), deps, NOW) == [], "nothing was added after the boundary"
    (control,) = with_root
    assert "software/trek.yml" in control and "software/margin.yml" in control, "the guard is what keeps them out"


def test_awesome_source_refuses_a_non_github_url_in_production(ds: Any, awesome_origin: str) -> None:
    with pytest.raises(ds.SourceError, match="not an allowed repository URL"):
        ds.awesome_source(make_cfg(("awesome-selfhosted",)), make_deps(awesome_selfhosted_url=awesome_origin), NOW)


# ---------------------------------------------------------------------------
# CNCF landscape
# ---------------------------------------------------------------------------


def pyyaml_landscape(text: str) -> list[dict[str, Any]]:
    records = []
    for category in yaml.safe_load(text)["landscape"]:
        for sub in category.get("subcategories") or []:
            for item in sub.get("items") or []:
                records.append({"category": category["name"], "subcategory": sub["name"], "name": item.get("name"),
                                "description": item.get("description"), "repo_url": item.get("repo_url"),
                                "project": item.get("project"), "accepted": (item.get("extra") or {}).get("accepted")})
    return records


def test_landscape_reader_agrees_with_pyyaml_on_the_captured_excerpt(ds: Any) -> None:
    text = fixture_bytes("cncf_landscape_excerpt.yml").decode("utf-8")
    mine, ref = ds.parse_landscape(text), pyyaml_landscape(text)
    assert len(mine) == len(ref) == 11
    for got, want in zip(mine, ref, strict=True):
        for key in ("category", "subcategory", "name", "repo_url", "project", "accepted"):
            assert got.get(key) == want[key], (want["name"], key)
        # Folded and quoted descriptions agree once whitespace is collapsed.
        assert scout_module.clean_text(got.get("description") or "", 500) == scout_module.clean_text(want["description"] or "", 500)
    forms = {item["name"] for item in mine}
    assert {"KubeReport", "Idem Project", "FeatureHub"} <= forms, "dash-name items, folded and quoted descriptions"


def test_cncf_leads_are_recent_sandbox_or_incubating(ds: Any) -> None:
    items = ds.parse_landscape(fixture_bytes("cncf_landscape_excerpt.yml").decode("utf-8"))
    leads = ds.cncf_leads(items, NOW)
    # Cedar was accepted on 2025-10-08, ten days before the window opens.
    assert [(lead.name, lead.category, lead.cncf_maturity) for lead in leads] == [
        ("OpenShell", "kubernetes", "sandbox"),
        ("Praxis", "kubernetes", "sandbox"),
        ("Hive Commons", "kubernetes", "sandbox"),
    ]
    assert leads[0].url == "https://github.com/NVIDIA/OpenShell"
    assert leads[0].description.startswith("OpenShell provides secure")
    earlier = ds.cncf_leads(items, NOW - dt.timedelta(days=30))
    assert [(lead.name, lead.category) for lead in earlier] == [("Cedar", "security")], "and the later ones are not yet"
    observability = {"category": "Observability and Analysis", "subcategory": "Observability"}
    assert ds.cncf_category(observability) == "observability"


def test_cncf_source_failures_are_source_errors(ds: Any) -> None:
    cfg = make_cfg(("cncf",))
    with pytest.raises(ds.SourceError, match="no items"):
        ds.cncf_source(cfg, make_deps(source_opener=Opener({ds.CNCF_LANDSCAPE_URL: b"just: text\n"})), NOW)
    with pytest.raises(ds.SourceError, match="larger than the limit"):
        ds.cncf_source(cfg, make_deps(source_opener=Opener({ds.CNCF_LANDSCAPE_URL: b"x" * (ds.LANDSCAPE_MAX_BYTES + 1)})), NOW)
    with pytest.raises(ds.SourceError, match="HTTP 500"):
        ds.cncf_source(cfg, make_deps(source_opener=Opener({ds.CNCF_LANDSCAPE_URL: http_error(500)})), NOW)


# ---------------------------------------------------------------------------
# DistroWatch
# ---------------------------------------------------------------------------


def test_distrowatch_fixture_parses_names_links_and_text(ds: Any) -> None:
    leads = ds.parse_distrowatch(fixture_bytes("distrowatch_dwd.xml"))
    assert [(lead.name, lead.url) for lead in leads] == [
        ("ArchBANG", "https://distrowatch.com/archbang"), ("Cerberix", "https://distrowatch.com/cerberix"),
        ("AOSC", "https://distrowatch.com/aosc"), ("NebiOS", "https://distrowatch.com/nebios")]
    assert all(lead.github is None and lead.category == "os" and lead.sources == ["distrowatch"] for lead in leads)
    assert leads[0].description.startswith("ArchBang Linux is a lightweight distribution")
    assert "<img" not in leads[0].description and "icon-small" not in leads[0].description


@pytest.mark.parametrize("title, name", [
    ("ArchBANG 181026", "ArchBANG"), ("Rocky Linux 10.0 RC1", "Rocky Linux"), ("Ubuntu 26.04 LTS", "Ubuntu"),
    ("4MLinux 49.0", "4MLinux"), ("NebiOS 10.3-rc1", "NebiOS"), ("openSUSE Leap v16", "openSUSE Leap"), ("Debian", "Debian"),
])
def test_release_suffix_is_cut_from_distribution_names(ds: Any, title: str, name: str) -> None:
    assert ds.release_name(title) == name


@pytest.mark.parametrize("body, reason", [
    (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><rss><channel><item><title>&a;</title></item></channel></rss>',
     "DTD"),
    (b"<rss><channel><item>", "not well-formed"),
    (b"<rss>" + b" " * (512 << 10) + b"</rss>", "larger than the limit"),
])
def test_distrowatch_refuses_dtds_junk_and_oversize(ds: Any, body: bytes, reason: str) -> None:
    with pytest.raises(ds.SourceError, match=reason):
        ds.parse_distrowatch(body)


def test_distrowatch_links_must_stay_on_distrowatch(ds: Any) -> None:
    feed = (b"<rss><channel>"
            b"<item><title>Evil 1</title><link>https://evil.example/x</link></item>"
            b"<item><title>Lan 1</title><link>https://distrowatch.lan/x</link></item>"
            b"<item><title>Plain 1</title><link>http://distrowatch.com/plain</link></item>"
            b"<item><title>Hub 1</title><link>https://github.com/o/r</link></item>"
            b"<item><title>2026</title><link>https://distrowatch.com/numbers</link></item>"
            b"<item><title>Good 1</title><link>https://distrowatch.com/good</link></item>"
            b"</channel></rss>")
    assert [lead.name for lead in ds.parse_distrowatch(feed)] == ["Good"]


# ---------------------------------------------------------------------------
# Filters, licenses, merging, ranking
# ---------------------------------------------------------------------------


def test_license_allowlist_is_osi_only(ds: Any) -> None:
    for spdx in ("MIT", "Apache-2.0", "AGPL-3.0", "GPL-2.0", "BSD-3-Clause", "MPL-2.0", "BSL-1.0", "Unlicense"):
        assert spdx in ds.OSI_LICENSES
    for spdx in ("BUSL-1.1", "SSPL-1.0", "Elastic-2.0", "CC0-1.0", "CC-BY-NC-4.0", "WTFPL", "NOASSERTION",
                 "None stated", "Other", ""):
        assert spdx not in ds.OSI_LICENSES


@pytest.mark.parametrize("over, reason", [
    ({"fork": True}, "fork"),
    ({"fork": None}, "fork flag missing"),
    ({"license": None}, "OSI allowlist"),
    ({"license": {"spdx_id": "NOASSERTION"}}, "OSI allowlist"),
    ({"license": {"spdx_id": "BUSL-1.1"}}, "OSI allowlist"),
    ({"stargazers_count": 5}, "fewer than 20 stars"),
    ({"archived": True}, "archived"),
    ({"pushed_at": iso(NOW - dt.timedelta(days=200))}, "not pushed in over 180 days"),
    ({"name": "Tool 2"}, "name rules"),
])
def test_apply_repo_rejects(ds: Any, over: dict[str, Any], reason: str) -> None:
    lead = ds.github_lead("https://github.com/o/r", "hn", "self-hosted")
    lead.repo = {**repo("o", "r"), **over}
    with pytest.raises(scout_module.Rejected, match=reason):
        ds.apply_repo(lead, NOW, 180)


def test_apply_repo_follows_a_rename_and_fills_gaps(ds: Any) -> None:
    lead = ds.github_lead("https://github.com/old/name", "hn", "self-hosted", description="Show HN title")
    lead.repo = repo("new", "renamed", topics=["Kubernetes", "operator"], html_url="https://github.com/new/renamed")
    ds.apply_repo(lead, NOW, 180)
    assert (lead.name, lead.url, lead.github) == ("renamed", "https://github.com/new/renamed", ("new", "renamed"))
    assert lead.description == "Show HN title", "a source description is kept"
    assert lead.category == "kubernetes", "an HN lead's hint comes from the repo topics"


def test_merge_keeps_one_lead_per_repo_with_every_signal(ds: Any) -> None:
    search = ds.parse_github_search({"items": [repo("o", "tool")]}, "observability")[0]
    hn = ds.github_lead("https://github.com/O/Tool/", "hn", "self-hosted", description="Show HN text")
    hn.hn_points = 300
    curated = ds.github_lead("https://github.com/o/tool", "awesome-selfhosted", "self-hosted", "Tool Pro", "Curated text")
    merged = ds.merge([hn, search, curated])
    assert len(merged) == 1
    (lead,) = merged
    assert lead.sources == ["hn", "github", "awesome-selfhosted"]
    assert lead.hn_points == 300 and lead.repo is not None
    assert lead.category == "observability", "the search query's hint wins"
    assert (lead.name, lead.description) == ("Tool Pro", "Curated text"), "curated text wins"


def test_score_is_deterministic_and_rewards_the_documented_signals(ds: Any) -> None:
    def scored(**over: Any) -> float:
        lead = ds.parse_github_search({"items": [repo("o", "x", **over)]}, "data")[0]
        ds.apply_repo(lead, NOW, 180)
        return ds.score(lead, NOW)

    base = scored()
    assert base == scored(), "same input, same score"
    assert scored(stars=5000) > base
    assert scored(created_days=10) > base, "star velocity"
    assert scored(pushed_days=90) < base, "push recency"
    lead = ds.parse_github_search({"items": [repo("o", "x")]}, "data")[0]
    ds.apply_repo(lead, NOW, 180)
    plain = ds.score(lead, NOW)
    lead.hn_points = 500
    assert ds.score(lead, NOW) > plain
    lead.sources.append("cncf")
    assert ds.score(lead, NOW) - ds.score(ds.merge([lead])[0], NOW) == 0
    assert ds.score(lead, NOW) > plain + 1.0, "curated and a second source"


def lead_with(ds: Any, name: str, category: str, value: float, source: str = "github") -> Any:
    lead = ds.Lead(name, f"https://github.com/o/{name}", ("o", name), "", [source], category)
    lead.score = value
    return lead


def test_spread_takes_each_source_floor_then_rotates_categories(ds: Any) -> None:
    leads = [lead_with(ds, f"sec{i}", "security", 9 - i * 0.1) for i in range(6)]
    leads += [lead_with(ds, "obs0", "observability", 5), lead_with(ds, "obs1", "observability", 4)]
    leads += [lead_with(ds, "dw0", "os", 1, "distrowatch"), lead_with(ds, "dw1", "os", 0.9, "distrowatch"),
              lead_with(ds, "dw2", "os", 0.8, "distrowatch")]
    picked = ds.spread(leads, 8)
    assert [lead.name for lead in picked] == ["sec0", "sec1", "dw0", "dw1", "sec2", "obs0", "dw2", "sec3"]
    assert [lead.id for lead in picked] == [f"c{i:02d}" for i in range(1, 9)]
    assert [lead.name for lead in ds.spread(leads, 3)] == ["sec0", "sec1", "dw0"], "the size is a hard cap"


# ---------------------------------------------------------------------------
# Repository lookups and the whole pass
# ---------------------------------------------------------------------------


class FakeGitHub:
    PREFIX = "https://api.github.com/repos/"

    def __init__(self, repos: dict[str, Any], limit_after: int | None = None) -> None:
        self.repos = repos
        self.limit_after = limit_after
        self.paths: list[str] = []

    def __call__(self, request: Any, timeout: float | None = None) -> Any:
        assert timeout and request.full_url.startswith(self.PREFIX)
        path = request.full_url[len(self.PREFIX):]
        self.paths.append(path)
        if self.limit_after is not None and len(self.paths) > self.limit_after:
            raise http_error(403)
        if path not in self.repos:
            raise http_error(404)
        return FakeResponse(json.dumps(self.repos[path]).encode())


def hn_feed(names: list[str], points: int = 200) -> dict[str, Any]:
    return {"hits": [{"title": f"Show HN: {n}", "url": f"https://github.com/o/{n}", "points": points + i,
                      "created_at": iso(NOW - dt.timedelta(days=5))} for i, n in enumerate(names)]}


def test_lookups_are_capped_per_source_and_stop_at_a_rate_limit(ds: Any, capsys: pytest.CaptureFixture[str]) -> None:
    names = [f"p{i:02d}" for i in range(14)]
    github = FakeGitHub({f"o/{n}": repo("o", n) for n in names})
    deps = make_deps(source_opener=Opener({ds.HN_SEARCH_URL: hn_feed(names)}), github_opener=github)
    result = ds.discover(make_cfg(("hn",)), deps, ["x"], scout_module.Seen(), NOW)
    assert len(github.paths) == ds.ENRICH_CAPS["hn"] == 10
    assert github.paths[0] == "o/p13", "the best HN posts are looked up first"
    assert len(result.shortlist) == 10 and result.api_calls == 10
    assert result.dropped["no GitHub facts (lookup budget, rate limit or not found)"] == 4

    limited = FakeGitHub({f"o/{n}": repo("o", n) for n in names}, limit_after=2)
    deps = make_deps(source_opener=Opener({ds.HN_SEARCH_URL: hn_feed(names)}), github_opener=limited)
    result = ds.discover(make_cfg(("hn",)), deps, ["x"], scout_module.Seen(), NOW)
    assert len(limited.paths) == 3, "one refused call ends the lookups"
    assert len(result.shortlist) == 2
    assert "GitHub API rate limited; no more repository lookups this run" in capsys.readouterr().err

    many = FakeGitHub({f"o/{n}": repo("o", n) for n in names})
    deps = make_deps(source_opener=Opener({ds.HN_SEARCH_URL: hn_feed(names)}), github_opener=many)
    ds.discover(make_cfg(("hn",), github_token=FAKE_GITHUB_TOKEN), deps, ["x"], scout_module.Seen(), NOW)
    assert len(many.paths) == 14, "a token raises the caps"


def test_known_projects_cost_no_lookup(ds: Any) -> None:
    github = FakeGitHub({"o/fresh": repo("o", "fresh"), "o/loki": repo("o", "loki"), "o/seen": repo("o", "seen")})
    deps = make_deps(source_opener=Opener({ds.HN_SEARCH_URL: hn_feed(["fresh", "loki", "seen"])}), github_opener=github)
    seen = scout_module.Seen([{"name": "x", "url": "https://github.com/o/seen", "first_posted": "2026-01-01"}])
    result = ds.discover(make_cfg(("hn",)), deps, ["Loki"], seen, NOW)
    assert github.paths == ["o/fresh"]
    assert [lead.name for lead in result.shortlist] == ["fresh"]


def test_a_failing_source_is_skipped_and_the_rest_still_run(ds: Any, monkeypatch: pytest.MonkeyPatch,
                                                            capsys: pytest.CaptureFixture[str]) -> None:
    def broken(cfg: Any, deps: Any, now: Any) -> Any:
        raise KeyError("parser bug")

    monkeypatch.setitem(ds.SOURCES, "cncf", broken)
    opener = Opener({ds.DISTROWATCH_URL: fixture_bytes("distrowatch_dwd.xml"), ds.HN_SEARCH_URL: http_error(503)})
    result = ds.discover(make_cfg(("hn", "cncf", "distrowatch")), make_deps(source_opener=opener), ["x"],
                         scout_module.Seen(), NOW)
    assert [(r.name, r.status, r.detail) for r in result.sources] == [
        ("hn", "failed", "HTTP 503"), ("cncf", "failed", "KeyError"), ("distrowatch", "ok", "")]
    assert [lead.name for lead in result.shortlist] == ["AOSC", "ArchBANG", "Cerberix", "NebiOS"]
    err = capsys.readouterr().err
    assert "source hn failed (HTTP 503); skipping it" in err
    assert "source cncf failed unexpectedly (KeyError); skipping it" in err
    assert "parser bug" not in err, "an unexpected error's text is not logged"


def test_report_and_prompt_records_carry_data_not_links(ds: Any) -> None:
    opener = Opener({ds.DISTROWATCH_URL: fixture_bytes("distrowatch_dwd.xml")})
    hn = Opener({ds.HN_SEARCH_URL: hn_feed(["tool"], points=150)})
    github = FakeGitHub({"o/tool": repo("o", "tool", stars=1234, spdx="Apache-2.0")})
    both = Opener({**opener.routes, **hn.routes})
    result = ds.discover(make_cfg(("hn", "distrowatch")), make_deps(source_opener=both, github_opener=github), ["x"],
                         scout_module.Seen(), NOW)
    records = result.prompt_records()
    tool = next(r for r in records if r["name"] == "tool")
    assert tool["repo"] == "o/tool" and tool["sources"] == ["hn"]
    assert tool["facts"] == {"stars": 1234, "last_push": "2026-10-16", "license": "Apache-2.0", "created": "2026-08-19",
                             "hn_points": 150}
    assert all("url" not in r for r in records)
    report = result.report()
    assert report["github_repo_lookups"] == 1
    assert {s["name"]: s["status"] for s in report["sources"]} == {"hn": "ok", "distrowatch": "ok"}
    assert next(c for c in report["shortlist"] if c["name"] == "tool")["url"] == "https://github.com/o/tool"
    listed = {item.name: item for item in result.listed()}
    assert listed["tool"].facts.stars == 1234 and listed["ArchBANG"].facts is None
    json.dumps(report)  # serialisable as printed by --collect-only

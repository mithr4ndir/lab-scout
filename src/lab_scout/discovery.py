"""Candidate discovery for lab-scout: public sources in, a ranked shortlist out.

Sources, each optional (LAB_SCOUT_SOURCES). A source that fails for any reason
(timeout, HTTP error, rate limit, parse error) is logged and skipped:

    github              GitHub search API, one topic query per category
    hn                  Hacker News "Show HN" posts that link a GitHub repo
    awesome-selfhosted  entries added to awesome-selfhosted-data in the window,
                        read from a shallow clone (no API quota spent)
    cncf                CNCF landscape sandbox and incubating projects accepted
                        in the window, from landscape.yml
    distrowatch         DistroWatch's latest distribution releases (RSS)

Every GitHub candidate is judged on facts from the GitHub API. A search hit
already carries them; a candidate from any other source costs one
GET /repos/OWNER/REPO, within a fixed budget, because the unauthenticated core
limit is 60 requests an hour. Filtering happens here, before the model sees
anything: already in the inventory, already posted, archived, disabled, a fork,
stale, too few stars, or a license outside the OSI allowlist. What is left is
scored on deterministic signals and spread across categories.

SECURITY: everything a source returns is untrusted. URLs pass validate_url,
names pass the same text rules as model output, descriptions are cleaned and
capped and reach the model only as data. Bodies are size capped, redirects
are not followed (GitHub API redirects only to api.github.com, so the token
cannot leak), the token is sent to api.github.com only, and XML with a DTD is
refused before parsing.
"""

from __future__ import annotations

import datetime as dt
import functools
import html
import http.client
import json
import math
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from lab_scout.scout import (
    GIT_CLONE_TIMEOUT_SECS,
    GIT_TIMEOUT_SECS,
    GITHUB_API_HOST,
    GITHUB_API_VERSION,
    GITHUB_USER_AGENT,
    NAME_MAX_CHARS,
    Config,
    Deps,
    GitHubRateLimited,
    GitHubRedirect,
    GitRunner,
    Listed,
    NoRedirect,
    Opener,
    Rejected,
    RepoFacts,
    ScoutError,
    Seen,
    canonical_url,
    checked_text,
    clean_text,
    fetch_github_repo,
    is_github_repo_url,
    log,
    parse_ts,
    repo_facts,
    run_git,
    squash,
    validate_url,
)

# ---------------------------------------------------------------------------
# Sources and limits
# ---------------------------------------------------------------------------

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
HN_SEARCH_URL = "https://hn.algolia.com/api/v1/search_by_date"
AWESOME_SELFHOSTED_URL = "https://github.com/awesome-selfhosted/awesome-selfhosted-data"
AWESOME_SELFHOSTED_BRANCH = "master"
CNCF_LANDSCAPE_URL = "https://raw.githubusercontent.com/cncf/landscape/master/landscape.yml"
DISTROWATCH_URL = "https://distrowatch.com/news/dwd.xml"
DISTROWATCH_HOST = "distrowatch.com"

# One query per category. The category is a hint for the spread; the model
# picks the category it posts. {dN} is the date N days ago.
GITHUB_QUERIES = (
    ("topic:self-hosted created:>{d90} stars:>50", "self-hosted"),
    ("topic:homelab created:>{d180} stars:>30", "self-hosted"),
    ("topic:kubernetes created:>{d180} stars:>100", "kubernetes"),
    ("topic:observability created:>{d180} stars:>50", "observability"),
    ("topic:security created:>{d180} stars:>100", "security"),
    ("topic:ros2 pushed:>{d30} stars:>100", "robotics"),
    ("topic:operating-system pushed:>{d30} stars:>200", "os"),
)
GITHUB_SEARCH_PER_PAGE = 30
# Unauthenticated search allows 10 requests a minute. Calls are not spaced
# blindly: when X-RateLimit-Remaining reaches 0 the next call waits for the
# reset, if that is this soon; otherwise the rest of the queries are skipped.
GITHUB_SEARCH_MAX_WAIT_SECS = 65

HN_WINDOW_DAYS = 90
HN_MIN_POINTS = 100
HN_HITS = 100
AWESOME_WINDOW_DAYS = 90
# The clone reaches further back than the window: the oldest commit of a
# shallow clone has no parent, so what it added is not visible as an addition.
AWESOME_CLONE_MARGIN_DAYS = 30
AWESOME_MAX_FILES = 200
AWESOME_PATH_RE = re.compile(r"^software/[a-z0-9][a-z0-9._-]{0,100}\.yml$")
CNCF_WINDOW_DAYS = 365
CNCF_MATURITIES = ("sandbox", "incubating")

# GET /repos/O/R calls for candidates that are not search hits. Ordered within
# each source by the source's own signal (HN points, awesome-selfhosted stars,
# CNCF acceptance date).
ENRICH_CAPS = {"hn": 10, "awesome-selfhosted": 15, "cncf": 10}
ENRICH_MAX = 35
# With GITHUB_TOKEN the core limit is 5000 an hour, so the caps grow.
ENRICH_TOKEN_FACTOR = 4
# Slots each source keeps in the shortlist before categories take turns. A
# source without GitHub facts (DistroWatch) scores low and would otherwise
# never get past the GitHub hits of its category.
SOURCE_FLOOR = 2

MIN_STARS = 20
DESCRIPTION_MAX_CHARS = 300
SOURCE_TIMEOUT_SECS = 30
JSON_MAX_BYTES = 2 << 20
LANDSCAPE_MAX_BYTES = 4 << 20
RSS_MAX_BYTES = 512 << 10
AWESOME_FILE_MAX_BYTES = 64 << 10

# Sources a human curates. A listing there is a signal that search stars,
# which can be farmed, are not.
CURATED_SOURCES = frozenset({"awesome-selfhosted", "cncf", "distrowatch"})

# OSI-approved licenses, by the SPDX ids GitHub's license detection reports.
# Anything else is dropped: no license, NOASSERTION (GitHub could not tell),
# and source-available licenses such as BUSL-1.1 (not BSL-1.0, which is the
# Boost license), SSPL-1.0, Elastic-2.0 or the Commons Clause.
OSI_LICENSES = frozenset({
    "0BSD", "AFL-3.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-2.0", "Artistic-2.0",
    "BSD-2-Clause", "BSD-2-Clause-Patent", "BSD-3-Clause", "BSL-1.0", "CECILL-2.1", "ECL-2.0", "EPL-1.0",
    "EPL-2.0", "EUPL-1.1", "EUPL-1.2", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0",
    "GPL-3.0-only", "GPL-3.0-or-later", "ISC", "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0",
    "LGPL-3.0-only", "LGPL-3.0-or-later", "LPPL-1.3c", "MIT", "MIT-0", "MPL-2.0", "MS-PL", "MS-RL",
    "MulanPSL-2.0", "NCSA", "OFL-1.1", "OSL-3.0", "PostgreSQL", "UPL-1.0", "Unlicense", "Zlib",
})

# Keyword hints from GitHub topics and awesome-selfhosted tags, first match wins.
CATEGORY_KEYWORDS = (
    ("robotics", ("ros", "ros2", "robotics", "robot", "gazebo")),
    ("os", ("operating-system", "kernel", "linux-distribution", "distro", "bsd", "microkernel")),
    ("kubernetes", ("kubernetes", "k8s", "helm", "gitops", "operator")),
    ("observability", ("observability", "monitoring", "prometheus", "grafana", "logging", "tracing", "metrics",
                       "status / uptime pages")),
    ("security", ("security", "siem", "detection", "vulnerability", "password managers", "intrusion")),
    ("networking", ("networking", "network", "vpn", "dns", "proxy", "firewall", "wireguard")),
    ("data", ("database", "analytics", "data", "etl")),
)


class SourceError(ScoutError):
    """A source that cannot be used this run. The message is safe to log."""


class SourceRateLimited(SourceError):
    pass


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------


@dataclass
class Lead:
    """A candidate as the sources describe it, then as the filters judge it."""

    name: str  # empty until the GitHub repo name fills it
    url: str
    github: tuple[str, str] | None
    description: str
    sources: list[str]
    category: str
    repo: dict[str, Any] | None = None  # the GitHub repository object, when known
    facts: RepoFacts | None = None
    created_at: dt.datetime | None = None
    hn_points: int | None = None
    cncf_maturity: str | None = None
    rank_hint: float = 0.0  # the source's own order, for spending the API budget
    score: float = 0.0
    id: str = ""

    def keys(self) -> set[str]:
        names = {squash(self.name)}
        if self.github:
            names.add(squash(self.github[1]))
        names.discard("")
        return names


def source_text(value: Any, limit: int = DESCRIPTION_MAX_CHARS) -> str:
    return clean_text(value, limit) if isinstance(value, str) else ""


def source_name(value: Any) -> str:
    """A display name from a source, or "" when it breaks the name rules
    (a number, a link, an IP address, secret-like text, too long)."""
    if not isinstance(value, str):
        return ""
    try:
        return checked_text(value, "name", NAME_MAX_CHARS)
    except Rejected:
        return ""


def github_lead(url: Any, source: str, category: str, name: Any = "", description: Any = "") -> Lead | None:
    """A Lead for a GitHub repository URL, or None when it is not one."""
    if not isinstance(url, str):
        return None
    try:
        link, pair = validate_url(url.strip())
    except Rejected:
        return None
    if pair is None:
        return None
    return Lead(source_name(name), link, pair, source_text(description), [source], category)


def hint_from_keywords(words: Iterable[str], default: str) -> str:
    lowered = [w.lower() for w in words if isinstance(w, str)]
    for category, keywords in CATEGORY_KEYWORDS:
        if any(word in keywords for word in lowered):
            return category
    return default


# ---------------------------------------------------------------------------
# HTTP for the sources
# ---------------------------------------------------------------------------


@dataclass
class Fetched:
    body: bytes
    headers: Mapping[str, str]


def source_request(url: str, token: str | None = None) -> urllib.request.Request:
    parts = urllib.parse.urlsplit(url)
    headers = {"User-Agent": GITHUB_USER_AGENT, "Accept": "application/json, application/xml;q=0.9, */*;q=0.5"}
    if parts.scheme == "https" and parts.hostname == GITHUB_API_HOST and parts.port is None:
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = GITHUB_API_VERSION
        # SECURITY: the token goes to api.github.com and nowhere else.
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, method="GET", headers=headers)


def default_opener(url: str) -> Opener:
    if urllib.parse.urlsplit(url).hostname == GITHUB_API_HOST:
        return urllib.request.build_opener(GitHubRedirect).open
    return urllib.request.build_opener(NoRedirect).open


def http_get(url: str, opener: Opener | None, max_bytes: int, token: str | None = None) -> Fetched:
    """One GET with a timeout and a body cap, or SourceError."""
    opener = opener or default_opener(url)
    try:
        with opener(source_request(url, token), timeout=SOURCE_TIMEOUT_SECS) as response:
            status = getattr(response, "status", 200)
            if status != 200:
                raise SourceError(f"HTTP {status}")
            body = response.read(max_bytes + 1)
            headers = dict(getattr(response, "headers", None) or {})
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        if code in (403, 429):
            raise SourceRateLimited(f"HTTP {code} (rate limited or forbidden)") from None
        raise SourceError(f"HTTP {code}") from None
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
        # These can carry request details in their text. Keep only the type.
        raise SourceError(type(exc).__name__) from None
    if len(body) > max_bytes:
        raise SourceError("response is larger than the limit")
    return Fetched(body, headers)


def json_body(fetched: Fetched) -> Any:
    try:
        return json.loads(fetched.body)
    except ValueError:
        raise SourceError("response is not JSON") from None


# ---------------------------------------------------------------------------
# GitHub search
# ---------------------------------------------------------------------------


def github_queries(now: dt.datetime) -> list[tuple[str, str]]:
    days = {f"d{n}": (now - dt.timedelta(days=n)).strftime("%Y-%m-%d") for n in (30, 90, 180)}
    return [(query.format(**days), category) for query, category in GITHUB_QUERIES]


def github_search_url(query: str) -> str:
    params = {"q": query, "sort": "stars", "order": "desc", "per_page": str(GITHUB_SEARCH_PER_PAGE)}
    return f"{GITHUB_SEARCH_URL}?{urllib.parse.urlencode(params)}"


def parse_github_search(data: Any, category: str) -> list[Lead]:
    """Leads from one search response. Each hit keeps its repository object:
    it carries the same facts GET /repos/O/R would."""
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise SourceError("search response has no items list")
    leads = []
    for item in items:
        if not isinstance(item, dict):
            continue
        lead = github_lead(item.get("html_url"), "github", category, item.get("name"), item.get("description"))
        if lead is not None:
            lead.repo = item
            leads.append(lead)
    return leads


def search_pause(headers: Mapping[str, str], now_epoch: float) -> float | None:
    """Seconds to wait before the next search call: 0 while calls remain, the
    time to the reset when none do, None when that is too long to wait."""
    lowered = {key.lower(): value for key, value in headers.items()}
    try:
        remaining = int(lowered["x-ratelimit-remaining"])
    except (KeyError, ValueError):
        return 0.0
    if remaining > 0:
        return 0.0
    try:
        wait = max(float(lowered["x-ratelimit-reset"]) - now_epoch, 0.0) + 1.0
    except (KeyError, ValueError):
        return None
    return wait if wait <= GITHUB_SEARCH_MAX_WAIT_SECS else None


def github_source(cfg: Config, deps: Deps, now: dt.datetime) -> list[Lead]:
    leads: list[Lead] = []
    queries = github_queries(now)
    for number, (query, category) in enumerate(queries, start=1):
        try:
            fetched = http_get(github_search_url(query), deps.source_opener, JSON_MAX_BYTES, cfg.github_token)
        except SourceRateLimited as exc:
            if not leads:
                raise
            log.warning("source github: %s on query %d of %d; keeping %d result(s)", exc, number, len(queries), len(leads))
            return leads
        found = parse_github_search(json_body(fetched), category)
        log.debug("source github: %r gave %d", query, len(found))
        leads.extend(found)
        if number < len(queries):
            pause = search_pause(fetched.headers, time.time())
            if pause is None:
                log.warning("source github: search quota spent; skipping the last %d query(ies)", len(queries) - number)
                return leads
            if pause > 0:
                log.info("source github: search quota spent; waiting %.0fs for the reset", pause)
                deps.sleep(pause)
    return leads


# ---------------------------------------------------------------------------
# Hacker News (Algolia)
# ---------------------------------------------------------------------------

SHOW_HN_RE = re.compile(r"(?i)^\s*show\s+hn\s*:\s*")


def hn_url(now: dt.datetime) -> str:
    since = int((now - dt.timedelta(days=HN_WINDOW_DAYS)).timestamp())
    params = {"tags": "show_hn", "numericFilters": f"points>{HN_MIN_POINTS},created_at_i>{since}",
              "hitsPerPage": str(HN_HITS)}
    return f"{HN_SEARCH_URL}?{urllib.parse.urlencode(params)}"


def parse_hn(data: Any, now: dt.datetime) -> list[Lead]:
    """Show HN posts that link a GitHub repository. Anything else is usually a
    product page, which says nothing about a public source repository."""
    hits = data.get("hits") if isinstance(data, dict) else None
    if not isinstance(hits, list):
        raise SourceError("HN response has no hits list")
    oldest = now - dt.timedelta(days=HN_WINDOW_DAYS)
    leads = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        points = hit.get("points")
        created = parse_ts(hit.get("created_at"))
        if not isinstance(points, int) or isinstance(points, bool) or points < HN_MIN_POINTS:
            continue
        if created is None or created < oldest:
            continue
        title = hit.get("title")
        description = SHOW_HN_RE.sub("", title) if isinstance(title, str) else ""
        lead = github_lead(hit.get("url"), "hn", "self-hosted", description=description)
        if lead is not None:
            lead.hn_points = points
            lead.rank_hint = points
            leads.append(lead)
    return leads


def hn_source(cfg: Config, deps: Deps, now: dt.datetime) -> list[Lead]:
    return parse_hn(json_body(http_get(hn_url(now), deps.source_opener, JSON_MAX_BYTES)), now)


# ---------------------------------------------------------------------------
# awesome-selfhosted-data (shallow clone)
# ---------------------------------------------------------------------------

YAML_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(?:[ \t]+(.*?))?[ \t]*$")
YAML_LIST_ITEM_RE = re.compile(r"^[ \t]+-[ \t]+(.*?)[ \t]*$")


def yaml_scalar(raw: str) -> str | None:
    """A one-line YAML scalar: plain, 'single' or "double" quoted. None for
    anything this narrow reader does not handle (block scalars, flow
    collections, an unterminated quote)."""
    value = raw.strip()
    if not value or value[0] in "|>[{&*!":
        return None
    if value[0] == "'":
        if len(value) < 2 or value[-1] != "'":
            return None
        return value[1:-1].replace("''", "'")
    if value[0] == '"':
        if len(value) < 2 or value[-1] != '"':
            return None
        try:
            decoded = json.loads(value)
        except ValueError:
            return None
        return decoded if isinstance(decoded, str) else None
    return re.sub(r"[ \t]+#.*$", "", value)


def parse_awesome_entry(text: str) -> dict[str, Any]:
    """The fields lab-scout uses from one software/*.yml entry. Top-level
    keys only, one-line scalars and lists of scalars; a plain scalar continued
    on indented lines is folded with spaces, as YAML does."""
    entry: dict[str, Any] = {}
    key: str | None = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        top = YAML_KEY_RE.match(line)
        if top:
            key, raw = top.group(1), top.group(2)
            entry[key] = yaml_scalar(raw) if raw else []
            continue
        item = YAML_LIST_ITEM_RE.match(line)
        if item and key is not None and isinstance(entry.get(key), list):
            entry[key].append(yaml_scalar(item.group(1)))
            continue
        if key is not None and line[:1] in " \t" and isinstance(entry.get(key), str):
            entry[key] = f"{entry[key]} {line.strip()}"
    return entry


def awesome_lead(entry: Mapping[str, Any]) -> Lead | None:
    """A Lead from an awesome-selfhosted entry, or None. Only GitHub sources
    qualify: elsewhere there are no facts to check."""
    if entry.get("archived") == "true":
        return None
    licenses = [x for x in entry.get("licenses") or [] if isinstance(x, str)]
    if not any(x in OSI_LICENSES for x in licenses):
        return None
    tags = [x for x in entry.get("tags") or [] if isinstance(x, str)]
    lead = github_lead(entry.get("source_code_url"), "awesome-selfhosted", hint_from_keywords(tags, "self-hosted"),
                       entry.get("name"), entry.get("description"))
    if lead is None:
        return None
    stars = entry.get("stargazers_count")
    # Their crawler's count, only to order the API budget. Never shown.
    lead.rank_hint = float(stars) if isinstance(stars, str) and stars.isdigit() else 0.0
    return lead


def awesome_clone_argv(url: str, since: str, checkout: str) -> list[str]:
    return ["git", "clone", f"--shallow-since={since}", "--no-checkout", "--single-branch",
            "--branch", AWESOME_SELFHOSTED_BRANCH, "--", url, checkout]


def awesome_source(cfg: Config, deps: Deps, now: dt.datetime) -> list[Lead]:
    url = deps.awesome_selfhosted_url or AWESOME_SELFHOSTED_URL
    # Checked like an inventory source: the URL becomes an argv element.
    if not (deps.repo_url_ok or is_github_repo_url)(url):
        raise SourceError("awesome-selfhosted URL is not an allowed repository URL")
    runner: GitRunner = deps.git_runner or functools.partial(run_git, allow_protocols=deps.git_protocols)
    window_start = (now - dt.timedelta(days=AWESOME_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    clone_since = (now - dt.timedelta(days=AWESOME_WINDOW_DAYS + AWESOME_CLONE_MARGIN_DAYS)).strftime("%Y-%m-%d")
    leads: list[Lead] = []
    with tempfile.TemporaryDirectory(prefix="lab-scout-awesome-") as scratch:
        checkout = os.path.join(scratch, "repo")
        try:
            runner(awesome_clone_argv(url, clone_since, checkout), GIT_CLONE_TIMEOUT_SECS)
            # log.showRoot=false: the shallow boundary commit looks like a root
            # commit that adds every file, and must not count.
            added = runner(["git", "-C", checkout, "-c", "log.showRoot=false", "log", f"--since={window_start}",
                            "--diff-filter=A", "--name-only", "--format=", "HEAD", "--", "software/"],
                           GIT_TIMEOUT_SECS)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SourceError(f"git failed ({type(exc).__name__})") from None
        paths = list(dict.fromkeys(p.strip() for p in added.splitlines() if AWESOME_PATH_RE.match(p.strip())))
        for path in paths[:AWESOME_MAX_FILES]:
            try:
                text = runner(["git", "-C", checkout, "show", f"HEAD:{path}"], GIT_TIMEOUT_SECS)
            except (ScoutError, OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
                # Added and then removed or renamed inside the window.
                continue
            if len(text) > AWESOME_FILE_MAX_BYTES:
                continue
            lead = awesome_lead(parse_awesome_entry(text))
            if lead is not None:
                leads.append(lead)
        log.debug("source awesome-selfhosted: %d entries added, %d usable", len(paths), len(leads))
    return leads


# ---------------------------------------------------------------------------
# CNCF landscape (landscape.yml, read line by line)
# ---------------------------------------------------------------------------

LANDSCAPE_NODE_RE = re.compile(r"^- (category|subcategory|item):\s*$")
LANDSCAPE_ITEM_KEYS = ("name", "description", "repo_url", "project")
BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?$")


def split_key(stripped: str) -> tuple[str, str] | None:
    match = YAML_KEY_RE.match(stripped)
    return (match.group(1), match.group(2) or "") if match else None


def parse_landscape(text: str) -> list[dict[str, str | None]]:
    """Items of landscape.yml with the fields lab-scout uses.

    landscape.yml has a fixed shape: `- category:` and `- subcategory:` nodes,
    and under each subcategory's `items:` a list of items, written either as
    `- item:` followed by its keys or as `- name: X` with the first key on the
    dash line. Item keys sit two columns right of the dash, with an `extra:`
    map one level deeper. Only the keys lab-scout uses are read: one-line
    scalars, plus a folded or literal block (`>-`, `|`) or an indented plain
    continuation, both joined with spaces. Anything else is None. Checked
    against PyYAML on a captured excerpt in the tests.
    """
    items: list[dict[str, str | None]] = []
    names = {"category": "", "subcategory": ""}
    item: dict[str, str | None] | None = None
    node: str | None = None
    key_indent = -1
    item_dash: int | None = None  # the column of the dash before each item
    expect_items = False
    in_extra = False
    block_key: str | None = None  # an item key whose value continues below

    def set_item_key(key: str, raw: str) -> None:
        nonlocal block_key
        assert item is not None
        if BLOCK_SCALAR_RE.match(raw.strip()):
            item[key], block_key = "", key
        else:
            item[key] = yaml_scalar(raw)
            # Only a plain scalar can continue on the next lines.
            plain = bool(raw.strip()) and raw.strip()[0] not in "'\""
            block_key = key if plain else None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if item is not None and block_key is not None and indent > key_indent and not in_extra:
            joined = f"{item.get(block_key) or ''} {stripped}".strip()
            item[block_key] = joined
            continue
        block_key = None
        found = LANDSCAPE_NODE_RE.match(stripped)
        if found:
            node, key_indent, in_extra, item = found.group(1), indent + 2, False, None
            if node == "item":
                item_dash = indent
                item = {"category": names["category"], "subcategory": names["subcategory"]}
                items.append(item)
            else:
                expect_items, item_dash = False, None
            continue
        if (stripped.startswith("- ") and expect_items and (item_dash is None or indent == item_dash)
                and (first := split_key(stripped[2:].strip()))):
            node, key_indent, in_extra, item_dash = "item", indent + 2, False, indent
            item = {"category": names["category"], "subcategory": names["subcategory"]}
            items.append(item)
            if first[0] in LANDSCAPE_ITEM_KEYS:
                set_item_key(*first)
            continue
        if node is None or indent < key_indent:
            node, item = None, None
            continue
        pair = split_key(stripped)
        if indent == key_indent and pair:
            key, raw = pair
            in_extra = key == "extra" and not raw
            if node in names and key == "name":
                names[node] = yaml_scalar(raw) or ""
                if node == "category":
                    names["subcategory"] = ""
            elif node == "subcategory" and key == "items" and not raw:
                expect_items = True
            elif item is not None and key in LANDSCAPE_ITEM_KEYS:
                set_item_key(key, raw)
        elif item is not None and in_extra and indent == key_indent + 2 and pair and pair[0] == "accepted":
            item["accepted"] = yaml_scalar(pair[1])
    return items


def cncf_category(item: Mapping[str, str | None]) -> str:
    category = (item.get("category") or "").lower()
    subcategory = (item.get("subcategory") or "").lower()
    if "observability" in category:
        return "observability"
    if "security" in subcategory:
        return "security"
    return "kubernetes"


def cncf_leads(items: Iterable[Mapping[str, str | None]], now: dt.datetime) -> list[Lead]:
    oldest = (now - dt.timedelta(days=CNCF_WINDOW_DAYS)).date()
    leads = []
    for item in items:
        maturity = item.get("project")
        if maturity not in CNCF_MATURITIES:
            continue
        try:
            accepted = dt.date.fromisoformat(item.get("accepted") or "")
        except ValueError:
            continue
        if accepted < oldest or accepted > now.date():
            continue
        lead = github_lead(item.get("repo_url"), "cncf", cncf_category(item), item.get("name"), item.get("description"))
        if lead is not None:
            lead.cncf_maturity = maturity
            lead.rank_hint = accepted.toordinal()
            leads.append(lead)
    return leads


def cncf_source(cfg: Config, deps: Deps, now: dt.datetime) -> list[Lead]:
    fetched = http_get(CNCF_LANDSCAPE_URL, deps.source_opener, LANDSCAPE_MAX_BYTES)
    try:
        text = fetched.body.decode("utf-8")
    except UnicodeDecodeError:
        raise SourceError("landscape.yml is not UTF-8") from None
    items = parse_landscape(text)
    if not items:
        raise SourceError("landscape.yml has no items this reader recognises")
    return cncf_leads(items, now)


# ---------------------------------------------------------------------------
# DistroWatch (RSS)
# ---------------------------------------------------------------------------

DTD_RE = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]*>")
RELEASE_TOKEN_RE = re.compile(r"^[vV]?\d")


def release_name(title: str) -> str:
    """'Rocky Linux 10.0 RC1' -> 'Rocky Linux'. Cut at the first word after
    the first that starts with a digit; a name that starts with one
    (4MLinux) keeps that word."""
    words = title.split()
    for index, word in enumerate(words[1:], start=1):
        if RELEASE_TOKEN_RE.match(word):
            return " ".join(words[:index])
    return " ".join(words)


def parse_distrowatch(body: bytes) -> list[Lead]:
    if len(body) > RSS_MAX_BYTES:
        raise SourceError("feed is larger than the limit")
    # SECURITY: no DTD at all, so no entity expansion of any kind.
    if DTD_RE.search(body):
        raise SourceError("feed declares a DTD; refused")
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        raise SourceError("feed is not well-formed XML") from None
    leads = []
    for node in root.iter("item"):
        title = node.findtext("title") or ""
        link = (node.findtext("link") or "").strip()
        try:
            url, pair = validate_url(link)
        except Rejected:
            continue
        if pair is not None or urllib.parse.urlsplit(url).hostname != DISTROWATCH_HOST:
            continue
        name = source_name(release_name(clean_text(title, 200)))
        if not name:
            continue
        description = source_text(html.unescape(TAG_RE.sub(" ", node.findtext("description") or "")))
        leads.append(Lead(name, url, None, description, ["distrowatch"], "os"))
    return leads


def distrowatch_source(cfg: Config, deps: Deps, now: dt.datetime) -> list[Lead]:
    return parse_distrowatch(http_get(DISTROWATCH_URL, deps.source_opener, RSS_MAX_BYTES).body)


SOURCES = {
    "github": github_source,
    "hn": hn_source,
    "awesome-selfhosted": awesome_source,
    "cncf": cncf_source,
    "distrowatch": distrowatch_source,
}


# ---------------------------------------------------------------------------
# Merging, facts and filtering
# ---------------------------------------------------------------------------

# Which source's name and description win when several list one project.
SOURCE_PRIORITY = ("cncf", "awesome-selfhosted", "distrowatch", "github", "hn")


def merge(leads: Iterable[Lead]) -> list[Lead]:
    """One Lead per project (by canonical URL), keeping every source's signal."""
    merged: dict[str, Lead] = {}
    for lead in leads:
        key = canonical_url(lead.url)
        kept = merged.get(key)
        if kept is None:
            merged[key] = lead
            continue
        better = SOURCE_PRIORITY.index(lead.sources[0]) < min(SOURCE_PRIORITY.index(s) for s in kept.sources)
        if lead.name and (better or not kept.name):
            kept.name = lead.name
        if lead.description and (better or not kept.description):
            kept.description = lead.description
        if "github" in lead.sources:
            # A search query's category is the most specific hint there is.
            kept.category = lead.category
        kept.sources += [s for s in lead.sources if s not in kept.sources]
        kept.repo = kept.repo or lead.repo
        if lead.hn_points is not None:
            kept.hn_points = max(kept.hn_points or 0, lead.hn_points)
        kept.cncf_maturity = kept.cncf_maturity or lead.cncf_maturity
        kept.rank_hint = max(kept.rank_hint, lead.rank_hint)
    return list(merged.values())


class Known:
    """What dedup compares against: the inventory and the seen state."""

    def __init__(self, inventory: Iterable[str], seen: Seen) -> None:
        self.inventory = {squash(name) for name in inventory if squash(name)}
        self.seen_names = seen.name_keys()
        self.seen_urls = seen.url_keys()

    def reason(self, lead: Lead) -> str | None:
        keys = lead.keys()
        if keys & self.inventory:
            return "already in the lab inventory"
        urls = {canonical_url(lead.url)}
        if lead.facts is not None:
            urls.add(canonical_url(lead.facts.html_url))
        if keys & self.seen_names or urls & self.seen_urls:
            return "already suggested in an earlier digest"
        return None


def apply_repo(lead: Lead, now: dt.datetime, max_stale_days: int) -> None:
    """Judge a GitHub lead on its repository object, or Rejected."""
    assert lead.github is not None and lead.repo is not None
    data = lead.repo
    facts = repo_facts(lead.github[0], lead.github[1], data, now, max_stale_days)
    if data.get("fork") is not False:
        raise Rejected("GitHub repo is a fork" if data.get("fork") is True else "GitHub fork flag missing")
    if facts.license not in OSI_LICENSES:
        raise Rejected("license is not on the OSI allowlist")
    if facts.stars < MIN_STARS:
        raise Rejected(f"fewer than {MIN_STARS} stars")
    lead.facts = facts
    lead.created_at = parse_ts(data.get("created_at"))
    # The repo may have been renamed: the API's names are the current ones.
    lead.github = validate_url(facts.html_url)[1] or lead.github
    lead.url = facts.html_url
    if not lead.name:
        lead.name = source_name(data.get("name"))
        if not lead.name:
            raise Rejected("repository name breaks the name rules")
    if not lead.description:
        lead.description = source_text(data.get("description"))
    if lead.sources == ["hn"]:
        topics = data.get("topics")
        lead.category = hint_from_keywords(topics if isinstance(topics, list) else [], lead.category)


@dataclass
class Budget:
    """GET /repos/O/R calls left this run. A rate limit spends the rest."""

    left: int = ENRICH_MAX
    used: int = 0
    limited: bool = False


def enrich(leads: list[Lead], budget: Budget, deps: Deps, token: str | None) -> None:
    """Fetch the repository object for GitHub leads that do not have one,
    best first within each source, up to each source's cap."""
    factor = ENRICH_TOKEN_FACTOR if token else 1
    used: Counter[str] = Counter()
    wanting = [lead for lead in leads if lead.github and lead.repo is None]
    wanting.sort(key=lambda lead: -lead.rank_hint)
    for lead in wanting:
        assert lead.github is not None
        source = lead.sources[0]
        if budget.limited or budget.left <= 0 or used[source] >= ENRICH_CAPS.get(source, 0) * factor:
            continue
        budget.left -= 1
        budget.used += 1
        used[source] += 1
        try:
            data = fetch_github_repo(lead.github[0], lead.github[1], deps.github_opener, token)
        except GitHubRateLimited:
            budget.limited = True
            log.warning("discovery: GitHub API rate limited; no more repository lookups this run")
            continue
        except Rejected:
            continue
        if isinstance(data, dict):
            lead.repo = data


def score(lead: Lead, now: dt.datetime) -> float:
    """Deterministic rank. Stars count on a log scale; star velocity (stars a
    day since creation) and a push in the last month add to it; HN points,
    a curated listing and agreement between sources add more."""
    value = 0.0
    if lead.facts is not None:
        stars = lead.facts.stars
        value += math.log10(1 + stars)
        if lead.created_at is not None:
            age_days = max((now - lead.created_at).days, 7)
            value += 1.5 * math.log10(1 + stars / age_days)
        push_days = max((now - lead.facts.pushed_at).days, 0)
        value += max(0.0, 1 - push_days / 30)
    if lead.hn_points:
        value += 0.8 * math.log10(1 + lead.hn_points)
    if CURATED_SOURCES & set(lead.sources):
        value += 1.0
    value += 0.5 * (len(set(lead.sources)) - 1)
    return round(value, 3)


def spread(leads: list[Lead], size: int) -> list[Lead]:
    """The best `size` leads. First the best SOURCE_FLOOR of every source (by
    the source that found them first), then round robin across categories:
    the best of every category before the second best of any, categories
    taking turns in the order of their best lead. Ids follow that order."""
    ordered = sorted(leads, key=lambda lead: (-lead.score, lead.name.lower(), lead.url))
    picked: list[Lead] = []
    per_source: Counter[str] = Counter()
    for lead in ordered:
        if per_source[lead.sources[0]] < SOURCE_FLOOR and len(picked) < size:
            per_source[lead.sources[0]] += 1
            picked.append(lead)
    chosen = {id(lead) for lead in picked}
    by_category: dict[str, list[Lead]] = {}
    for lead in ordered:
        if id(lead) not in chosen:
            by_category.setdefault(lead.category, []).append(lead)
    depth = 0
    while len(picked) < size and any(depth < len(group) for group in by_category.values()):
        for group in by_category.values():
            if depth < len(group) and len(picked) < size:
                picked.append(group[depth])
        depth += 1
    for number, lead in enumerate(picked, start=1):
        lead.id = f"c{number:02d}"
    return picked


# ---------------------------------------------------------------------------
# The whole pass
# ---------------------------------------------------------------------------


@dataclass
class SourceReport:
    name: str
    status: str
    found: int = 0
    detail: str = ""


@dataclass
class Discovery:
    shortlist: list[Lead]
    sources: list[SourceReport]
    considered: int = 0
    dropped: Counter[str] = field(default_factory=Counter)
    api_calls: int = 0

    def listed(self) -> list[Listed]:
        return [Listed(lead.id, lead.name, lead.url, lead.github, lead.facts) for lead in self.shortlist]

    def prompt_records(self) -> list[dict[str, Any]]:
        """What the model sees: data only, no links."""
        return [prompt_record(lead) for lead in self.shortlist]

    def report(self) -> dict[str, Any]:
        return {
            "sources": [vars(report) for report in self.sources],
            "considered": self.considered,
            "dropped": dict(sorted(self.dropped.items())),
            "github_repo_lookups": self.api_calls,
            "shortlist": [{**prompt_record(lead), "url": lead.url, "score": lead.score} for lead in self.shortlist],
        }


def prompt_record(lead: Lead) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    if lead.facts is not None:
        facts["stars"] = lead.facts.stars
        facts["last_push"] = lead.facts.pushed_at.strftime("%Y-%m-%d")
        facts["license"] = lead.facts.license
    if lead.created_at is not None:
        facts["created"] = lead.created_at.strftime("%Y-%m-%d")
    if lead.hn_points is not None:
        facts["hn_points"] = lead.hn_points
    if lead.cncf_maturity:
        facts["cncf_maturity"] = lead.cncf_maturity
    record: dict[str, Any] = {"id": lead.id, "name": lead.name}
    if lead.github:
        record["repo"] = f"{lead.github[0]}/{lead.github[1]}"
    record.update({"sources": list(lead.sources), "category_hint": lead.category,
                   "description": lead.description or "(none given)", "facts": facts})
    return record


def run_sources(cfg: Config, deps: Deps, now: dt.datetime) -> tuple[list[Lead], list[SourceReport]]:
    leads: list[Lead] = []
    reports = []
    for name in cfg.sources:
        try:
            found = SOURCES[name](cfg, deps, now)
        except ScoutError as exc:
            reports.append(SourceReport(name, "failed", detail=str(exc)))
            log.warning("source %s failed (%s); skipping it", name, exc)
            continue
        except Exception as exc:  # noqa: BLE001  one broken source must never stop the others
            reports.append(SourceReport(name, "failed", detail=type(exc).__name__))
            log.warning("source %s failed unexpectedly (%s); skipping it", name, type(exc).__name__)
            continue
        reports.append(SourceReport(name, "ok", found=len(found)))
        log.info("source %s: %d candidate(s)", name, len(found))
        leads.extend(found)
    return leads, reports


def discover(cfg: Config, deps: Deps, inventory: Iterable[str], seen: Seen, now: dt.datetime) -> Discovery:
    """Collect, filter, rank. Never raises for a source; an empty shortlist
    is the caller's failure to report."""
    raw, reports = run_sources(cfg, deps, now)
    leads = merge(raw)
    result = Discovery([], reports, considered=len(leads))
    known = Known(inventory, seen)

    def keep(lead: Lead, reason: str | None) -> bool:
        if reason is None:
            return True
        result.dropped[reason] += 1
        return False

    # Cheap checks first, so no API call is spent on a known project.
    leads = [lead for lead in leads if keep(lead, known.reason(lead))]
    budget = Budget(ENRICH_MAX * (ENRICH_TOKEN_FACTOR if cfg.github_token else 1))
    enrich(leads, budget, deps, cfg.github_token)
    result.api_calls = budget.used
    survivors = []
    urls: set[str] = set()
    for lead in leads:
        if lead.github is not None:
            if lead.repo is None:
                keep(lead, "no GitHub facts (lookup budget, rate limit or not found)")
                continue
            try:
                apply_repo(lead, now, cfg.max_stale_days)
            except Rejected as exc:
                keep(lead, str(exc))
                continue
            # Again with the current repo name and URL.
            if not keep(lead, known.reason(lead)):
                continue
        # Two sources can name one repo by its old and its new name.
        if not keep(lead, "duplicate of another candidate" if canonical_url(lead.url) in urls else None):
            continue
        urls.add(canonical_url(lead.url))
        lead.score = score(lead, now)
        survivors.append(lead)
    result.shortlist = spread(survivors, cfg.shortlist_size)
    log.info("discovery: %d candidate(s), %d dropped, %d repo lookup(s), shortlist of %d",
             result.considered, sum(result.dropped.values()), result.api_calls, len(result.shortlist))
    for reason, count in sorted(result.dropped.items()):
        log.info("discovery: dropped %d: %s", count, reason)
    return result

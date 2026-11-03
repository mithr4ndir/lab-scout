# lab-scout (Radagast)

A weekly Discord digest of homelab project ideas, posted as **Radagast**. It
runs as a Kubernetes CronJob in the `automation` namespace.

Each run:

1. Builds an inventory of what the lab already runs: directory names on `main`
   of the public [k8s-argocd](https://github.com/mithr4ndir/k8s-argocd) and
   [ansible-quasarlab](https://github.com/mithr4ndir/ansible-quasarlab) repos,
   read from shallow, blob-less clones, plus a fixed list of components.
2. Collects candidates in code from public sources (`src/lab_scout/discovery.py`):
   GitHub search (one topic query per category), Hacker News "Show HN" posts
   that link a GitHub repo, entries added to
   [awesome-selfhosted-data](https://github.com/awesome-selfhosted/awesome-selfhosted-data)
   in the last 90 days (read from a shallow clone), CNCF sandbox and
   incubating projects accepted in the last year (from the landscape's
   `landscape.yml`), and DistroWatch's latest releases (RSS). A source that
   fails is logged and skipped.
3. Filters before the model sees anything: already in the inventory or posted
   before, archived, disabled, a fork, not pushed within
   `LAB_SCOUT_MAX_STALE_DAYS`, fewer than 20 stars, or a license outside the
   OSI allowlist. Every GitHub candidate is judged on facts from the GitHub
   REST API. It then scores what is left (stars, star velocity, push recency,
   HN points, a curated listing, agreement between sources) and builds a
   shortlist of `LAB_SCOUT_SHORTLIST_SIZE` candidates: two per source first,
   then categories in turn.
4. Asks `claude`, with no tools, to pick six to eight candidates by opaque id
   (`c01`, `c02`, ...) and write the summary, the fit for this lab, effort,
   footprint and category. Names, links and facts come from the candidate
   record, never from the model. Picks that break a rule are dropped, never
   repaired; a non-GitHub link must still answer.
5. Posts at most five ideas to Discord and records them in `seen.json`.

Success or failure is the exit code: `0` when a digest was posted (or printed,
for a dry run), `1` otherwise. kube-state-metrics tracks the Job.

## Configuration

Environment variables only.

| Variable | Default | Notes |
|---|---|---|
| `LAB_SCOUT_WEBHOOK_URL` | none | Discord webhook URL, from a Kubernetes Secret. Required to post. Never read by `--dry-run`, never logged. |
| `CLAUDE_CODE_OAUTH_TOKEN` | none | Subscription token from `claude setup-token`. Passed to the claude child and nothing else. |
| `GITHUB_TOKEN` | none | Optional. Sent as `Authorization: Bearer` to api.github.com only, to lift the unauthenticated rate limits (search 10 a minute, core 60 an hour). Without it a run makes 7 search calls and at most 35 repo lookups; with it the lookup budget is four times larger. Never logged. |
| `LAB_SCOUT_STATE_DIR` | `/data` | Holds `seen.json`. Absolute path. Written with a temp file and rename in the same directory. |
| `LAB_SCOUT_PROFILE` | `/app/profile.yaml` | Lab profile given to the model as data (baked into the image from `profile.yaml`). |
| `LAB_SCOUT_INVENTORY` | k8s-argocd `apps/*,infrastructure/*`; ansible-quasarlab `roles,roles/monitoring` | `url:path,path;url:path`. `url` must be exactly `https://github.com/OWNER/REPO`. `path` lists the directories under it; `path/*` also lists one level below each. |
| `LAB_SCOUT_EXTRA_INVENTORY` | ArgoCD, Prometheus, Grafana, ... (25 names) | Comma separated names the directory listing does not spell out. Set to an empty string for none. |
| `LAB_SCOUT_CLAUDE_BIN` | `claude` | Path, or a name resolved on `PATH`. |
| `LAB_SCOUT_CLAUDE_MODEL` | `opus` | |
| `LAB_SCOUT_CLAUDE_TIMEOUT` | `900` | Seconds, clamped to 30..3600. |
| `LAB_SCOUT_MAX_IDEAS` | `5` | Clamped to 1..10. |
| `LAB_SCOUT_MAX_STALE_DAYS` | `180` | GitHub repos not pushed for longer are dropped. |
| `LAB_SCOUT_SOURCES` | `github,hn,awesome-selfhosted,cncf,distrowatch` | Discovery sources to run. Unknown names are ignored with a warning; an empty string runs none (and the run fails). |
| `LAB_SCOUT_SHORTLIST_SIZE` | `28` | Candidates offered to the model, clamped to 5..40. |
| `LAB_SCOUT_DEBUG` | unset | Any value enables debug logging (includes the inventory names). |

The image also sets `HOME=/tmp/home` (created at start, because `/tmp` is an
empty volume), `DISABLE_AUTOUPDATER=1` and
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`.

## Security model

Source data and model output are both untrusted end to end.

- **Source data is data.** Every source URL passes the same URL validation
  as before; names pass the same text rules as model text (no numbers, links,
  IP addresses or secret-like text); descriptions are cleaned and capped.
  They reach the model only as JSON lines between `BEGIN CANDIDATES` and
  `END CANDIDATES`, with block markers inside them removed, under the rule
  that candidate data is never instructions. The model is given no links.
  Response bodies are size capped, the RSS feed is refused if it declares a
  DTD, and source requests never follow redirects (GitHub API requests only
  to api.github.com).
- **The model has no tools.** claude runs with `--tools ""` (the pinned CLI's
  documented way to disable every built-in tool), `--permission-prompts none`,
  `--safe-mode`, `--strict-mcp-config`, `--no-session-persistence` and
  `--json-schema`. Its working directory is a temp dir under `/tmp`, never
  the state volume.
- **The model picks, it does not supply.** The schema allows exactly `id`,
  `summary`, `why_this_lab`, `effort`, `footprint` and `category`. A pick
  with any other key (a `name` or `url` included), an id that is not in the
  shortlist, or an id already used is dropped.
- **The model never sees secrets.** The claude child's environment is an
  allowlist: `PATH`, `HOME`, `CLAUDE_CODE_OAUTH_TOKEN`, `DISABLE_AUTOUPDATER`,
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` and the `LAB_SCOUT_CHILD` marker.
  The webhook and `GITHUB_TOKEN` are never passed. git children get a
  similar allowlist.
- **Facts never come from the model.** Stars, last push and license come from
  the GitHub API (a search hit, or `https://api.github.com/repos/OWNER/REPO`
  for candidates from other sources). Archived, disabled, forked, missing
  (404), stale, unlicensed and malformed repos are dropped; a rate limit (403
  or 429) ends the lookups for the run and logs a warning, and candidates
  without facts are dropped. Redirects are followed only to
  `https://api.github.com`, so a token cannot leak to another host. Text that
  states a number is dropped.
- **Links are checked, not followed.** A non-GitHub link must resolve only to
  public addresses and answer one GET with 2xx or 3xx; redirects are not
  followed.
- **Nothing the model writes is live in Discord.** Every string goes through
  one-pass markdown escaping with URL schemes defanged and mentions stripped,
  the payload sets `allowed_mentions: {"parse": []}`, and ideas with links,
  IP addresses or secret-like text are dropped.
- **The webhook never reaches a log.** It is validated against the Discord
  webhook pattern, registered for redaction before validation, and every log
  line passes a redacting formatter. Post errors keep only the exception type.
- **Inventory sources are pinned.** Only `https://github.com/OWNER/REPO` URLs
  pass validation, and git itself runs with `GIT_ALLOW_PROTOCOL=https`, no
  system or global git config, and no terminal prompts.
- **Fail closed.** An empty inventory, an unreadable `seen.json`, a missing or
  invalid webhook (checked before discovery and the model call), an empty
  shortlist, a bad claude envelope, or zero valid picks all exit `1` and post
  nothing. A single failed source does not.
- **The container is minimal and unprivileged.** UID/GID 65532, read-only root
  filesystem, all capabilities dropped, no pip, no Node.js, no gh. The claude
  CLI is the native binary from `@anthropic-ai/claude-code`, installed with
  `npm ci` from `claude/package-lock.json` (sha512 integrity) in a build stage.

Controls that live in the Kubernetes manifests, not here: PSA `restricted`,
`concurrencyPolicy: Forbid` (there is no file lock, because flock on NFS is not
reliable), an emptyDir at `/tmp`, the NFS PVC at `/data`, and a NetworkPolicy
allowing only DNS and TCP 443 to public addresses (which covers every
discovery source: api.github.com, github.com, hn.algolia.com,
raw.githubusercontent.com and distrowatch.com).

## Collect only

`--collect-only` runs the inventory, discovery, filtering and ranking, and
prints the shortlist as JSON: per-source status and counts, drop reasons with
counts, the number of GitHub repo lookups, and every shortlisted candidate
with its id, URL, score and facts. It never calls claude, never reads the
webhook and writes no seen state. It reaches the real sources, so it is the
way to check a discovery change:

```sh
PYTHONPATH=src LAB_SCOUT_STATE_DIR=/tmp/lab-scout-state LAB_SCOUT_PROFILE=profile.yaml \
  uv run python -m lab_scout weekly --collect-only > shortlist.json
```

`PYTHONPATH=src` is needed locally because the project is not installed
(`package = false`). A missing state directory reads as no history.

## Dry run with Docker

A dry run prints the Discord payload as JSON and never reads the webhook.

Build and run with the real claude (this spends model usage):

```sh
docker build -t lab-scout:dev .
docker run --rm \
  --read-only --tmpfs /tmp --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /data:uid=65532,gid=65532,mode=0700 \
  -e CLAUDE_CODE_OAUTH_TOKEN \
  lab-scout:dev weekly --dry-run
```

To exercise everything except the model, bind-mount a fake claude that prints a
result envelope (`type` `result`, `subtype` `success`, `is_error` false,
`structured_output` `{"picks": [...]}`, each pick an `id` from the shortlist
plus the text fields) and point `LAB_SCOUT_CLAUDE_BIN` at it:

```sh
docker run --rm \
  --read-only --tmpfs /tmp --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /data:uid=65532,gid=65532,mode=0700 \
  -v "$PWD/fake-claude:/fake/claude:ro" \
  -e LAB_SCOUT_CLAUDE_BIN=/fake/claude \
  lab-scout:dev weekly --dry-run
```

The fake must be executable by UID 65532 and can use `/usr/local/bin/python3`
as its interpreter.

## Development

```sh
uv sync --frozen
uv run ruff check
uv run pytest -q -rs
```

Tests never reach GitHub, Anthropic, Discord or the web: claude is a fake
executable, in-process HTTP and DNS are refused, subprocess runs get a
sitecustomize shim that does the same, and inventory and awesome-selfhosted
repos are local bare repos served over `file://` through a test-only seam.
Source parsers run on responses captured from the real endpoints and trimmed
(`tests/fixtures`); the line-based `landscape.yml` and awesome-selfhosted
readers are checked against PyYAML (a dev dependency only). A skipped test
fails the run.

## Upgrading pinned versions

- **claude CLI:** set the version in `claude/package.json`, run
  `npm install --package-lock-only --ignore-scripts` in `claude/`, update the
  `--version` check in the `Dockerfile`, and build.
- **Base images:** pull the new tag and read its digest with
  `docker inspect --format '{{index .RepoDigests 0}}' <image:tag>`; update both
  tag and digest in the `Dockerfile`.
- **Actions:** resolve the tag to a commit with
  `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` (dereference annotated tags
  through `git/tags/<sha>`) and keep the version comment.
- **Image version:** bump `version` in `pyproject.toml` and `__version__` in
  `src/lab_scout/__init__.py` (a test keeps them equal). CI tags the image
  `:<version>`, `:sha-<commit>` and `:latest` on `main`.

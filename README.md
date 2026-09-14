# lab-scout (Radagast)

A weekly Discord digest of homelab project ideas, posted as **Radagast**. It
runs as a Kubernetes CronJob in the `automation` namespace.

Each run:

1. Builds an inventory of what the lab already runs: directory names on `main`
   of the public [k8s-argocd](https://github.com/mithr4ndir/k8s-argocd) and
   [ansible-quasarlab](https://github.com/mithr4ndir/ansible-quasarlab) repos,
   read from shallow, blob-less clones, plus a fixed list of components.
2. Asks `claude` (web search and allowlisted web fetch only) for six to eight
   candidate projects as JSON matching a closed schema.
3. Validates every candidate and drops (never repairs) anything that breaks a
   rule, fact-checks GitHub repos against the GitHub REST API, checks other
   links answer, and removes anything already in the inventory or posted
   before.
4. Posts at most five ideas to Discord and records them in `seen.json`.

Success or failure is the exit code: `0` when a digest was posted (or printed,
for a dry run), `1` otherwise. kube-state-metrics tracks the Job.

## Configuration

Environment variables only.

| Variable | Default | Notes |
|---|---|---|
| `LAB_SCOUT_WEBHOOK_URL` | none | Discord webhook URL, from a Kubernetes Secret. Required to post. Never read by `--dry-run`, never logged. |
| `CLAUDE_CODE_OAUTH_TOKEN` | none | Subscription token from `claude setup-token`. Passed to the claude child and nothing else. |
| `GITHUB_TOKEN` | none | Optional. Sent as `Authorization: Bearer` to api.github.com only, to lift the unauthenticated rate limit. Never logged. |
| `LAB_SCOUT_STATE_DIR` | `/data` | Holds `seen.json`. Absolute path. Written with a temp file and rename in the same directory. |
| `LAB_SCOUT_PROFILE` | `/app/profile.yaml` | Lab profile given to the model as data (baked into the image from `profile.yaml`). |
| `LAB_SCOUT_INVENTORY` | k8s-argocd `apps/*,infrastructure/*`; ansible-quasarlab `roles,roles/monitoring` | `url:path,path;url:path`. `url` must be exactly `https://github.com/OWNER/REPO`. `path` lists the directories under it; `path/*` also lists one level below each. |
| `LAB_SCOUT_EXTRA_INVENTORY` | ArgoCD, Prometheus, Grafana, ... (25 names) | Comma separated names the directory listing does not spell out. Set to an empty string for none. |
| `LAB_SCOUT_CLAUDE_BIN` | `claude` | Path, or a name resolved on `PATH`. |
| `LAB_SCOUT_CLAUDE_MODEL` | `opus` | |
| `LAB_SCOUT_CLAUDE_TIMEOUT` | `900` | Seconds, clamped to 30..3600. |
| `LAB_SCOUT_MAX_IDEAS` | `5` | Clamped to 1..10. |
| `LAB_SCOUT_MAX_STALE_DAYS` | `180` | GitHub repos not pushed for longer are dropped. |
| `LAB_SCOUT_FETCH_DOMAINS` | github.com, raw.githubusercontent.com, awesome-selfhosted.net, news.ycombinator.com, selfh.st, landscape.cncf.io, www.cncf.io, www.reddit.com, old.reddit.com, distrowatch.com, discourse.openrobotics.org | The only hosts claude may WebFetch. |
| `LAB_SCOUT_DEBUG` | unset | Any value enables debug logging (includes the inventory names). |

The image also sets `HOME=/tmp/home` (created at start, because `/tmp` is an
empty volume), `DISABLE_AUTOUPDATER=1` and
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`.

## Security model

Model output is shaped by web content, so it is untrusted end to end.

- **The model can only read.** claude runs with `--tools WebSearch,WebFetch`,
  `--allowedTools` limited to `WebSearch` and `WebFetch(domain:...)` for the
  allowlisted hosts, `--permission-prompts none` (anything not pre-allowed is
  denied), `--safe-mode`, `--strict-mcp-config`, `--no-session-persistence`
  and `--json-schema`. Its working directory is a temp dir under `/tmp`, never
  the state volume.
- **The model never sees secrets.** The claude child's environment is an
  allowlist: `PATH`, `HOME`, `CLAUDE_CODE_OAUTH_TOKEN`, `DISABLE_AUTOUPDATER`,
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` and the `LAB_SCOUT_CHILD` marker.
  The webhook and `GITHUB_TOKEN` are never passed. git children get a
  similar allowlist.
- **Facts never come from the model.** Stars, last push and license come from
  `https://api.github.com/repos/OWNER/REPO`. Archived, disabled, missing
  (404), stale and malformed repos are dropped; a rate limit (403 or 429)
  drops the idea and logs a warning. Redirects are followed only to
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
  invalid webhook (checked before the model call), a bad claude envelope, or
  zero valid ideas all exit `1` and post nothing.
- **The container is minimal and unprivileged.** UID/GID 65532, read-only root
  filesystem, all capabilities dropped, no pip, no Node.js, no gh. The claude
  CLI is the native binary from `@anthropic-ai/claude-code`, installed with
  `npm ci` from `claude/package-lock.json` (sha512 integrity) in a build stage.

Controls that live in the Kubernetes manifests, not here: PSA `restricted`,
`concurrencyPolicy: Forbid` (there is no file lock, because flock on NFS is not
reliable), an emptyDir at `/tmp`, the NFS PVC at `/data`, and a NetworkPolicy
allowing only DNS and TCP 443 to public addresses.

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
`structured_output` `{"ideas": [...]}`) and point `LAB_SCOUT_CLAUDE_BIN` at it:

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
sitecustomize shim that does the same, and inventory repos are local bare
repos served over `file://` through a test-only seam. A skipped test fails the
run.

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

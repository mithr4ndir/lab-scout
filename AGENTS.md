# Agent instructions: lab-scout

## Purpose

"Radagast": a weekly Discord digest of homelab project ideas. Stdlib-only Python that
shells out to a pinned `claude` CLI for the generation step, shipped as a container image
and run as a Kubernetes CronJob.

## Boundaries

- This repo builds and publishes `ghcr.io/mithr4ndir/lab-scout`. The CronJob manifest
  lives in `k8s-argocd`, not here, so changing the schedule or the env is a change there.
- `[tool.uv] package = false`. Nothing is built or pip-installed. The image copies
  `src/lab_scout` in and runs `python -m lab_scout`; pytest finds it via
  `pythonpath = ["src"]`.
- Runtime secrets (`LAB_SCOUT_WEBHOOK_URL`, `CLAUDE_CODE_OAUTH_TOKEN`, `GITHUB_TOKEN`)
  come from Kubernetes Secrets. None are in this repo.
- `claude/package-lock.json` pins the `claude` CLI version baked into the image. The
  Dockerfile installs it with `npm ci --ignore-scripts` and verifies the version string.

## Validation

```
uv sync --frozen
uv run ruff check
uv run pytest -q -rs
```

The README and CI agree exactly here, unlike sibling repos. There is no typecheck step.

`__init__.py`'s `__version__` must stay in sync with the `pyproject.toml` version; a test
enforces it, and the CI build job reads the version to tag the image.

## Landmines

- **A skipped test fails the run.** `tests/conftest.py` forces a failing exit code in
  `pytest_sessionfinish` if any test was skipped, even when everything that ran passed.
- The suite refuses network by design: an autouse fixture monkeypatches
  `urllib.request.OpenerDirector.open` and `socket.getaddrinfo` to raise, and a
  `sitecustomize` shim does the same for subprocesses. A test that genuinely needs the
  network gets refused, not skipped, and combined with the rule above that fails the run.
- Trivy scans the image before the push, and the pushed image is the same artifact that
  was scanned rather than a rebuild.
- Upgrading the pinned `claude` CLI or the base images needs manual digest lookups; see
  the README's "Upgrading pinned versions".

## Forbidden

- Do not add a runtime dependency without a deliberate decision. `dependencies = []` is
  intentional: every dependency is attack surface, and this image runs with a Claude OAuth
  token in its environment.

## Completion

Ruff and pytest actually run and pass, with no skips. If the image or its pins changed,
say whether the Trivy scan was exercised or only the local tests.

# lab-scout image: Python (stdlib only) plus a pinned claude CLI.
#
# Base images are pinned by tag AND index digest. To bump one, pull the new
# tag and read the digest back:
#   docker pull python:3.12.14-slim-bookworm
#   docker inspect --format '{{index .RepoDigests 0}}' python:3.12.14-slim-bookworm

# Stage 1: install the claude CLI from the committed lockfile. npm ci verifies
# every tarball against its sha512 integrity hash. Install scripts are not run:
# the wrapper's postinstall only copies the platform binary into place, which
# is done explicitly below. Node never reaches the runtime image, because the
# CLI is a native executable.
FROM node:22.23.2-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS claude
WORKDIR /opt/claude
COPY claude/package.json claude/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && install -D -m 0755 node_modules/@anthropic-ai/claude-code-linux-x64/claude /opt/claude/bin/claude \
 && DISABLE_AUTOUPDATER=1 HOME=/tmp /opt/claude/bin/claude --version | grep -Fx "2.1.270 (Claude Code)"

# Stage 2: runtime.
FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

# git for the inventory clones, ca-certificates for TLS. Pending Debian
# security updates are applied at build time, and pip is removed: nothing is
# installed at run time.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip uninstall -y pip

RUN groupadd -r -g 65532 nonroot \
 && useradd -r -u 65532 -g 65532 -d /tmp/home -s /usr/sbin/nologin nonroot \
 && mkdir -p /data \
 && chown 65532:65532 /data \
 && chmod 0700 /data

COPY --from=claude /opt/claude/bin/claude /opt/claude/bin/claude
RUN ln -s /opt/claude/bin/claude /usr/local/bin/claude

WORKDIR /app
# Owned by root and read-only to the runtime user: the app never writes here.
COPY src/lab_scout /app/lab_scout
COPY profile.yaml /app/profile.yaml
# Bytecode is compiled at build time; the root filesystem is read-only at run time.
RUN python -m compileall -q /app/lab_scout

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp/home \
    LAB_SCOUT_STATE_DIR=/data \
    LAB_SCOUT_PROFILE=/app/profile.yaml \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

USER 65532:65532

# HOME (/tmp/home) is created by the app at start, because /tmp is an empty
# volume in the pod.
ENTRYPOINT ["python", "-m", "lab_scout"]
CMD ["weekly"]

ARG PY_BASE=python:3.12-slim
FROM ${PY_BASE}

# Real npcapextract (ntop). Off by default (demo/tests use a stub). With
# --build-arg INSTALL_NTOP=1 (compose.ntop.yaml) the image installs ntop's `n2disk`
# package from their apt repo at build time, on the host that has the licence;
# nothing from ntop is redistributed. n2disk is only here for npcapextract and its libs.
ARG INSTALL_NTOP=0
RUN if [ "$INSTALL_NTOP" = "1" ]; then \
      set -eux; . /etc/os-release; \
      sed -i 's/^Components: main$/Components: main contrib/' /etc/apt/sources.list.d/debian.sources; \
      apt-get update; \
      apt-get install -y --no-install-recommends ca-certificates wget gnupg lsb-release whiptail; \
      wget -q "https://packages.ntop.org/apt-stable/${VERSION_CODENAME}/all/apt-ntop-stable.deb" -O /tmp/apt-ntop-stable.deb; \
      apt-get install -y --no-install-recommends /tmp/apt-ntop-stable.deb; \
      apt-get update; \
      apt-get install -y --no-install-recommends n2disk; \
      rm -rf /var/lib/apt/lists/* /tmp/apt-ntop-stable.deb; \
    fi

# supervisord runs the web (user sr) and the worker (root) side by side; tini reaps orphans.
RUN apt-get update \
 && apt-get install -y --no-install-recommends supervisor tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 sr \
 && useradd --system --uid 10001 --gid sr --no-create-home --shell /usr/sbin/nologin sr

# uv for dependency management.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Install locked dependencies first (better layer caching).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# App source.
COPY src ./src
COPY gunicorn.conf.py ./
COPY docker ./docker
RUN uv sync --frozen --no-dev && chmod 0755 /app/docker/entrypoint.sh

# npcapextract must be on PATH at runtime: INSTALL_NTOP=1 above, or a stub (demo).
# The worker (root) logs to /var/log/sycope-recorder, never into the state directory the web can write.
RUN mkdir -p /run/api /var/lib/sycope-recorder /var/log/sycope-recorder \
 && chown root:sr /var/log/sycope-recorder && chmod 2750 /var/log/sycope-recorder

ENV PATH="/app/.venv/bin:${PATH}"

ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker/entrypoint.sh"]

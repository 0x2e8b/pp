# Building and Shipping a Distribution

This document is for whoever packages the `api` service for a target host —
it is not needed for local development (see `README.md` for that).

The goal of a "dist" is a **pre-built `api` Docker image** plus the small set
of files a target host needs alongside it (`compose.yaml`, `caddy/Caddyfile`,
an `.env`). The target host never needs the source tree, `uv`, or a Python
toolchain — it only needs Docker.

## 1. Build the image

```bash
# Tag with something traceable back to source (git sha shown here).
# The release (v0.4b6, pyproject 0.4.0b6) plus the sha: the release is what the pages show.
TAG=v0.4b6-$(git rev-parse --short HEAD)
# INSTALL_NTOP=1 puts ntop's npcapextract into the image (compose.ntop.yaml sets the same on an installer host).
docker build --build-arg INSTALL_NTOP=1 -t sycope-recorder-api:$TAG .
```

Without `--build-arg INSTALL_NTOP=1` the image has no `npcapextract`: it starts, but `doctor` reports
`npcapextract` FAIL (not found on PATH) and every job fails. That image is only good for a demo without a capture.

The `Dockerfile` build stage needs network access to pull `python:3.12-slim`,
`ghcr.io/astral-sh/uv:latest`, and the locked dependencies — do this on a
machine with normal internet access, not on an air-gapped target. With
`INSTALL_NTOP=1` the build also installs ntop's apt repository package and the
`n2disk` package (which provides `npcapextract`) from `packages.ntop.org`, so
the build host must reach `packages.ntop.org` as well; nothing from ntop has to
be installed on the build host itself.

`caddy:2` is used as-is (no local Dockerfile) — pull it too so both images can
travel together:

```bash
docker pull caddy:2
```

## 2. Get the images to the target host

Pick one, depending on whether the target host can reach a registry:

**A. Registry (preferred when available)**

```bash
docker tag sycope-recorder-api:$TAG your-registry.example.com/sycope-recorder-api:$TAG
docker push your-registry.example.com/sycope-recorder-api:$TAG
docker tag caddy:2 your-registry.example.com/caddy:2
docker push your-registry.example.com/caddy:2
```

The target host then just needs `docker login` +
`docker compose -f compose.yaml -f compose.dist.yaml pull` (`compose.dist.yaml`: step 3).

**B. Offline transfer (no registry reachable from the target)**

```bash
docker save sycope-recorder-api:$TAG -o sycope-recorder-api.tar
docker save caddy:2 -o caddy.tar
```

Copy the two tarballs to the target host (`scp`/`rsync`) along with the dist
folder from step 3, then on the target:

```bash
docker load -i sycope-recorder-api.tar
docker load -i caddy.tar
```

## 3. Assemble the dist folder

The target host needs these files from the repo (nothing else — no `.git`,
`tests/`, `docs/`, `old/`, `.venv/`):

```
compose.yaml
compose.ntop.yaml   (the image installs npcapextract; rolling/alerts bound to host paths)
caddy/Caddyfile
caddy/entrypoint.sh
certs/              (empty dir is fine; own TLS certificate goes here)
profiles/           (profiles.json from tools/profiles/gen_profiles.py, or leave empty and build it from
                     the Profiles page; mounted read-only at /profiles)
```

**`compose.yaml` currently builds the `api` image from source (`build: .`).**
For a pre-built-image dist, repoint it at the tag you built/loaded instead —
either edit the `api` service in place on the target, or ship an override
file, e.g. `compose.dist.yaml`:

```yaml
services:
  api:
    build: !reset null
    image: sycope-recorder-api:REPLACE_WITH_TAG   # or the registry path from step 2A
```

and run with `docker compose -f compose.yaml -f compose.dist.yaml up -d`
(no `--build` — the image is already local).

## 4. Deploy on the target host

Same runtime steps as `README.md`'s quickstart — required env vars
(`SR_PUBLIC_HOST`, `BASIC_AUTH_USER`, `BASIC_AUTH_HASH`, optionally
`ALLOWED_IPS`) still apply, and are unrelated to how the image was built:

```bash
docker run --rm caddy:2 caddy hash-password --plaintext 'yourpassword'
export SR_PUBLIC_HOST=recorder.example.com
export BASIC_AUTH_USER=sycope
export BASIC_AUTH_HASH='<paste the hash>'   # in a .env file: single-quote it
docker compose -f compose.yaml -f compose.dist.yaml up -d
docker compose -f compose.yaml -f compose.dist.yaml exec api python -m sycope_recorder doctor
```

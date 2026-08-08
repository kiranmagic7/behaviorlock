FROM node:26-bookworm-slim@sha256:cd565714d4da3e84bfd341e31448f81d47c6362198f152345297c9c1154e6341

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates strace \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 scanner \
    && useradd --uid 65532 --gid 65532 --home-dir /home/scanner --shell /usr/sbin/nologin scanner \
    && mkdir -p /seed /opt/behaviorlock \
    && chown -R 65532:65532 /seed

COPY --chmod=0555 entrypoint.sh /opt/behaviorlock/entrypoint.sh
COPY --chmod=0555 lifecycle.sh /opt/behaviorlock/lifecycle.sh
COPY --chmod=0444 metadata.mjs /opt/behaviorlock/metadata.mjs
COPY --chmod=0444 sentinel-start sentinel-end /opt/behaviorlock/

ENTRYPOINT ["/opt/behaviorlock/entrypoint.sh"]

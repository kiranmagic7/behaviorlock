FROM node:25-bookworm-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370

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

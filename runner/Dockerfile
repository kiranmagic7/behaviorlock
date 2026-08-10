FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates strace util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 scanner \
    && useradd --uid 65532 --gid 65532 --home-dir /home/scanner --shell /usr/sbin/nologin scanner \
    && mkdir -p /seed /opt/behaviorlock \
    && chown -R 65532:65532 /seed

COPY --chmod=0555 entrypoint.sh /opt/behaviorlock/entrypoint.sh
COPY --chmod=0555 lifecycle.sh /opt/behaviorlock/lifecycle.sh
COPY --chmod=0555 import.sh /opt/behaviorlock/import.sh
COPY --chmod=0444 import.mjs /opt/behaviorlock/import.mjs
COPY --chmod=0444 metadata.mjs /opt/behaviorlock/metadata.mjs
COPY --chmod=0444 module-kind.mjs /opt/behaviorlock/module-kind.mjs
COPY --chmod=0444 proxy.mjs /opt/behaviorlock/proxy.mjs
COPY --chmod=0444 proxy-relay.mjs /opt/behaviorlock/proxy-relay.mjs
COPY --chmod=0444 sinkhole.mjs /opt/behaviorlock/sinkhole.mjs
COPY --chmod=0444 sentinel-start sentinel-end /opt/behaviorlock/

ENTRYPOINT ["/opt/behaviorlock/entrypoint.sh"]

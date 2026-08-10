# Acquisition proxy

Package preparation must download public npm metadata and archives without giving npm a general network route. BehaviorLock enforces that boundary with a private socket and a narrow proxy policy.

## Data path

The preparation container runs as uid `65532`, with lifecycle scripts disabled and Docker network mode `none`. It cannot route directly to a public address, a private address, cloud metadata, or a Docker bridge gateway.

The container has read-only access to a randomly named Docker volume. A small loopback relay accepts npm proxy traffic on `127.0.0.1:8080` and forwards bytes only to `/proxy/proxy.sock` in that volume. It has no other destination.

The proxy sidecar owns the Unix socket and joins a separate, randomly named egress bridge. Its trusted supervisor starts with only `CHOWN`, `SETUID`, and `SETGID`, prepares the private socket directory, and then runs the Node proxy as uid `65532`. The sidecar receives no host path, Docker socket, credential, repository token, or inherited proxy configuration.

```text
npm in preparation container
        |
        | loopback HTTP proxy
        v
127.0.0.1:8080 relay
        |
        | private Docker-volume Unix socket
        v
unprivileged allowlist proxy
        |
        | validated public address only
        v
registry.npmjs.org:443
```

## Request policy

The proxy accepts HTTP/1.1 CONNECT only when both the request authority and the single Host header are exactly `registry.npmjs.org:443`. It rejects ordinary HTTP methods, other ports, IP literals, suffix lookalikes, trailing dots, user information, Unicode lookalikes, duplicate Host headers, transfer encoding, content length, proxy authorization, upgrades, and oversized header sets.

The proxy resolves `registry.npmjs.org` itself. Every returned address must be public. A mixed public and nonpublic answer is rejected as a unit. Private, loopback, link-local, carrier-grade NAT, benchmark, documentation, multicast, reserved, IPv4-mapped IPv6, and other non-global ranges are blocked. The proxy dials one validated address directly, so a second hostname resolution cannot change the destination after validation.

TLS remains end to end between npm and the registry. The proxy carries encrypted bytes and does not install a certificate authority or inspect package content.

## Lockfile policy

After installation, the runner checks every acquired package entry in `package-lock.json`. Separate acquisitions must use HTTPS on `registry.npmjs.org`, use the default port or port 443, contain no URL credentials, and include npm integrity metadata. Git, local path, linked, credentialed, alternate-port, and off-registry sources fail preparation. A dependency already bundled inside an allowed registry archive may omit a separate acquisition URL.

The profile records `registry-proxy-unix`, policy version `npm-registry-connect-v1`, the exact allowed authority, and the immutable proxy runner image ID. These fields participate in profile comparability and the stable semantic digest.

## Failure and cleanup

Preparation fails if the proxy does not become ready, emits an error, denies any request, records no allowed registry tunnel, returns unsafe DNS data, or produces an invalid lockfile inventory. Capture also fails on timeout or truncated proxy logs.

Cleanup removes only the cryptographically random container, image, volume, and network names created for that capture. The proxy is stopped before the private socket volume and egress network are removed.

## Remaining trust

This boundary limits destinations; it does not make registry data benign. A compromised registry response can still deliver hostile package bytes, and the proxy and containers share the Docker host kernel. Docker daemon administrators can inspect or alter containers and volumes. Capture therefore remains experimental and belongs on a disposable machine without valuable credentials, trusted workloads, or private-network access.

Release gate 6 stays open until hosted integration proves direct preparation egress denial, exact-registry success, nonregistry denial, minimal proxy runtime identity, and complete cleanup on the reviewed commit.

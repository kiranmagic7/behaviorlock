# Security policy

## Supported versions

There is no tagged release yet. Security fixes currently target the latest commit on `main`.

## Report privately

Do not open a public issue for a vulnerability. Use [GitHub private vulnerability reporting](https://github.com/kiranmagic7/behaviorlock/security/advisories/new).

Include:

1. Affected commit or version
2. Impact and threat model
3. Reproduction in an authorized disposable environment
4. Logs with secrets and personal data removed
5. A suggested fix if available

The maintainer will acknowledge a credible report within seven days and provide a status update within fourteen days. These are response targets, not a bounty or compensation promise.

## Scope

In scope are vulnerabilities in BehaviorLock itself, its repository automation, its parser, its report generation, and its documented containment controls.

Vulnerabilities in third party npm packages are out of scope unless BehaviorLock creates additional exposure or reports them incorrectly. Report an upstream package vulnerability to that package's maintainer, the npm security contact, or the appropriate coordinated disclosure channel. Do not use this repository to publish accusations about package authors.

## Safe testing boundary

Test only systems and packages you own, have permission to test, or created as inert fixtures. Do not probe third party infrastructure, exfiltrate data, publish live secrets, distribute malware, or use BehaviorLock to make unsupported accusations about package authors.

If a BehaviorLock vulnerability involves an actively exploited dependency, avoid public disclosure until users have a reasonable chance to update.

## Security model

The Docker capture backend is experimental. Containers share the host kernel and are not a complete hostile code boundary. Read [the threat model](docs/THREAT_MODEL.md) before testing capture.

BehaviorLock has no bug bounty program. Responsible reports and coordinated disclosure are still welcome.

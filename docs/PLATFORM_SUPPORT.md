# Platform support

BehaviorLock has two platform questions: where the CLI can run, and which operating system behavior the capture represents. They are not the same.

## Current support matrix

| Capability | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Build the Go CLI | Verified | Verified | Not yet tested in CI |
| Parse an existing Linux `strace` file | Expected | Expected | Not yet tested in CI |
| Compare compatible profile JSON | Expected | Expected | Not yet tested in CI |
| Run the full capture integration | Verified on GitHub hosted Linux | Not verified | Not verified |
| Observe native operating system behavior | Linux only | No | No |

## Linux

Linux is the observed target platform for `0.1.0-dev`. The runner depends on Linux containers, Linux permissions, Linux capabilities, `/proc`, and `strace`.

The complete Docker integration runs on GitHub hosted Ubuntu. It checks the package uid, effective capabilities, trace isolation, blocked network access, canary path visibility, immutable capture evidence, and cleanup.

## macOS

The Go CLI builds and its unit tests run on GitHub hosted macOS.

The full Docker capture has not been verified on macOS. Docker Desktop could operate the Linux runner inside its virtual machine, but the result would describe Linux container behavior. It would not show native macOS file, process, or network events.

## Windows

Windows is not in the current CI matrix. The code may compile because the parser and comparison core use portable Go, but this has not been established by hosted tests.

Docker Desktop can run Linux containers on some Windows configurations. Even if capture works there, the resulting profile would describe Linux behavior rather than native Windows behavior.

## What native support would require

Native support needs a separate capture backend for each operating system.

1. Linux can continue using `strace`, with eBPF as a possible later option.
2. macOS would need an authorized event source such as Endpoint Security or another supported tracing mechanism.
3. Windows would need Windows event telemetry such as ETW plus a separate containment design.

The normalized profile and comparison model could remain shared, but every backend would need its own threat model, coverage declaration, comparability rules, tests, and release gate.

## Accurate public description

The current accurate description is:

> BehaviorLock compares observed npm install lifecycle behavior in Linux containers. Its parser and comparison core are portable, but native Windows and macOS tracing are not implemented.

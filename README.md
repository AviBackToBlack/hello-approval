# hello-approval

Hardware-backed human signing and approval for Windows developer workflows.

> **Status:** early design/reference implementation. The first production-tested integration is Git SSH signing through Windows Hello / WebAuthn using `sshenc`.

`hello-approval` explores a deliberately narrow security primitive with broad applications:

> A human explicitly approves a specific cryptographic statement with a Windows Hello / WebAuthn credential whose private signing material is hardware-backed and is not exposed as a normal private-key file.

Git commit and tag signing is the first reference integration, not the boundary of the project.

## What this project is for

The project aims to make Windows Hello-backed signing useful as a reusable human-approval boundary for developer and operator workflows such as:

- Git commit and tag signing;
- detached artifact or manifest signing;
- release approval;
- infrastructure-change approval;
- explicit approval of high-impact automation or AI-agent actions.

The common model is:

```text
application / workflow
        |
        v
canonical subject or intent
        |
        v
local signing client
        |
        v
isolated per-user signing channel
        |
        v
interactive signing broker
        |
        v
Windows Hello / WebAuthn
        |
        v
hardware-backed credential
        |
        v
signature / attestation
        |
        v
independent verifier + policy
```

The verifier does not need access to the private signing material.

## First reference integration: Git signing

The production-tested starting point is:

```text
Git commit/tag
    |
    v
sshenc.exe
    |
    v
per-user sshenc config
    |
    v
dedicated named pipe
    |
    v
sshenc-agent
    |
    v
Windows Hello / WebAuthn
    |
    v
TPM-backed credential
    |
    v
SSH signature embedded in Git object
    |
    +--> local OpenSSH verification
    |
    +--> GitHub verification
```

The normal Windows OpenSSH authentication agent remains a separate parallel path and is not replaced by this design.

## Core design principles

- No ordinary private signing-key file.
- Dedicated signing credentials, not reused broad SSH authentication keys.
- Interactive user context for Windows Hello.
- Isolated signing channel and explicit credential labels.
- Signing identity is separate from author identity.
- Signing is separate from SSH transport configuration.
- Local verification is first-class; a hosting-platform badge is not the root of trust.
- Automation is fail-closed, conservative, and reversible.
- High-impact approval must bind the signature to the exact subject and purpose being approved.
- TPM-backed does not mean safe on a fully compromised host.

## Explicit non-goals

`hello-approval` is **not** intended to become:

- a password manager or secret vault;
- a generic private-key encryption/unlock system;
- a replacement for the stock Windows `ssh-agent`;
- an SSH authentication framework;
- a replacement for Authenticode, code-signing PKI, Sigstore, Vault, or enterprise IAM;
- a claim that Windows Hello or TPM protects against malware/admin/kernel compromise on the same machine.

Using Windows Hello to unlock an existing encrypted SSH private key is a different problem from using a hardware-backed WebAuthn credential to perform the signature operation itself.

## v0.1 scope

v0.1 intentionally stays narrow:

1. document the generic signing/approval architecture;
2. provide a production-grade Git signing reference integration on Windows 11;
3. isolate `sshenc-agent` from the normal SSH authentication agent;
4. run the signing agent in the interactive user session **without a persistent visible console window**;
5. document local and GitHub verification;
6. provide a reproducible acceptance checklist;
7. document threat model, provenance limits, rollback, and failure modes.

Generic artifact/release/infrastructure/automation approval is architecture work for later versions, not claimed v0.1 functionality.

## Current architecture decisions

See [Architecture](docs/ARCHITECTURE.md) and [Threat model](docs/THREAT-MODEL.md).

Implementation sequencing is tracked in [ROADMAP.md](ROADMAP.md). The Windows v0.1 runtime contract is documented in [Runtime layout and configuration](docs/RUNTIME-LAYOUT.md), the no-visible-console process/lifecycle design in [Invisible interactive agent launcher](docs/LAUNCHER.md), the per-user Task Scheduler integration in [Scheduled Task installation](docs/SCHEDULED-TASK.md), Git signing configuration in [Git signing configuration](docs/GIT-CONFIG.md), and local trust semantics in [Local Git signature verification](docs/LOCAL-VERIFICATION.md).

## Security status

This repository is a reference implementation, not a formal security audit of Windows Hello, WebAuthn, TPM, OpenSSH, Git, GitHub, or `sshenc`.

The upstream `sshenc` project and release provenance must be evaluated independently. Pinning and checksum verification are part of the intended implementation, but upstream release binaries should not be treated as trusted merely because this repository uses them.

For the currently audited `sshenc` v0.6.101 Windows release, `hello-approval` deliberately prefers the ZIP/manual-binary path over the MSI/WinGet installer path. The upstream MSI runs `sshenc install` during installation and `sshenc uninstall` during removal, while those integration paths manage SSH/Git state that this project intentionally leaves alone. The upstream `gitenc` integration is excluded for the same reason: it couples signing setup with Git SSH transport configuration.

The audited v0.6.101 x86_64 Windows `sshenc.exe` is also not Authenticode-signed. That is a point-in-time provenance limitation, not a claim about every future release; each pinned upgrade must re-check it. A matching SHA-256 digest establishes asset identity, not trustworthiness.

See [Upstream provenance and pinning](docs/PROVENANCE.md) for the immutable release evidence, selected asset hash, binary surface, and upgrade gate.

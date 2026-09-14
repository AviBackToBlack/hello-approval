# Roadmap

The implementation is intentionally sliced into small reviewable changes. No phase implies permission to auto-merge.

## Phase 0 — Foundation

### HA-0.1: Scope and architecture

- Define the project as Windows Hello-backed human signing/approval rather than Git-only tooling.
- Keep Git as the first production reference integration.
- Record non-goals and threat model.
- Record the no-visible-console requirement for the interactive signing agent.

### HA-0.2: Upstream/provenance research gate

- Re-check current `sshenc` release/version behavior.
- Document release provenance limitations.
- Decide pin/checksum source and upgrade policy.
- Confirm relevant Windows/WebAuthn assumptions against upstream/current platform behavior.

## Phase 1 — Git reference integration

### HA-1.1: Runtime layout and configuration

- Define deterministic per-user paths.
- Add `config.toml.example`.
- Define dedicated named pipe and signing-label policy.
- Never alter stock `ssh-agent`, `SSH_AUTH_SOCK`, or `GIT_SSH_COMMAND`.

### HA-1.2: Invisible interactive agent launcher

- Research and implement the smallest reliable launcher/wrapper.
- Keep the process in the interactive user session.
- Prevent a persistent console window.
- Preserve lifecycle supervision, restart behavior, exit observability, and logs.
- Acceptance-test Windows Hello prompting through the hidden launch path.

### HA-1.3: Scheduled Task installation

- Idempotent task creation/update.
- User-logon trigger.
- Interactive logon type.
- Limited run level.
- Ignore duplicate instances.
- Restart policy.
- Infinite execution limit.
- Conservative uninstall path.

### HA-1.4: Git configuration

- Configure SSH signing program and public signing key.
- Enable commit/tag signing only with explicit user intent.
- Keep author identity separate.
- Include optional repo-local identity guardrail example.

### HA-1.5: Local verification

- `allowed_signers` example and configuration.
- `git verify-commit` / `git log --show-signature` acceptance.
- Explain cryptographic validity versus principal/trust mapping.

### HA-1.6: GitHub verification

- Register the public key as a **Signing Key**, not an Authentication Key.
- Push a locally signed acceptance commit.
- Verify GitHub API reports `verified=true` and `reason=valid`.
- Document GitHub-generated signing versus locally generated signing.

### HA-1.7: Doctor and rollback

- Read-only diagnostics first.
- Detect stock-agent mutation/collision.
- Detect config/task/path mismatch.
- Conservative cleanup with explicit credential-removal handling.

## Phase 2 — Hardening

- CI / PowerShell static analysis.
- Idempotence tests.
- `-WhatIf` coverage where meaningful.
- Failure-injection/rollback tests.
- Upgrade path for pinned upstream binaries.
- Public documentation cleanup.

## Phase 3 — Generic signed statements

Design gate before implementation.

- Define a versioned canonical envelope.
- Define domain separation and purpose semantics.
- Define verifier/trust-policy model.
- Define replay/expiry/nonce behavior.
- Add generic detached signing only if the semantics remain clear and independently verifiable.

## Phase 4 — Reference approval integrations

Possible examples, each requiring its own threat-model/design gate:

- release manifest approval;
- artifact/SBOM attestation;
- Terraform plan approval;
- deployment approval;
- high-impact automation / AI-agent action approval.

These are intentionally not v0.1 promises.

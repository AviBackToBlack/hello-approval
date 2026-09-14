# Threat model

## Security goals

`hello-approval` aims to reduce several practical failure modes around developer signing and human approval.

### Protect signing private material

The preferred credential model does not expose the signing private key as a conventional file that can be copied between machines or accidentally committed/backed up.

### Reduce accidental credential reuse

Signing credentials should be dedicated to signing/approval rather than reused broad SSH authentication/admin/automation keys.

### Bind approval to an explicit subject

For future approval integrations, the signature must identify the exact object, purpose, target, and relevant validity constraints being approved.

### Reduce accidental unsigned changes

Integrations may enable default signing and diagnostics that fail closed when expected signing state is absent.

### Reduce accidental identity confusion

Author identity, signing credential, and trust policy are separate concepts. The implementation should make mismatches visible rather than silently conflating them.

## Trust boundaries

The design assumes trust in:

- the Windows installation and interactive user session at the moment of approval;
- the Windows Hello / WebAuthn platform stack;
- the platform authenticator / TPM implementation;
- the signer binaries being executed;
- the verifier implementation;
- the user's configured trust policy and public keys.

Each of those can fail independently.

## Explicit non-protections

The project does **not** claim protection against:

- malware already running with equivalent access in the interactive user's session;
- a malicious or compromised `sshenc`/signer binary;
- a compromised Windows Hello/WebAuthn implementation;
- a compromised operating system;
- a malicious administrator;
- kernel-level compromise;
- physical attacks outside the platform authenticator's actual guarantees;
- compromise of a GitHub/account recovery path;
- social engineering that tricks the user into approving a misleading subject.

`TPM-backed` is not synonymous with `safe on a compromised host`.

## User-consent integrity

A cryptographic signature proves possession/use of a credential under its protocol rules. It does not automatically prove that the human understood what was being signed.

For generic approval workflows, the system therefore needs a trustworthy presentation layer that shows the human a stable, meaningful representation of the signed statement before Windows Hello confirmation.

This is intentionally deferred beyond the Git-focused v0.1, where Git itself defines the signed object semantics.

## Replay and cross-purpose misuse

Future approval formats must use domain separation and include enough context to prevent replay or semantic substitution.

Depending on the workflow, that may include:

- schema/version;
- purpose/action;
- target/environment;
- subject digest and algorithm;
- repository/project identity;
- nonce/challenge;
- creation and expiry time;
- optional workflow/run identifier.

A signature over `SHA256(file)` alone must not automatically mean `approve deployment of file to production`.

## Agent/channel risk

The dedicated named pipe reduces accidental coupling with the stock SSH authentication agent, but it is not by itself a security sandbox against same-user malware.

The agent must expose only intended signing labels and must not be treated as safe from arbitrary clients running with equivalent user access unless the upstream protocol and Windows ACL behavior are verified to provide such isolation.

## Supply-chain risk

The first reference integration depends on `sshenc`, which is a young upstream project. The repository must not describe a particular upstream release as trusted merely because it was used successfully.

The implementation should support:

- explicit version pinning;
- cryptographic checksum verification;
- documented provenance limitations;
- reproducible inspection of what is being installed where practical.

A checksum proves that a downloaded asset matches the expected asset; it does not prove that the asset itself is trustworthy.

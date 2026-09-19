# Phase 2 validation contract

## Status

Design gate for Phase 2 hardening issues #6 and #8.

This document freezes the intended semantics for a future shared Windows PowerShell 5.1 validation library before any existing production caller is migrated. No production script changes behavior merely because this design exists.

## Why this comes first

Phase 1 intentionally used small, self-contained slices. Runtime and path validation is now repeated across runtime installation, preflight, Scheduled Task installation, Git configuration, Doctor diagnostics, and cleanup.

Those copies already differ in case sensitivity, provenance-policy checks, regular-file handling, and path ancestry. Phase 2 should establish one read-only contract first, prove parity, and only then migrate callers individually.

## Scope

The first shared layer covers only:

1. provenance-pin policy consistency;
2. trusted-base descendant path validation;
3. exact installed pinned-runtime validation.

It does not initially own Git precedence, Scheduled Task XML, sshenc config semantics, transport isolation, launcher ownership, credential lifecycle, cleanup mutation, or archive installation.

## Proposed library

Repository-owned and dependency-free:

`lib/HelloApproval.Validation.psm1`

Proposed public operations:

- `Assert-HelloApprovalPinPolicy`
- `Assert-HelloApprovalTrustedPath`
- `Get-HelloApprovalFileSha256`
- `Assert-HelloApprovalPinnedRuntime`

Names may change during implementation review; the semantics below are the design gate.

## Provenance-pin policy

`Assert-HelloApprovalPinPolicy` validates installed-runtime policy consistency:

- schema exactly `hello-approval/upstream-pin/v1`;
- file names are non-empty and unique under ordinal case-sensitive comparison;
- dispositions are exactly from `required`, `unused`, `excluded`;
- `installation_policy.installed_files` contains non-empty unique names under ordinal case-sensitive comparison;
- the exact case-sensitive installed-file set equals the exact set of records whose disposition is `required`;
- every installed file has exactly one required provenance record;
- required sizes are non-negative integers;
- required SHA-256 values are exactly 64 hexadecimal characters.

Installer-only policy such as target architecture and distribution format remains caller-specific unless a later design requires centralizing it.

## Trusted-base descendant paths

### Boundary model

The caller supplies a trusted base and a target.

Examples:

- trusted base: `%LOCALAPPDATA%`
- target: `%LOCALAPPDATA%\hello-approval\runtime\sshenc\v0.6.101`

or:

- trusted base: `%USERPROFILE%`
- target: `%USERPROFILE%\.ssh\github-signing.pub`

The trusted base is accepted from the current Windows session/OS configuration. The validator does not walk above it and does not claim its ancestors are non-reparse.

This avoids unsupported assumptions about legitimate profile, roaming-profile, or redirected-profile layouts.

### Lexical containment

Before filesystem traversal:

- base and target must be absolute;
- both are normalized with `System.IO.Path.GetFullPath`;
- target must equal the base or be an actual descendant component using Windows ordinal-ignore-case comparison;
- sibling-prefix tricks such as `C:\Base2` for base `C:\Base` fail closed;
- `..` is normalized before containment is evaluated.

### Existing descendant components

For every existing component strictly below the trusted base through the target:

- expected directory components must be real directories and non-reparse;
- an expected file leaf must be a real file and non-reparse;
- unexpected type fails closed.

This is the intentional #6 hardening delta.

### Missing components

The shared validator is read-only and never creates paths.

Callers explicitly decide whether a missing descendant is an error or an allowed pre-creation state. A mutating caller that creates a missing path must re-run validation after creation and before consuming it as trusted state.

### TOCTOU boundary

Walking components reduces path-redirection risk but does not remove same-user TOCTOU races. The threat model excludes a compromised same-user process as a fully defended boundary; this validation must not claim otherwise.

## Exact installed pinned runtime

`Assert-HelloApprovalPinnedRuntime` conceptually accepts `RuntimeRoot`, parsed `Pin`, and `TrustedBase`.

It validates pin policy before runtime bytes.

### Runtime root

- exists inside the trusted base;
- every descendant component below the base is non-reparse;
- is a real directory;
- contains exactly one entry;
- that entry is named exactly `bin` by ordinal case-sensitive comparison;
- `bin` is a real non-reparse directory.

### Bin surface

- contains exactly the case-sensitive set in `installation_policy.installed_files`;
- no extra or missing entry;
- case-only mismatches fail;
- every entry is a regular non-reparse file;
- every installed file maps to exactly one required provenance record.

### File bytes

For every installed file:

- byte length equals pinned `size_bytes`;
- SHA-256 equals the pinned hash;
- hashing is read-only.

Success means only that the current installed runtime surface and bytes match approved provenance policy under the declared trusted-path boundary.

It does not prove publisher identity, process integrity, or protection against a compromised same-user attacker.

## Failure model

The shared library is assertion-style and fail closed:

- success returns normally and may return normalized metadata;
- policy/path/surface/hash violations throw;
- it does not emit user-facing PASS/BLOCK findings itself.

Presentation and exit semantics remain caller-specific:

- installers throw before mutation;
- preflight and Doctor translate exceptions to structured BLOCK findings;
- cleanup refuses destructive removal;
- tests compare acceptance/rejection behavior.

## No hidden mutation

Shared validation must not create or delete paths, start/stop services or tasks, rewrite Git, modify environment variables, repair permissions, execute runtime binaries, or alter staging/quarantine state.

## Parity gate before migration

Introducing the library does not authorize caller migration.

The implementation slice must first add dependency-free Windows PowerShell 5.1 tests covering:

### Accepted fixture

- exact runtime root and `bin`;
- exact required files;
- exact sizes/hashes;
- no reparse descendants.

### Pin-policy rejection

- duplicate file record;
- duplicate `installed_files` entry;
- unknown disposition;
- required/installed set mismatch;
- missing required record;
- malformed SHA-256.

### Runtime-surface rejection

- missing runtime;
- extra root entry;
- `Bin` instead of exact `bin`;
- missing/extra file;
- case-only filename mismatch;
- directory where file expected;
- reparse file/directory;
- size mismatch;
- hash mismatch.

### Intermediate ancestry rejection

Controlled temporary fixtures place a junction/reparse point at each supported descendant position below the trusted base, including project root descendant, `runtime`, `sshenc`, version root, `bin`, and a file leaf where supported.

Every redirected fixture must fail before an integration caller would mutate state.

### Boundary behavior

- trusted base itself is accepted as the external boundary;
- target outside base rejected;
- sibling-prefix confusion rejected;
- normalized `..` escape rejected;
- normal Windows profile/temp-style paths accepted.

## Migration order

After parity:

1. `Install-HelloApprovalRuntime.ps1`
2. `Install-HelloApprovalScheduledTask.ps1`
3. `Install-HelloApprovalGitConfig.ps1`
4. `Test-HelloApprovalPreflight.ps1`
5. `Test-HelloApprovalDoctor.ps1`
6. `Uninstall-HelloApproval.ps1`

The runtime installer defines the original contract; integration installers consume it before mutation; diagnostic callers need structured exception translation; destructive cleanup migrates last.

Each migration PR must prove no intentional acceptance/rejection change except the explicitly approved #6 ancestry hardening.

## Relationship to #6 and #8

Issue #8 owns centralization and parity.

Issue #6 supplies the one intentional hardening delta: intermediate reparse ancestry below a declared trusted base.

They therefore share one implementation rather than landing independent path walkers.

## Out of scope

- canonical Git `include.path` identity (#9);
- generic ACL validation;
- handle-based race-free traversal;
- Authenticode/publisher validation;
- generic application validation framework;
- recursive OpenSSH config parsing;
- generic Git environment-injection parsing.

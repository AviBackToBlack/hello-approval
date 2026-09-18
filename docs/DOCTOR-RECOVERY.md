# Doctor, cleanup, and credential recovery

## Scope

HA-1.7 closes the v0.1 operational lifecycle around the Windows Git-signing integration:

- read-only health diagnostics;
- detection of integration drift and prohibited stock-SSH takeover state;
- conservative removal of state that hello-approval actually owns;
- explicit recovery/retirement guidance for a lost, dead, or compromised hardware-backed credential;
- clear separation between current trust policy and historical signature evidence.

The lifecycle intentionally does **not** turn credential deletion or GitHub account-key administration into unattended automation.

## Read-only Doctor

Run the Doctor from a trusted checkout of the same hello-approval version used to manage the workstation:

```powershell
.\scripts\Test-HelloApprovalDoctor.ps1
```

To also inspect repository-local and conditional Git overrides:

```powershell
.\scripts\Test-HelloApprovalDoctor.ps1 -Repo C:\path\to\repo
```

Machine-readable output:

```powershell
.\scripts\Test-HelloApprovalDoctor.ps1 -Repo C:\path\to\repo -Json
```

Exit codes:

- `0` — no `BLOCK` findings;
- `2` — one or more fail-closed `BLOCK` findings;
- any other nonzero result — the script itself could not complete normally.

The Doctor is read-only. It does not start/stop services, register tasks, rewrite Git, repair configuration, rotate trust, or touch credentials.

### What the Doctor checks

The Doctor reuses the existing HA-1.3/1.4/1.5 installers under `-WhatIf` as contract validators, then adds post-install composition checks that those installers do not express as a health report.

It checks:

- the pinned runtime, sshenc policy, launcher surface, and owned Scheduled Task contract through the existing installers;
- exact Scheduled Task ownership and critical definition;
- task Running state, dedicated pipe presence, and the pinned `sshenc-agent.exe` process/command line;
- prohibited `SSHENC_AGENT_SOCKET` overrides;
- `SSH_AUTH_SOCK` / `GIT_SSH_COMMAND` takeover fingerprints that point normal SSH transport at sshenc or the dedicated signing pipe;
- upstream sshenc-managed SSH config blocks and `IdentityAgent` coupling;
- SSH `Include` directives are not recursively expanded in v0.1; when present, checks that would otherwise claim the absence of an upstream sshenc-managed block or prohibited `IdentityAgent` fail closed with `BLOCK`;
- current stock Windows `ssh-agent` state without modifying it;
- canonical hardware-backed public-key shape;
- optional target-repository effective Git signing/trust values.

### What the Doctor cannot prove

The Doctor is not a forensic history recorder.

In particular, if the stock Windows `ssh-agent` service is currently Disabled, the Doctor cannot infer who changed it or what its state was before hello-approval existed. A disabled stock agent by itself is therefore reported as suspicious/current state, not as proof that hello-approval mutated it.

If that state appears together with sshenc takeover fingerprints such as persistent `SSH_AUTH_SOCK` or `GIT_SSH_COMMAND` pointing at sshenc, the combination is treated as prohibited integration state.

This distinction matters because the v0.1 invariant is “hello-approval does not mutate the stock agent,” not “the stock agent must always be enabled.”

## Conservative cleanup

The full lifecycle cleanup entry point is:

```powershell
.\scripts\Uninstall-HelloApproval.ps1
```

Preview first:

```powershell
.\scripts\Uninstall-HelloApproval.ps1 -WhatIf
```

Default cleanup removes only state that hello-approval can identify as its own:

- the owned HA-1.3 Scheduled Task;
- direct global `include.path` entries pointing to the owned HA-1.4/HA-1.5 Git fragments;
- the owned `signing.gitconfig` fragment;
- the owned `verification.gitconfig` fragment;
- the owned HA-1.5 `allowed_signers` trust store.

Existing unrelated global Git settings and unrelated includes are preserved.

Before mutation, owned files and the Scheduled Task must carry the expected ownership/schema markers. A same-name foreign task or an unowned file at an owned path causes fail-closed refusal.

Git cleanup is snapshot-backed. If later cleanup fails after Git mutation starts, the global Git config and owned Git/trust files are restored. If the owned Scheduled Task was removed before a later failure, its XML/running-state snapshot is used for best-effort restoration. Explicit runtime/cache removal first renames validated directories into same-volume quarantine paths; quarantine is restored on a later failure and is only deleted after the rollback-capable operation set succeeds.

### Explicit destructive switches

The pinned runtime is preserved by default. To remove it:

```powershell
.\scripts\Uninstall-HelloApproval.ps1 -RemoveRuntime
```

Removal is allowed only if the runtime surface still matches the pinned provenance record exactly. Tampered/foreign bytes are refused rather than recursively deleted.

The content-addressed launcher cache is also preserved by default. To remove it:

```powershell
.\scripts\Uninstall-HelloApproval.ps1 -RemoveLauncherCache
```

Each cache directory must be a 64-hex digest directory containing exactly one regular `Start-HelloApprovalAgent.ps1` whose SHA-256 equals the directory name.

Both switches can be combined, and `-WhatIf` applies to them.

## State cleanup intentionally preserves

Even a full cleanup does **not** delete or mutate:

- the authoritative sshenc user config;
- `%USERPROFILE%\.ssh\github-signing.pub`;
- the Windows Hello/WebAuthn/platform private credential;
- GitHub Signing Key registration;
- user SSH config;
- unrelated `SSH_AUTH_SOCK` / `GIT_SSH_COMMAND` state;
- the stock Windows `ssh-agent` service;
- unrelated Git settings/includes;
- logs/state not selected by an explicit cleanup switch.

Those boundaries are deliberate. The private credential and GitHub account key are different trust/control planes and require explicit human intent.

## Lost or dead hardware-backed credential

A TPM reset/clear, device loss, profile rebuild, authenticator re-enrollment, or credential corruption may make the old private credential permanently unavailable.

Do **not** model recovery as “restore the private key.” The v0.1 credential model assumes the private signing material may be non-exportable and unrecoverable.

Recovery is replacement plus trust rotation:

1. Stop future use of the old local signing path. If appropriate, remove/stop the owned Scheduled Task or perform conservative hello-approval cleanup.
2. Provision a new hardware-backed credential manually using the project’s current credential-creation procedure. Do not copy/import a conventional private key as a substitute.
3. Put the replacement public key at the canonical signing-key path and reconcile the sshenc label/config deliberately.
4. Re-run the HA-1.3/HA-1.4 configuration checks as appropriate.
5. Re-run HA-1.5 local verification installation so the active project-owned `allowed_signers` contains the replacement key.
6. Add the replacement public key to GitHub explicitly as a **Signing Key**, not merely an Authentication Key.
7. Remove/retire the dead old GitHub Signing Key explicitly in GitHub account settings.
8. Create a fresh Windows Hello-backed signed commit and repeat HA-1.5 local verification plus HA-1.6 GitHub verification.

GitHub signing-key registration/removal remains manual in v0.1. The corresponding REST API is an account-administration surface and requires broader signing-key administration permission; HA-1.6 deliberately does not request it.

## Compromised credential

For suspected compromise, treat the old key as untrusted for **future/current** policy immediately:

1. stop the local signing task/path;
2. remove the old GitHub Signing Key manually;
3. provision and register a replacement credential/key;
4. rewrite the active local `allowed_signers` trust mapping to the replacement key;
5. validate the new path before resuming signing.

Do not keep a compromised old key in the active `allowed_signers` merely so old commits continue to verify locally.

If historical audit requires verifying old signatures, preserve the old **public** key and incident/rotation timestamps in a separate historical audit policy or evidence bundle. Do not silently merge historical trust into the active current-trust file.

## Local trust versus historical cryptographic evidence

The Git object contains the signature. `allowed_signers` supplies current local trust mapping.

Removing an old key from the active `allowed_signers` does not erase the signature bytes from historical commits; it changes whether the current local policy maps that key to an accepted principal.

This is why “cryptographically signed by key X” and “currently trusted under active policy” must remain separate statements.

## GitHub historical verification is persistent

GitHub documents persistent commit-signature verification: once a commit signature has been verified in a repository network, GitHub stores a verification record and does not retroactively re-verify that historical commit when the signing key is later rotated, revoked, expired, or removed.

Reference:

https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification

Therefore:

- removing a GitHub Signing Key is important for preventing that removed key from establishing verification for future newly-seen commits;
- it does **not** mean old commits lose their existing GitHub Verified record;
- the `verified_at` timestamp records when GitHub created the persistent verification record;
- GitHub Verified history and the workstation’s current `allowed_signers` policy answer different questions.

Neither mechanism is a universal retroactive revocation service.

## Recommended rotation record

For a deliberate rotation, record at minimum:

- old public-key fingerprint;
- replacement public-key fingerprint;
- reason: loss, routine rotation, suspected compromise, or confirmed compromise;
- time the old local trust was removed;
- time the old GitHub Signing Key was removed;
- time the replacement GitHub Signing Key was registered;
- first replacement-key commit that passed HA-1.5 and HA-1.6 verification;
- any repositories/verifiers with separate trust stores that still require rotation.

This gives future auditors a timeline without pretending that historical signatures or GitHub persistent verification records were retroactively rewritten.

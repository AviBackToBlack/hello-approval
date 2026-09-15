# Git signing configuration

## Scope

HA-1.4 configures the Git **signing** path only. Author/committer identity remains a separate repository concern.

The installer does not set `user.name`, `user.email`, `core.sshCommand`, `SSH_AUTH_SOCK`, `GIT_SSH_COMMAND`, or local repository configuration.

## Owned global fragment

The project owns one per-user fragment:

```text
%LOCALAPPDATA%\hello-approval\git\signing.gitconfig
```

and registers it through one global `include.path`. The fragment contains:

```text
gpg.format = ssh
gpg.ssh.program = <pinned sshenc.exe>
user.signingkey = <absolute path to ~/.ssh/github-signing.pub>
```

The fragment also contains `hello-approval.schema = hello-approval/ha-1.4/v1` as its ownership/version marker.

Existing direct/global signing settings are not deleted or rewritten. If an existing global value for one of the three owned signing keys conflicts, installation refuses by default. `-OverrideExistingSigningConfig` is an explicit request to retain those old values but give the hello-approval include precedence in the context-neutral global baseline. Because the preserved conflicting values remain present, later installer runs continue to require the override switch; it is not a one-time grant. If an unconditional global include later overrides the hello-approval fragment, verification fails rather than silently claiming success.

Post-write verification deliberately runs from a fresh non-repository directory with repository discovery bounded there. It proves the **context-neutral global baseline**, not every repository context. Git repository-local settings and conditional `includeIf` rules can intentionally override global values for particular repositories/branches/remotes. HA-1.4 does not try to outlaw normal Git precedence. Production acceptance and HA-1.5 local verification must therefore inspect the effective signing configuration in the target repository as well as the global baseline.

## Signing enablement is explicit

A default install does **not** write `commit.gpgSign` or `tag.gpgSign`.

Use explicit intent when desired:

```powershell
.\scripts\Install-HelloApprovalGitConfig.ps1
.\scripts\Install-HelloApprovalGitConfig.ps1 -EnableCommitSigning
.\scripts\Install-HelloApprovalGitConfig.ps1 -EnableCommitSigning -EnableTagSigning
.\scripts\Install-HelloApprovalGitConfig.ps1 -OverrideExistingSigningConfig
.\scripts\Install-HelloApprovalGitConfig.ps1 -WhatIf
```

`-OverrideExistingSigningConfig` preserves conflicting existing global values and permits the hello-approval global baseline to take precedence; it does not delete those values. `-WhatIf` executes validation/read checks but performs no mutation.

Once a hello-approval fragment has enabled one of those toggles, a later idempotent run without switches preserves it. HA-1.4 does not implement implicit disabling; broader rollback/cleanup remains HA-1.7 scope.


## Program path semantics

`gpg.ssh.program` is stored as the absolute executable path returned by the pinned runtime, using forward slashes for Git config portability. The value is **not** wrapped in literal quote characters when the path contains spaces. Git for Windows accepts an unquoted config value such as `C:/Program Files/.../ssh-keygen.exe` as an executable path; embedding literal quotes in the value changes the executable name and breaks process creation. The Windows acceptance matrix includes a real `git commit -S` with an SSH signing program under `C:/Program Files/...`.

## Public key boundary

The signing key configured in Git is the public OpenSSH key at:

```text
%USERPROFILE%\.ssh\github-signing.pub
```

For the v0.1 reference path it must contain exactly one non-empty `sk-ecdsa-sha2-nistp256@openssh.com` public-key line. No private-key file is configured or copied. Git's SSH signing backend may use a public-key path when the corresponding signing operation is serviced by the configured signing program/agent path.

## Author identity remains separate

`user.name` and `user.email` determine Git author/committer identity; they are not derived from the signing credential. HA-1.4 never writes them globally or locally.

A repository can set its own identity explicitly:

```powershell
git config --local user.name "Example Name"
git config --local user.email "example@example.invalid"
```

### Optional repo-local identity guardrail

`examples/pre-commit-identity-guard.ps1` is an optional guardrail for repositories where author/committer identity must stay fixed. Configure the expected identity repo-locally:

```powershell
git config --local hello-approval.expectedName "Example Name"
git config --local hello-approval.expectedEmail "example@example.invalid"
```

Then invoke the script from the repository's `pre-commit` hook (directly or through a small hook wrapper appropriate for the environment). The script compares the actual `git var GIT_AUTHOR_IDENT` and `GIT_COMMITTER_IDENT` values against the expected repo-local identity, so environment overrides and `--author` changes are visible to the check.

This is a guardrail, not a hard security boundary: Git's `pre-commit` hook can be bypassed with `--no-verify`.

## Rollback behavior during installation

Before mutation, the installer snapshots the Git global write file reported by `git var GIT_CONFIG_GLOBAL` and the owned fragment if present. If include registration or post-write verification fails, both files are restored to their previous bytes where possible.

The installer intentionally uses Git itself to write `include.path` and staged config values; it does not implement a second Git-config parser/writer. `Test-HelloApprovalPreflight.ps1` also reads global/system Git configuration with includes enabled so the project-owned fragment is visible to diagnostics instead of being reported as absent.

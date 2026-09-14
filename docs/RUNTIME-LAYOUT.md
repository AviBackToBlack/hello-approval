# Runtime layout and configuration

## 1. Scope

This document freezes the HA-1.1 runtime contract for the Windows v0.1 Git-signing reference integration.

HA-1.1 deliberately does **not**:

- create or start a Scheduled Task;
- solve the hidden-console problem;
- create the Windows Hello/WebAuthn credential;
- configure Git signing;
- modify the stock Windows OpenSSH Authentication Agent;
- modify `SSH_AUTH_SOCK`, `GIT_SSH_COMMAND`, `PATH`, or `~/.ssh/config`.

Those operations either belong to later slices or are explicit non-goals.

## 2. Deterministic paths

For the currently pinned `sshenc` release (`v0.6.101`), the default v0.1 layout is:

| Purpose | Path |
| --- | --- |
| Project-owned root | `%LOCALAPPDATA%\hello-approval` |
| Pinned runtime root | `%LOCALAPPDATA%\hello-approval\runtime\sshenc\v0.6.101` |
| Runtime binaries | `%LOCALAPPDATA%\hello-approval\runtime\sshenc\v0.6.101\bin` |
| `sshenc.exe` | `%LOCALAPPDATA%\hello-approval\runtime\sshenc\v0.6.101\bin\sshenc.exe` |
| `sshenc-agent.exe` | `%LOCALAPPDATA%\hello-approval\runtime\sshenc\v0.6.101\bin\sshenc-agent.exe` |
| Future logs | `%LOCALAPPDATA%\hello-approval\logs` |
| Future project state | `%LOCALAPPDATA%\hello-approval\state` |
| Upstream sshenc config | Path reported by pinned `sshenc.exe config path` |
| Public signing key | `%USERPROFILE%\.ssh\github-signing.pub` |

Only the runtime tree under `%LOCALAPPDATA%\hello-approval` is owned by this project.

The upstream-resolved sshenc config path and `%USERPROFILE%\.ssh` are shared/user-owned locations. Scripts must therefore treat pre-existing content there as user state, never as disposable project state.

### Why the runtime path is versioned

A pinned upstream upgrade gets a new version directory instead of replacing trusted bytes in place. Later integration state (Scheduled Task and Git signing program) can then move from one reviewed runtime path to another explicitly.

This also makes rollback simple: changing integration pointers back to the previously accepted version does not require reconstructing overwritten binaries.

## 3. Approved binary surface

HA-0.2 pins the full upstream archive but v0.1 installs only:

- `sshenc.exe`;
- `sshenc-agent.exe`.

The installer in this repository must reject an archive whose SHA-256/size or per-file SHA-256/size does not match the machine-readable provenance pin. It must not extract the other upstream files into the production runtime directory.

The runtime installer does **not**:

- invoke the MSI;
- invoke WinGet/Scoop;
- run `sshenc install` or `sshenc uninstall`;
- run `gitenc.exe`;
- alter `PATH`;
- register services/tasks;
- write SSH/Git configuration.

It is intentionally an inert verified file-placement operation.

## 4. sshenc configuration

The canonical example is [`examples/sshenc/config.toml.example`](../examples/sshenc/config.toml.example).

Do **not** hard-code `%APPDATA%` as the config location. `sshenc` computes its default through Rust `dirs::config_dir()` and falls back to `~/.config` when that platform lookup is unavailable. The authoritative v0.1 location is therefore the output of the pinned binary:

```powershell
& $SshencExe config path
```

On a normal Windows profile the pinned v0.6.101 binary resolves under Roaming AppData (`%APPDATA%\sshenc\config.toml`). Upstream also has a `~/.config` fallback when the platform config-directory lookup is unavailable. The project must follow the binary's resolved path instead of assuming either shape.

For v0.1 the policy-bearing values are:

```toml
socket_path = '\\.\pipe\sshenc-github-signing'
allowed_labels = ["github-signing"]
prompt_policy = "always"
pub_dir = "~/.ssh"
log_level = "info"
```

### Dedicated pipe

The signing channel is:

`\\.\pipe\sshenc-github-signing`

It must not be changed to the upstream Windows default `\\.\pipe\openssh-ssh-agent`, because that name belongs to the normal Windows OpenSSH authentication path in this architecture.

The pipe name is deliberately Git-reference-specific for v0.1. Future approval integrations may get separate labels/channels after their own design gates.

### Dedicated label

The only v0.1 label exposed by the signing agent is:

`github-signing`

This matters because upstream `allowed_labels = []` means **no filter / expose all labels**. An empty list is therefore fail-open for this project's purpose and is not an acceptable production configuration.

Upstream validates labels as 1–64 ASCII alphanumeric / hyphen / underscore characters. `github-signing` is within that contract.

### Prompt policy

The reference config explicitly sets:

`prompt_policy = "always"`

The accepted v0.1 credential is created with `sshenc keygen --strong`, which selects the SK/FIDO2/WebAuthn path and requires user presence during signing independently of this config field. `always` is retained as defense-in-depth if a non-SK key is ever accidentally introduced under the approved label.

### Public key location

With label `github-signing`, upstream `sshenc keygen --strong --label github-signing` defaults to:

`%USERPROFILE%\.ssh\github-signing.pub`

Only the public key is written there. The WebAuthn credential's private signing material is not materialized as a conventional private-key file.

Credential generation remains an explicit/manual acceptance operation and is not performed by HA-1.1 automation.

## 5. Client routing contract

`sshenc.exe` loads its platform-resolved default config path (discoverable with `sshenc.exe config path`) and uses that config's `socket_path` for client operations.

Upstream also honors `SSHENC_AGENT_SOCKET` as a higher-precedence client-side override. Therefore production `hello-approval` requires `SSHENC_AGENT_SOCKET` to be unset in both persistent user state and the process environment used for signing.

This requirement is separate from `SSH_AUTH_SOCK`: `hello-approval` intentionally leaves ordinary SSH authentication routing untouched.

## 6. Future agent-launch contract

HA-1.2 will decide how to launch the console-subsystem agent invisibly. HA-1.3 will install the Scheduled Task. Both must preserve this logical invocation contract:

```text
sshenc-agent.exe
  --foreground
  --config <exact path returned by sshenc.exe config path>
  --socket \\.\pipe\sshenc-github-signing
```

The explicit `--socket` is mandatory.

At the pinned upstream release, standalone `sshenc-agent.exe` has its own CLI default of `\\.\pipe\openssh-ssh-agent`; merely supplying `--config` does **not** replace that CLI socket value. Omitting `--socket` would therefore collide with the path this project is specifically designed to leave alone.

The agent may load `allowed_labels`, prompt policy, public-key directory, and log level from the explicit config file. HA-1.2 must not duplicate those policy values in an opaque launcher unless a later requirement proves duplication necessary.

## 7. Read-only preflight

Before any later integration mutation, run:

```powershell
.\scripts\Test-HelloApprovalPreflight.ps1
```

or for machine-readable output:

```powershell
.\scripts\Test-HelloApprovalPreflight.ps1 -Json
```

The preflight is read-only. It inspects, among other things:

- project/pin availability;
- any existing pinned runtime files and their hashes;
- the dedicated pipe name for an existing listener;
- process/user `SSHENC_AGENT_SOCKET` overrides;
- process/user `SSH_AUTH_SOCK` and `GIT_SSH_COMMAND` without changing them;
- stock Windows `ssh-agent` state;
- existing sshenc config at any known candidate path, and the authoritative resolved path once the pinned runtime exists;
- `~/.ssh/config` for upstream-managed or `IdentityAgent` state;
- relevant global Git transport/signing configuration.

Exit codes:

- `0` — no blocking finding; warnings may still require human review;
- `2` — at least one blocking finding;
- `1` — script/platform failure before a trustworthy preflight result could be produced.

A warning is not permission to overwrite state. It means the later mutation must either preserve that state or require an explicit reviewed decision.

## 8. Inert runtime installation

After obtaining the exact pinned ZIP, install the approved binary surface with:

```powershell
.\scripts\Install-HelloApprovalRuntime.ps1 -ArchivePath C:\path\to\sshenc-x86_64-pc-windows-msvc.zip
```

Preview with:

```powershell
.\scripts\Install-HelloApprovalRuntime.ps1 -ArchivePath C:\path\to\sshenc-x86_64-pc-windows-msvc.zip -WhatIf
```

The script:

1. reads the repository's v0.1 machine-readable provenance pin;
2. verifies archive name, size, and SHA-256;
3. verifies the exact archive entry set;
4. verifies every entry's size and SHA-256;
5. stages only `installation_policy.installed_files`;
6. re-verifies staged hashes;
7. moves the version directory into its deterministic destination;
8. refuses to overwrite a mismatched existing runtime.

It deliberately has no "latest" lookup and no package-manager mode.

## 9. Config installation policy

HA-1.1 ships an example rather than silently overwriting the upstream-resolved sshenc config path.

If no upstream config exists, first resolve the path with the pinned `sshenc.exe config path`, then copy the example to that exact path after review. If a config already exists, it must be reconciled explicitly; a future helper may create/compare it idempotently, but must not replace a differing file by default.

This preserves the project rule that shared user configuration is never destructively claimed merely because `hello-approval` is being installed.

## 10. HA-1.1 acceptance

HA-1.1 is complete when review establishes that:

- paths are deterministic and versioned;
- the installed binary surface is exactly the pinned required surface;
- archive and file hashes gate installation;
- no package-manager/upstream integration command is used;
- the config exposes exactly `github-signing` on the dedicated pipe;
- `SSHENC_AGENT_SOCKET` override risk is detected;
- stock SSH transport state is observed but never mutated;
- the future agent invocation contract explicitly supplies `--socket`;
- scripts are read-only or mutate only the project-owned runtime tree;
- no task, agent process, credential, Git config, or SSH transport state is created/changed in this slice.

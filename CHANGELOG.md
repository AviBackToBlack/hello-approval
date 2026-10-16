# Changelog

All notable changes to `hello-approval` are recorded here. Versions follow [Semantic Versioning](https://semver.org/); the `0.x` series makes no compatibility promise between minor versions.

## 0.1.0

First release. It is a **Windows Git SSH signing reference integration**: Git commits and tags are signed with a Windows Hello / WebAuthn credential whose private signing material is hardware-backed and never exists as a normal private-key file. Generic artifact, release, infrastructure or automation approval is **not** implemented; it remains design work (see [ROADMAP.md](ROADMAP.md), phases 3 and 4).

### Included

- **Pinned upstream runtime.** `sshenc` v0.6.101, x86_64 Windows ZIP only, verified against a SHA-256 provenance pin and installed inertly. No MSI/WinGet, no `sshenc install`, no `gitenc` ([docs/PROVENANCE.md](docs/PROVENANCE.md), [docs/RUNTIME-LAYOUT.md](docs/RUNTIME-LAYOUT.md)).
- **Isolated signing channel.** A dedicated named pipe `\\.\pipe\sshenc-github-signing`, separate from the stock Windows OpenSSH agent. The agent exposes exactly one credential label, derived from the credential whose public key is `~\.ssh\github-signing.pub`.
- **Launcher.** A hidden Windows PowerShell 5.1 launcher runs the agent in the interactive user session inside a kill-on-close job object. It is installed as a SHA-256 content-addressed bundle that pins the shared validation module ([docs/LAUNCHER.md](docs/LAUNCHER.md)).
- **Per-user Scheduled Task.** Starts at logon, carries a case-exact ownership marker, and uses an idempotent update with rollback to the previous definition. Upgrades keep earlier bundle generations for rollback ([docs/SCHEDULED-TASK.md](docs/SCHEDULED-TASK.md)).
- **Git signing configuration.** Owned fragments are reached through a global `include.path`. Existing direct settings are preserved, and global auto-signing is not enabled unless requested ([docs/GIT-CONFIG.md](docs/GIT-CONFIG.md)).
- **Local verification.** A project-owned `allowed_signers` trust store, restricted to the `git` namespace, and a read-only verifier that is isolated from ambient Git routing and config ([docs/LOCAL-VERIFICATION.md](docs/LOCAL-VERIFICATION.md)). GitHub verification is documented in [docs/GITHUB-VERIFICATION.md](docs/GITHUB-VERIFICATION.md).
- **Diagnostics and cleanup.** Read-only preflight and Doctor with structured findings, and conservative ownership-checked uninstall ([docs/DOCTOR-RECOVERY.md](docs/DOCTOR-RECOVERY.md)).
- **Shared validation module.** Pin policy, trusted-path ancestry, exact runtime surface, and one Windows file-name component predicate ([docs/HARDENING-VALIDATION-CONTRACT.md](docs/HARDENING-VALIDATION-CONTRACT.md)).
- **Continuous integration.** A Windows PowerShell 5.1 acceptance workflow on GitHub-hosted `windows-2022` runs every suite under `tests/`.

### Tested configurations

- **Continuous integration:** GitHub-hosted `windows-2022`, Windows PowerShell 5.1. These suites use synthetic fixtures and stubs; they never use a real Windows Hello credential and never create a real Scheduled Task.
- **Production acceptance:** one physical Windows 11 Pro host (26H2, OS build 26300) with Windows PowerShell 5.1.26100, Git for Windows 2.55, OpenSSH for Windows 9.5p2, `sshenc` 0.6.101 and Windows Terminal 1.24 installed, migrated from a manual `sshenc` setup. Real Windows Hello-backed signing and local verification passed, and Doctor reported no BLOCK or WARN findings. Dated acceptance results are recorded in the release notes, not here.
- Other Windows builds, Windows PowerShell 7, non-x86_64 hardware and other authenticators have not been tested.

### Security notes and limitations

- This is a reference implementation, not a security audit of Windows Hello, WebAuthn, TPM, OpenSSH, Git, GitHub or `sshenc` ([docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)).
- A hardware-backed credential does not protect against malware, an administrator or kernel compromise on the same signed-in machine.
- The pinned `sshenc.exe` is not Authenticode-signed. A matching SHA-256 digest establishes asset identity, not trustworthiness ([docs/PROVENANCE.md](docs/PROVENANCE.md)).
- The local `allowed_signers` principal is a trust label for a key. It is not compared with Git author or committer identity.

### Known issues

- **Default terminal application ([#49](https://github.com/AviBackToBlack/hello-approval/issues/49)).** If Windows Terminal is the default terminal application, the launcher's console is delegated to it and stays visible as a Windows Terminal window, which breaks the no-visible-console goal. Setting the default terminal application to **Windows Console Host** avoided this on the tested host. This is a workaround; behavior on other configurations, and with "Let Windows decide", is untested ([docs/SCHEDULED-TASK.md](docs/SCHEDULED-TASK.md#default-terminal-application)).
- **`include.path` identity ([#35](https://github.com/AviBackToBlack/hello-approval/issues/35)).** Owned include paths are compared textually. If an alias spelling of an owned fragment already exists (`~/`, a relative path, an 8.3 short name or `..` segments), a duplicate include can be added and Doctor or uninstall can miss it. First-time installs, which write only the canonical spelling, are not affected.
- **Installer backups ([#37](https://github.com/AviBackToBlack/hello-approval/issues/37)).** When an installer re-runs over an existing owned file, another process holding a handle on the temporary backup can make its deletion fail silently. Rollback snapshots restore bytes but not file attributes. First-time installs do not create these backups.
- **Remaining hardening ([#9](https://github.com/AviBackToBlack/hello-approval/issues/9)).** The umbrella issue for the items above stays open.
- **Preflight after install.** `Test-HelloApprovalPreflight.ps1` is a pre-installation check. Once the owned agent is running it reports `agent.pipe.collision`, because it does not recognize the owned agent. Use Doctor to check an installed system.
- **Static analysis.** PowerShell static analysis from roadmap phase 2 is not in CI.

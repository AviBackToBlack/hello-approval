# Scheduled Task installation

## Scope

HA-1.3 binds the HA-1.2 hidden launcher to Windows Task Scheduler. It does not configure Git, generate credentials, change stock `ssh-agent`, or mutate persistent SSH environment variables.

## Task identity and ownership

v0.1 owns exactly one root-folder task:

- task name: `hello-approval Git Signing Agent`;
- task path: `\`;
- exact ownership marker / description: `hello-approval/ha-1.3/v1`.

An existing task with the same name but without the exact ownership marker is treated as foreign state and is never overwritten or removed.

## Principal and trigger

The task is registered for the user running the installer:

- one logon trigger scoped to that exact Windows account;
- `LogonType = Interactive` / Task Scheduler XML `InteractiveToken`;
- `RunLevel = Limited`;
- no password is stored;
- no SYSTEM/service-account execution.

The interactive-token requirement is part of the Windows Hello contract, not merely a convenience.

## Action

The task launches the system Windows PowerShell 5.1 executable with:

```text
-NoProfile
-NonInteractive
-WindowStyle Hidden
-ExecutionPolicy RemoteSigned
-File <content-addressed Start-HelloApprovalAgent.ps1>
-AgentPath <pinned sshenc-agent.exe>
-ConfigPath <exact path returned by pinned sshenc.exe config path>
-SocketPath \\.\pipe\sshenc-github-signing
```

The task action working directory is the content-addressed launcher directory. The HA-1.2 launcher separately gives `sshenc-agent.exe` the pinned runtime `bin` directory as its child working directory.

`RemoteSigned` is process-local for the task invocation. HA-1.3 does not write CurrentUser/LocalMachine execution-policy state. An enforced MachinePolicy/UserPolicy can still prevent execution and is allowed to fail closed.

## Content-addressed launcher deployment

The installed launcher bundle lives beneath:

```text
%LOCALAPPDATA%\hello-approval\app\launcher\<launcher-sha256>\
  Start-HelloApprovalAgent.ps1
  HelloApproval.Validation.psm1
```

The directory name remains the SHA-256 of `Start-HelloApprovalAgent.ps1`. The launcher source contains the exact SHA-256 of `HelloApproval.Validation.psm1`, so the launcher digest transitively commits the validation-module bytes as part of the bundle contract.

The installer requires the repository launcher pin to match the repository validation module before any cache mutation. Existing v2 digest directories must contain exactly those two real, non-reparse files; the launcher bytes must hash to the directory name and the module bytes must match the hash pinned by the launcher. New launcher/module combinations therefore get new immutable paths instead of overwriting code that may currently be executing.

Hash-bearing launcher/module files are forced to LF checkout bytes through `.gitattributes`, so the content-addressed identity does not depend on a machine's `core.autocrlf` setting.

### Existing Windows checkout created before LF pinning

A checkout that already existed before the LF attributes were introduced can remain deceptively clean while still holding the unchanged validation module as CRLF bytes. Git applies the new `eol=lf` attribute but may not rewrite that unchanged working-tree file during a fast-forward update.

The installer detects this exact case and fails closed with a stale-CRLF diagnostic. On a checkout with **no local changes to `lib/HelloApproval.Validation.psm1`**, refresh only that tracked file from the repository root:

```powershell
Remove-Item -LiteralPath .\lib\HelloApproval.Validation.psm1
git restore --source=HEAD --worktree -- lib/HelloApproval.Validation.psm1
git add --renormalize -- lib/HelloApproval.Validation.psm1
git status --short -- lib/HelloApproval.Validation.psm1
```

The final status command must produce no output. A fresh clone is an equivalent remediation. Do not use this sequence when that file contains local work that must be preserved.

Task updates switch the action to the new launcher hash-path. Old launcher hash directories are retained so rollback remains possible and uninstall does not make broad filesystem-cleanup decisions. General cleanup belongs to HA-1.7.

## Runtime/config discovery

The installer reads the repository's pinned upstream provenance record and requires the already-installed runtime to match the **exact HA-1.1 surface**: the version root contains only `bin`, `bin` contains exactly `installation_policy.installed_files`, entries are real non-reparse files, and every required file matches its pinned size and SHA-256. This is checked before Task Scheduler state is created or updated.

The sshenc config path is resolved by executing the verified pinned `sshenc.exe config path`. The resolved config must already exist as a real non-reparse file. The installer then uses the pinned binary's `sshenc.exe config show` output to validate the effective policy: `socket_path` must be the dedicated signing pipe, `allowed_labels` must contain exactly one label, the label of the single credential that pinned `sshenc.exe list --json` reports for the canonical `%USERPROFILE%\.ssh\github-signing.pub` fingerprint (compared case-sensitively; see `docs/RUNTIME-LAYOUT.md`, "Dedicated label"), and `prompt_policy` must be `always`. HA-1.3 does not create or replace the signing config. The parser intentionally targets the pinned v0.6.101 canonical `config show` format and fails closed; every upstream pin bump must revalidate that output contract.

## Scheduler settings

The task uses:

- `MultipleInstances = IgnoreNew`;
- restart on failure: 3 attempts, 1 minute apart;
- `ExecutionTimeLimit = PT0S` (no scheduler time limit for the long-lived agent);
- allow start on battery;
- do not stop merely because the machine switches to battery;
- task remains visible in Task Scheduler for observability;
- the task and its logon trigger must both remain enabled (Task Scheduler omits `<Enabled>` when true by default; an explicit `false` is rejected by verification);
- the task itself remains visible in Task Scheduler (`<Hidden>` omitted/false; `true` is rejected).

The task is not automatically started by a normal install/update. `-StartNow` is explicit because starting the task can collide with a pre-existing signing agent during migration. Before an explicit start, the dedicated pipe must be free. When requested, `-StartNow` is successful only after Task Scheduler reports the task as running **and** the dedicated named pipe remains present together with `Running` state for a short stability window; lack of an interactive token therefore fails visibly. A user-logon trigger remains the normal steady-state start path.

## Idempotent update and rollback

If the owned task already exactly matches the desired critical definition, installation is a no-op except for an explicitly requested `-StartNow`.

If an owned task needs an update:

1. export the existing task XML;
2. record whether it was running;
3. stop the running owned task and wait for both scheduler state and the dedicated pipe to clear before replacing its definition;
4. register and verify the desired definition, including exactly one principal, one logon trigger, one exec action, enabled task/trigger state, and visible task state;
5. restart it only if it was running before, or if `-StartNow` was explicitly requested;
6. if registration/start fails, first stop any possibly-running new-definition instance, wait for its pipe to clear, then restore the previous XML and previous running state where possible.

No foreign task is overwritten.

### Upgrading after a launcher or validation-module change

Any change to `scripts/Start-HelloApprovalAgent.ps1` or `lib/HelloApproval.Validation.psm1` produces a new launcher digest and therefore a new `app\launcher\<launcher-sha256>\` directory. Nothing is upgraded automatically:

- The installed task keeps pointing at its existing digest directory. That launcher still verifies its own sibling module, so the running agent is unaffected by updating the checkout.
- After the checkout is updated, Doctor reports `launcher.cache` BLOCK "Installed content-addressed launcher bundle directory is missing" (and, through it, `task.definition`). This is the upgrade-required signal, not an internal error.

Operator upgrade, from the updated checkout:

1. `.\scripts\Test-HelloApprovalDoctor.ps1` and confirm the only new BLOCKs are the `launcher.cache` "directory is missing" finding and its dependent `task.definition`.
2. `.\scripts\Install-HelloApprovalScheduledTask.ps1 -WhatIf` to preview, then `.\scripts\Install-HelloApprovalScheduledTask.ps1`. The installer stages and verifies the new digest directory, then performs the update flow above (export, stop, re-register, verify, restore the previous XML on failure).
3. `.\scripts\Test-HelloApprovalDoctor.ps1` and confirm `launcher.cache` and `task.definition` PASS.

Previous digest directories are retained. The installer never removes them, and `Uninstall-HelloApproval.ps1` preserves the whole launcher cache by default. Only an explicit `-RemoveLauncherCache` removes it: after verifying every generation, it removes all of them, including the rollback target.

Rollback: check out the previous commit and re-run `Install-HelloApprovalScheduledTask.ps1`. The installer verifies the retained directory byte-exact (launcher hash equals the directory name, module hash equals the launcher's pin), does not restage it, and re-points the task at it. A tampered retained directory is refused before registration. Return to the newer commit and re-run the installer to roll forward.

## Conservative uninstall

`Uninstall-HelloApprovalScheduledTask.ps1`:

- refuses a same-name task without the exact ownership marker;
- stops the owned task if running;
- unregisters only that task;
- does not delete the pinned upstream runtime;
- does not delete sshenc config, keys, public keys, Git settings, stock-agent state, or content-addressed launcher cache.

Those broader lifecycle decisions remain separate gates.

## Production visual acceptance

The Task Scheduler path adds one visual condition that HA-1.2 direct-launch acceptance could not prove: the system `powershell.exe` action is a console-subsystem executable. Production acceptance must explicitly watch the interactive desktop for any visible console flash both when invoking `-StartNow` and on a real user logon. A visible flash fails the no-visible-console contract and requires a new launcher/task design gate. The previously rejected `conhost.exe --headless` path remains rejected because it is not a supported hosting API and has unsuitable exit-propagation semantics; do not adopt it merely to hide a flash.

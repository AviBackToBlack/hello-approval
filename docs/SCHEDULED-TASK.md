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

The repository launcher is installed beneath:

```text
%LOCALAPPDATA%\hello-approval\app\launcher\<sha256>\Start-HelloApprovalAgent.ps1
```

The SHA-256 directory name is the hash of the script bytes. Existing digest directories must contain exactly one real, non-reparse launcher file with that hash. New launcher versions therefore get new immutable paths instead of overwriting a script that may currently be executing.

Task updates switch the action to the new launcher hash-path. Old launcher hash directories are retained in HA-1.3 so rollback remains possible and uninstall does not make broad filesystem-cleanup decisions. General cleanup belongs to HA-1.7.

## Runtime/config discovery

The installer reads the repository's pinned upstream provenance record and requires the already-installed `sshenc.exe` and `sshenc-agent.exe` to match the pinned size and SHA-256 before it creates or updates Task Scheduler state.

The sshenc config path is resolved by executing the verified pinned `sshenc.exe config path`. The resolved config must already exist as a real non-reparse file. HA-1.3 does not create or replace the signing config.

## Scheduler settings

The task uses:

- `MultipleInstances = IgnoreNew`;
- restart on failure: 3 attempts, 1 minute apart;
- `ExecutionTimeLimit = PT0S` (no scheduler time limit for the long-lived agent);
- allow start on battery;
- do not stop merely because the machine switches to battery;
- task remains visible in Task Scheduler for observability.

The task is not automatically started by a normal install/update. `-StartNow` is explicit because starting the task can collide with a pre-existing signing agent during migration. A user-logon trigger remains the normal steady-state start path.

## Idempotent update and rollback

If the owned task already exactly matches the desired critical definition, installation is a no-op except for an explicitly requested `-StartNow`.

If an owned task needs an update:

1. export the existing task XML;
2. record whether it was running;
3. stop the running owned task before replacing its definition;
4. register the desired definition;
5. restart it only if it was running before, or if `-StartNow` was explicitly requested;
6. if registration/start fails, restore the previous XML and previous running state where possible.

No foreign task is overwritten.

## Conservative uninstall

`Uninstall-HelloApprovalScheduledTask.ps1`:

- refuses a same-name task without the exact ownership marker;
- stops the owned task if running;
- unregisters only that task;
- does not delete the pinned upstream runtime;
- does not delete sshenc config, keys, public keys, Git settings, stock-agent state, or content-addressed launcher cache.

Those broader lifecycle decisions remain separate gates.

# Invisible interactive agent launcher

## Scope

HA-1.2 selects the process-launch mechanism for the long-lived Windows `sshenc-agent.exe`. It does not create a Scheduled Task; HA-1.3 will bind this launcher to an interactive per-user task.

The launcher must preserve the HA-1.1 agent contract:

```text
sshenc-agent.exe --foreground --config <resolved config> --socket \\.\pipe\sshenc-github-signing
```

and must not repoint ordinary SSH authentication.

## Decision

v0.1 uses `scripts/Start-HelloApprovalAgent.ps1`, launched by Windows PowerShell with `-WindowStyle Hidden`. The task invocation also uses process-local `-ExecutionPolicy RemoteSigned`; it does not change CurrentUser/LocalMachine execution policy. If an enforced MachinePolicy/UserPolicy still forbids the script, startup fails closed.

The PowerShell process remains alive as the supervised process that Task Scheduler will own. It uses a small in-process P/Invoke helper to create `sshenc-agent.exe` with these Win32 semantics:

1. create an unnamed Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`;
2. open project-owned stdout/stderr logs as inheritable handles;
3. create `sshenc-agent.exe` with `CREATE_SUSPENDED | CREATE_NO_WINDOW`;
4. assign the suspended child to the Job Object;
5. resume it only after assignment succeeds;
6. wait for the child process;
7. propagate the child's exit code;
8. close the Job Object on every launcher exit.

This ordering intentionally removes the launch-to-job race. If Task Scheduler or another supervisor terminates the PowerShell wrapper, Windows closes its Job Object handle and terminates the associated agent process.

`CREATE_NO_WINDOW` suppresses the console for the console-subsystem child; it does not move the process to a service session. The wrapper and child remain in the same interactive user session, which is required for a Windows Hello/WebAuthn prompt.

## Candidate rejection

### Direct interactive Scheduled Task

Running `sshenc-agent.exe --foreground` directly leaves its console attached to the interactive desktop. It fails the no-persistent-console requirement.

### Hidden PowerShell plus ordinary `Start-Process -Wait`

This hides the window and waits, but it does not itself establish a child-lifetime contract if the wrapper is killed abruptly. A long-lived orphaned agent would defeat Task Scheduler restart/supervision semantics.

### `conhost.exe --headless`

Rejected for v0.1. `--headless` exists in the open-source console host, but Microsoft Terminal maintainers explicitly describe direct `conhost` command-line hosting as not a supported API surface. It also does not reliably propagate the hosted child process's exit code. Those properties conflict with the lifecycle/observability requirements.

### New compiled launcher executable

A tiny native/managed GUI launcher could implement the same Job Object pattern. It is not selected because introducing a project-owned executable creates another binary build/provenance/distribution surface without adding necessary v0.1 behavior. The supported Win32 primitives are reachable from the already-required Windows PowerShell runtime.

## Logging

The launcher keeps three classes of logs under `%LOCALAPPDATA%\hello-approval\logs` by default:

- `launcher.log` — launcher start, child exit, and launcher failures;
- `agent.stdout.log` / `agent.stderr.log` — inherited stdout/stderr from `sshenc-agent.exe`;
- `sshenc-operations.jsonl` — child-only `SSHENC_LOG` target for sshenc's own operation/warn/error logging and upstream rotation.

`SSHENC_LOG` is set only in the launcher process immediately before child creation, inherited by the child, and restored before a normal wrapper exit. No user- or machine-scope environment variable is written.

The launcher refuses a log directory outside `%LOCALAPPDATA%\hello-approval` and rejects reparse-point log directories.

## Guardrails

The launcher:

- requires a real, non-reparse `sshenc-agent.exe` file;
- requires a real, non-reparse config file;
- always passes `--foreground`;
- always passes `--config` explicitly;
- always passes `--socket` explicitly;
- accepts only a simple local `\\.\pipe\...` named-pipe path;
- explicitly refuses `\\.\pipe\openssh-ssh-agent`;
- never sets `SSH_AUTH_SOCK` or `GIT_SSH_COMMAND`;
- returns `125` for any launcher/validation/setup failure, reserving the agent's own exit code otherwise.

Runtime provenance/hashes remain the HA-1.1 responsibility and are not duplicated into this launcher.

## HA-1.2 acceptance

Before merge, acceptance must establish on Windows that:

- the wrapper and agent run in the same user/session;
- neither wrapper nor child has a persistent visible console window when the wrapper is started with `-WindowStyle Hidden`;
- the dedicated named pipe becomes reachable;
- stdout/stderr and launcher logs are written under the project-owned log root;
- normal agent exit is propagated by the wrapper;
- forcibly terminating the wrapper also terminates the agent through `KILL_ON_JOB_CLOSE`;
- a second launch against an occupied pipe fails observably;
- `\\.\pipe\openssh-ssh-agent` is refused before child creation;
- Windows PowerShell 5.1 is sufficient for the wrapper;
- the real Windows Hello/WebAuthn signing prompt still appears through this hidden launch path on the production user session.

The last item cannot be established on a non-interactive automation VM without the production Hello credential; it is a real-machine acceptance gate, not something the VM test should simulate.

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
2. open project-owned stdout/stderr logs with append-only file access plus an inherited `NUL` stdin handle;
3. restrict child handle inheritance with `STARTUPINFOEX` / `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to only stdin/stdout/stderr; this also deliberately prevents the child from inheriting the Job Object handle, which is required for `KILL_ON_JOB_CLOSE` to remain effective when the wrapper exits;
4. add the Job Object to the same creation attribute list with `PROC_THREAD_ATTRIBUTE_JOB_LIST`;
5. create `sshenc-agent.exe` with `CREATE_SUSPENDED | CREATE_NO_WINDOW`, so Windows assigns it to the Job Object as part of process creation;
6. resume the primary thread only after `CreateProcessW` returns successfully;
7. wait for the child process;
8. propagate the child's exit code;
9. close the Job Object on every launcher exit.

`PROC_THREAD_ATTRIBUTE_JOB_LIST` is supported on Windows 10 and newer and removes the orphan window that would exist with a separate post-create `AssignProcessToJobObject` call. If Task Scheduler or another supervisor terminates the PowerShell wrapper after `CreateProcessW` returns, Windows closes its Job Object handle and terminates the associated agent process.

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

## Win32 evidence

The launcher decision depends on supported Windows process APIs rather than undocumented console-host behavior:

- Microsoft documents `CREATE_NO_WINDOW` and `CREATE_SUSPENDED` in [Process Creation Flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags).
- Microsoft recommends `STARTUPINFOEX` plus `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` when a child must inherit only an explicit handle allowlist; see [Create processes](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-processes).
- `UpdateProcThreadAttribute` documents `PROC_THREAD_ATTRIBUTE_JOB_LIST` as assigning the listed Job Objects to the child at creation time, supported on Windows 10+ / Windows Server 2016+: [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
- Job-object termination semantics, including `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, are documented by Microsoft under [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) and the job limit structures.
- The Microsoft Terminal maintainers explicitly call direct `conhost` command-line hosting an unsupported API surface in [discussion #19003](https://github.com/microsoft/terminal/discussions/19003). Separately, [issue #17178](https://github.com/microsoft/terminal/issues/17178) demonstrates that `conhost.exe --headless` does not propagate the hosted child's exit code.

These links are design evidence, not a claim that undocumented implementation details will remain stable. The selected path intentionally uses the documented Win32 APIs instead.

## Logging

The launcher keeps three classes of logs under `%LOCALAPPDATA%\hello-approval\logs` by default:

- `launcher.log` — launcher start, child exit, and launcher failures;
- `agent.stdout.log` / `agent.stderr.log` — inherited stdout/stderr from `sshenc-agent.exe`;
- `sshenc-operations.jsonl` — child-only `SSHENC_LOG` target for sshenc's own operation/warn/error logging and upstream rotation.

`SSHENC_LOG` is set only in the launcher process immediately before child creation, inherited by the child, and restored before a normal wrapper exit. No user- or machine-scope environment variable is written.

The launcher refuses a log directory outside `%LOCALAPPDATA%\hello-approval`. It validates/creates the project root first, then walks each requested child directory one component at a time, refusing reparse points before traversing or creating through them.

Launcher-owned log leaves (`launcher.log`, `agent.stdout.log`, and `agent.stderr.log`) are opened with `FILE_FLAG_OPEN_REPARSE_POINT`, rejected if the opened object is a reparse point or has more than one hard link, and checked with `GetFinalPathNameByHandleW` against the requested path. The inherited stdout/stderr handles remain open without delete sharing while the child runs. `sshenc-operations.jsonl` is pre-created and validated with the same leaf checks before child creation, then closed because upstream `sshenc` must reopen/rotate that path itself. A same-user process replacing that path after launch is outside the v0.1 threat boundary; pretending otherwise would require breaking upstream rotation or changing upstream logging semantics.

## Guardrails

The launcher:

- requires absolute paths for `AgentPath`, `ConfigPath`, and any explicit `LogDirectory`;
- requires a real, non-reparse `sshenc-agent.exe` file;
- requires a real, non-reparse config file;
- gives the child an explicit current directory equal to the pinned runtime `bin` directory instead of inheriting Task Scheduler's ambient working directory;
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

### Production acceptance evidence

On 2026-09-15, the HA-1.2 launcher passed the production interactive-user acceptance on the real Windows host and production `github-signing` ECDSA-SK credential:

- the hidden PowerShell wrapper and `sshenc-agent.exe` both ran in interactive session `1`;
- both processes reported `MainWindowHandle = 0`;
- the dedicated production signing pipe was usable through the hidden launch path;
- a local disposable `git commit -S` completed successfully with the production hardware-backed credential;
- `git verify-commit` and `git log --show-signature` both reported a good SSH signature for the expected Git signing principal;
- the acceptance harness restored the prior production Scheduled Task in its `finally` cleanup path.

Together with the VM lifecycle/failure-injection acceptance above, this closes the HA-1.2 runtime acceptance gate. Review of the implementation remains a separate merge gate.

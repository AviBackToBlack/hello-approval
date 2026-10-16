# Release procedure

This document defines how a `hello-approval` release is accepted, tagged and published, and what maintenance-only mode means afterwards. Each of the following needs its own explicit maintainer approval:

- merging the release-preparation change;
- running the logon acceptance;
- creating and pushing the tag;
- publishing the GitHub Release.

No step below implies permission for the next one.

## Scope of 0.1.0

`0.1.0` is the Windows Git SSH signing reference integration described in [CHANGELOG.md](../CHANGELOG.md). It does not implement generic approval workflows.

## 1. Preconditions

- The release-preparation change is merged into `main`. Record the exact `main` commit SHA, the **release commit**. Post-merge CI on that SHA reports every Windows PowerShell 5.1 acceptance job as successful.
- The maintainer has decided the repository license. A `LICENSE` file is either present on the release commit, or the maintainer has explicitly accepted publishing without one.
- The maintainer accepts the conditional no-visible-console statement in the changelog and [#49](https://github.com/AviBackToBlack/hello-approval/issues/49).
- On the signing host:
  - HelloApproval Doctor reports no BLOCK and no WARN;
  - the default terminal application is Windows Console Host ([SCHEDULED-TASK.md](SCHEDULED-TASK.md#default-terminal-application));
  - the operator has a local, offline copy of the host's rollback instructions. The logon test can interrupt any remote session.

## 2. Logon acceptance gate

This gate proves what the Scheduled Task path is for: the agent starts on its own at a real user logon. Restarting the task does not prove that.

1. Record the current state: the HelloApproval task state, the launcher and `sshenc-agent.exe` process IDs and start times, and the list of visible top-level windows.
2. Sign out of Windows and sign back in. A full restart is a separate, explicitly approved variant.
3. For about 60 seconds after the desktop appears, watch for any console window, terminal window or flash. Any visible window **fails** the gate (see [SCHEDULED-TASK.md](SCHEDULED-TASK.md#production-visual-acceptance)).
4. Confirm all of the following:
   - the task is `Running` and its launcher started after this logon;
   - exactly one `sshenc-agent.exe` is running, from the pinned runtime, as a child of the launcher;
   - the dedicated pipe exists;
   - no `OpenConsole.exe` or new Windows Terminal window belongs to the launcher.
5. Run Doctor. It must report no BLOCK and no WARN.
6. Sign a throwaway file through the effective Git configuration and verify it against the effective `gpg.ssh.allowedSignersFile` (Windows Hello prompt):

   ```powershell
   $f = Join-Path $env:TEMP 'ha-logon-probe.txt'
   [IO.File]::WriteAllText($f, "logon probe`n")
   & (git config --global --includes --get gpg.ssh.program) -Y sign -n git -f (git config --global --includes --get user.signingkey) $f
   cmd /d /c "ssh-keygen -Y verify -f `"$(git config --global --includes --get gpg.ssh.allowedSignersFile)`" -I <principal> -n git -s `"$f.sig`" < `"$f`""
   ```

   Pass means both commands exit 0 and the output contains `Good "git" signature`. These `--global --includes` reads measure the context-neutral baseline, so run the probe outside any repository. Repository-local or `includeIf` settings can override them inside a worktree ([GIT-CONFIG.md](GIT-CONFIG.md)); section 3 checks the release worktree separately.

If any check fails, restore signing using the host's rollback instructions and stop. The release is blocked until the failure is understood.

## 3. Signed annotated tag

The release tag is created on the signing host with the existing Windows Hello-backed identity. Tag and commit signing use the same Git configuration (`gpg.format=ssh`, effective `user.signingkey`).

1. Check out the release commit in a clean worktree. Do not reuse a development checkout.

   ```powershell
   git fetch origin
   git worktree add <clean-path> <release-commit-sha>
   cd <clean-path>
   git status --short   # must print nothing
   # The signing settings in this worktree must come from the global baseline, not repo-local or includeIf overrides:
   git config --show-origin --get gpg.ssh.program
   git config --show-origin --get user.signingkey
   git config --show-origin --get gpg.ssh.allowedSignersFile
   ```

2. Create the annotated, signed tag (Windows Hello prompt):

   ```powershell
   git tag -s v0.1.0 -m "hello-approval v0.1.0" <release-commit-sha>
   ```

3. Verify the tag locally before pushing it, **independently of the signing broker**.
   - Plain `git tag -v` runs the effective `gpg.ssh.program`, which is the pinned `sshenc.exe` (it forwards the verification modes to `ssh-keygen`). That would route the release check through the same broker that made the signature.
   - So pin stock Windows OpenSSH `ssh-keygen.exe` for this one command, as the local verifier does ([LOCAL-VERIFICATION.md](LOCAL-VERIFICATION.md)). Use `System32` from 64-bit Windows PowerShell; a 32-bit process must use the `Sysnative` alias instead.
   - The trust store is still the effective `gpg.ssh.allowedSignersFile`, which is the project trust store.

   ```powershell
   $sshKeygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
   git -c "gpg.ssh.program=$sshKeygen" tag -v v0.1.0
   git rev-parse 'v0.1.0^{commit}'   # must equal the release commit SHA
   ```

   This requires `Good "git" signature` for the expected principal and key fingerprint. If this step fails, first check that `$sshKeygen` exists and that the trust store is the effective one; a verifier-selection problem does not mean the tag is bad.

4. Push only the tag:

   ```powershell
   git push origin refs/tags/v0.1.0
   ```

5. Confirm that GitHub verified the SSH signature on the tag object. Use the API, not the web badge:

   ```powershell
   $tagSha = gh api repos/AviBackToBlack/hello-approval/git/ref/tags/v0.1.0 --jq .object.sha
   gh api repos/AviBackToBlack/hello-approval/git/tags/$tagSha --jq .verification
   ```

   This requires `verified: true` and `reason: valid`.

What to do when verification fails depends on whether the tag has been pushed:

- **Step 3 fails (the tag is not pushed yet).** First rule out verifier selection and trust configuration (see step 3). If verification still genuinely fails, you may delete the unpublished local tag (`git tag -d v0.1.0`) and investigate before trying again.
- **Step 4 push is rejected** (for example, `already exists`). Check whether the tag already exists on origin (`git ls-remote origin refs/tags/v0.1.0`) before treating your local tag as unpublished. If origin already has `refs/tags/v0.1.0`, treat it as published and follow the step-5 rules below. Never force-push a tag.
- **Step 5 fails (step 4 has already pushed `refs/tags/v0.1.0`, so the tag is published).**
  - Stop the release and do not publish the GitHub Release.
  - Leave the remote tag exactly as it is, and investigate the failure.
  - Do not delete, force-update or replace the published tag without a separate maintainer decision. If the tag has to be abandoned, release a new version instead.

## 4. GitHub Release

After the tag is verified, publish a GitHub Release for the existing tag. Use the `0.1.0` section of `CHANGELOG.md` plus the dated acceptance results as notes:

```powershell
gh release create v0.1.0 --verify-tag --title "hello-approval v0.1.0" --notes-file <reviewed-notes.md>
```

The notes must state:
- the release scope: Git signing reference integration only;
- the tested configurations;
- the security limitations;
- the known issues, linked;
- the logon acceptance result and date.

Do not attach binaries. The upstream `sshenc` release is obtained and verified separately, as described in [PROVENANCE.md](PROVENANCE.md).

## 5. Maintenance-only mode after 0.1.0

After publication, the project accepts:

- security fixes;
- correctness fixes for the released Git signing integration;
- the open hardening backlog (#9, #35, #37, #49);
- documentation corrections;
- re-pinning a new upstream `sshenc` release through the provenance upgrade gate.

Each change is a small reviewed PR from `main`, merged only with explicit maintainer approval. New capabilities, including roadmap phases 3 and 4, need a design issue and a deliberate decision to leave maintenance mode.

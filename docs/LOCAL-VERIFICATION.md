# Local Git signature verification

## Scope

HA-1.5 makes local SSH-signature verification a first-class trust decision instead of relying on a hosting-platform badge.

It owns two per-user files under the existing hello-approval Git directory:

```text
%LOCALAPPDATA%\hello-approval\git\allowed_signers
%LOCALAPPDATA%\hello-approval\git\verification.gitconfig
```

The verification fragment owns only:

```text
gpg.ssh.allowedSignersFile = <absolute project-owned allowed_signers path>
```

and is registered through its own global `include.path`. HA-1.4's signing fragment remains independently owned and unchanged.

## Explicit principal mapping

Install the local trust mapping with an explicit principal:

```powershell
.\scripts\Install-HelloApprovalLocalVerification.ps1 `
    -Principal "principal@example.invalid"
```

The installer deliberately does **not** infer the principal from `user.email`, the commit author, the GitHub account, or the credential label. Those are different identity/policy concepts.

For v0.1, the principal must be one exact literal token. Pattern lists, wildcards, negation, and multiple principals are intentionally rejected. The generated OpenSSH allowed-signers entry is restricted to the SSH signature namespace used by Git:

```text
principal@example.invalid namespaces="git" <key-type> <public-key-blob>
```

The key is copied logically from the canonical public key at `%USERPROFILE%\.ssh\github-signing.pub`; no private material is read or created.

If an existing effective global `gpg.ssh.allowedSignersFile` points somewhere else, installation fails closed. `-OverrideExistingVerificationConfig` preserves the old setting physically and gives the later hello-approval verification include precedence in the context-neutral global baseline. As with HA-1.4, preserved conflicts mean later reruns continue to require the override switch.

## What the principal means — and does not mean

In Git's SSH-signature verifier, an `allowed_signers` principal identifies a trusted key. It is **not** automatically compared to the Git commit's author or committer email.

For example, a commit authored by `bob@example.invalid` can verify successfully when its signing key is trusted under principal `alice@example.invalid`. Git reports the signer principal from the trust mapping; it does not infer an author/signature identity binding.

Therefore HA-1.5 treats these as separate questions:

1. **Cryptographic signature:** does the embedded SSH signature verify against the signing key?
2. **Local trust mapping:** is that key present in the configured `allowed_signers` store for an accepted principal and namespace?
3. **Git author/committer identity:** what identity metadata is recorded in the commit?

HA-1.5 proves (1) and (2). HA-1.4 keeps (3) separate, with an optional repo-local identity guardrail where desired.

## Machine gate

Verify a commit in the target repository with:

```powershell
.\scripts\Test-HelloApprovalLocalVerification.ps1 `
    -Repo C:\path\to\repo `
    -Commit HEAD
```

The verifier requires all of the following:

- target repository effective `gpg.format=ssh`;
- effective `gpg.ssh.allowedSignersFile` points to the project-owned trust store;
- the trust store has the expected HA-1.5 marker and exactly one v0.1 signer entry;
- the trusted public key equals `%USERPROFILE%\.ssh\github-signing.pub`;
- `git verify-commit <commit>` exits 0;
- Git `%G?` reports `G`;
- Git `%GT` reports `fully`;
- Git `%GS` equals the explicit principal from the trust store;
- Git reports a non-empty signing-key fingerprint.

`git verify-commit` is the authoritative command gate in this slice. Verification forces `gpg.ssh.program` process-locally to the stock Windows OpenSSH `%SystemRoot%\System32\OpenSSH\ssh-keygen.exe`; it does not persistently change Git configuration. This keeps the local verifier independent from the `sshenc` signing broker used to create the signature.

## `git log --show-signature` is evidence, not the exit-code gate

`git log --show-signature` is useful for a human-readable record, and the verifier prints it after the machine checks pass. Its process exit code is **not** sufficient as an acceptance signal.

With a cryptographically good SSH signature whose key is absent from the configured trust mapping, Git can print output such as `No principal matched.` while `git log --show-signature` still exits 0. In that same state, `git verify-commit` fails and Git's pretty-format fields report an undefined/untrusted signature rather than `G` / `fully`.

## Local trust is not universal revocation

`allowed_signers` answers a local verifier policy question: which keys/principals this machine currently trusts for the Git SSH-signature namespace. It is not a universal revocation service and does not define hosting-platform policy.

OpenSSH/Git also support validity windows and revocation files. Key replacement, validity/revocation lifecycle, and historical-signature semantics are intentionally handled in HA-1.7 rather than being implied by this slice.

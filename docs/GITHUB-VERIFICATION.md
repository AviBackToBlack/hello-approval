# GitHub verification

## Scope

HA-1.6 proves that the **exact commit object signed locally through the hello-approval path** is also accepted by GitHub's independent commit-signature verifier.

This is intentionally separate from HA-1.5 local verification. A hosting-platform badge is not the local root of trust, and a GitHub `Verified` result by itself does not prove that Windows Hello / `sshenc` produced the commit signature.

## Register the public key as a Signing Key

GitHub must know the public key before it can verify SSH-signed commits produced with that credential.

Register `%USERPROFILE%\.ssh\github-signing.pub` in **GitHub → Settings → SSH and GPG keys → New SSH key**, choosing **Signing Key** as the key type. See GitHub's [Adding a new SSH key to your GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account).

Do not register it merely as an Authentication Key and assume that signing verification follows. If one physical/public key is intentionally used for both purposes, GitHub treats authentication-key registration and signing-key registration as separate account records.

hello-approval does not automate signing-key registration/removal in v0.1. That operation changes account trust state and remains an explicit user action.

## Machine gate

After creating and pushing a locally signed commit, run:

```powershell
.\scripts\Test-HelloApprovalGitHubVerification.ps1 `
    -Repository "OWNER/REPO" `
    -Repo C:\path\to\local\repo `
    -Commit HEAD
```

The verifier requires:

1. the local revision resolves to one exact 40-hex commit object;
2. the **local commit object itself** contains `gpgsig -----BEGIN SSH SIGNATURE-----`;
3. the GitHub REST commit endpoint returns the **same SHA**;
4. `commit.verification.verified` is `true`;
5. `commit.verification.reason` is exactly `valid`;
6. GitHub returns an extracted SSH signature, a non-empty signed payload, and `verified_at`.

The local SSH-signature check is deliberate. GitHub also creates and signs some commits itself. Such a GitHub-generated commit can legitimately have `verified=true` and `reason=valid`, but that is not evidence that the commit passed through the local Windows Hello-backed signing broker.

## GitHub-generated versus locally generated signatures

A concrete distinction from this repository's own history:

- GitHub-created merge commits are authored on behalf of the user but committed by `GitHub <noreply@github.com>` and can carry a GitHub-generated PGP signature.
- VM-created implementation commits in this repository are intentionally unsigned and therefore report `verified=false`, `reason=unsigned`.
- HA-1.6 acceptance requires a third case: a commit whose **local object already contains an SSH signature** before push, and whose **same SHA** is reported by GitHub as `verified=true`, `reason=valid`, with an SSH signature.

Therefore neither the GitHub `Verified` badge nor the REST `verified=true` field should be treated alone as proof of the hello-approval local signing path.

## API permissions

Reading commit verification does not require signing-key administration permission. The HA-1.6 verifier uses the normal [Get a commit REST API](https://docs.github.com/en/rest/commits/commits#get-a-commit) through `gh api` and does not request `admin:ssh_signing_key`.

Listing, adding, or deleting SSH signing keys is a different account-management API surface. hello-approval deliberately does not require or request that broader permission for HA-1.6 verification.

## Persistence and revocation boundary

GitHub documents [commit-signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification) as persistent within a repository network once verified. Removing a signing key later is therefore not a universal retroactive revocation mechanism for historical commits.

Key retirement, GitHub signing-key removal, local `allowed_signers` rotation, and historical-signature semantics are handled explicitly in HA-1.7 rather than being inferred from HA-1.6.

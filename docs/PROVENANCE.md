# Upstream provenance and pinning

## 1. Purpose

`hello-approval` depends on upstream software that participates directly in the signing path. This document records what was verified for the pinned v0.1 reference release and, equally importantly, what was **not** proven.

The goal is not to label an upstream binary "trusted." The goal is to make acquisition reproducible, make assumptions explicit, and force every upgrade through the same review gate.

## 2. Current v0.1 pin

The v0.1 reference integration is pinned to:

- upstream repository: `godaddy/sshenc`;
- release: `v0.6.101`;
- release tag target commit: `2b689c8644d0590e80f1839721dec53b95f44526`;
- selected Windows asset: `sshenc-x86_64-pc-windows-msvc.zip`;
- selected asset SHA-256: `1b7d452f2de462a569c40841ee6080782e34da3815cca842c50b4278657c8f0e`;
- published: `2026-06-04T01:27:13Z`.

The release asset digest reported by GitHub matches an independent SHA-256 calculation over a fresh download of the release ZIP.

Machine-readable details are in [`provenance/sshenc-v0.6.101.json`](../provenance/sshenc-v0.6.101.json).

## 3. Why the ZIP is selected instead of MSI / WinGet

The upstream Windows MSI is not an inert file-copy package.

At the pinned release commit, `installer/sshenc.wxs` wires:

- `sshenc.exe install` as a deferred custom action after file installation; and
- `sshenc.exe uninstall` as a deferred custom action before file removal.

The upstream Windows integration path can manage the stock Windows `ssh-agent` service and persistent `SSH_AUTH_SOCK` / `GIT_SSH_COMMAND` state. Those mutations intentionally violate the isolation boundary of `hello-approval`.

Therefore v0.1:

- does **not** use the MSI;
- does **not** use WinGet when it resolves to that MSI;
- does **not** run `sshenc install` or `sshenc uninstall`;
- extracts only the explicitly approved binary surface from the pinned ZIP.

This is an isolation decision, not an assertion that ZIP distribution is inherently safer or more trustworthy.

## 4. Archive contents and v0.1 binary surface

The pinned x86_64 Windows ZIP contains six files:

| File | SHA-256 | v0.1 role |
| --- | --- | --- |
| `sshenc.exe` | `83ff19ffb8601a6d44ad68a8d042e16b31515aa948e451a3bb434e6914665df7` | **Required** signing/key-management client |
| `sshenc-agent.exe` | `fb75b274c1e0369a5f9d315ba1143f5235f3ec625050429ab4fda969148d35f2` | **Required** isolated signing agent |
| `sshenc-keygen.exe` | `7294f2bfe7f3806d93dffb6be05e532ef61b8d8660a5e83a84dc09bb9a73319c` | Not used; `sshenc keygen --strong` is used instead |
| `gitenc.exe` | `b88350c1594c615b46fef4ea1f1bca144f96a85b85ce6224988bdd5e663fbe90` | Explicitly out of scope; couples signing with Git SSH transport |
| `sshenc-tpm-bridge.exe` | `1b7cdeed3c235ced1ba32669be4e25ddefc0f68dd1b09d6db3a688385bb5e0a8` | Not used in native-Windows v0.1 |
| `sshenc_pkcs11.dll` | `7a5caf3a325f9234e8afe14355fbcbeda16fc1f7c043f11560b07647ba33a0b2` | Not used in v0.1 |

`sshenc.exe` and `sshenc-agent.exe` do not import the packaged `sshenc_pkcs11.dll`; their normal PE imports are Windows/runtime DLLs, including `webauthn.dll`.

The v0.1 runtime layout should therefore install only the required client and agent binaries unless a later reviewed feature proves another file is necessary.

## 5. Windows Authenticode status

Every PE file inspected in the pinned x86_64 ZIP has a zero-valued PE Security Directory. In particular, the two v0.1-required binaries are not Authenticode-signed:

- `sshenc.exe` — unsigned;
- `sshenc-agent.exe` — unsigned.

Upstream documentation also states that Windows release binaries are shipped unsigned.

This is a **point-in-time finding for v0.6.101**. Every version upgrade must re-check executable-signing state rather than treating unsigned Windows binaries as a permanent upstream property.

A matching SHA-256 hash proves that the downloaded bytes match the pinned bytes. It does not prove who produced those bytes or that they are safe.

## 6. Release-to-source linkage

The `v0.6.101` Git ref is a lightweight tag pointing directly to:

`2b689c8644d0590e80f1839721dec53b95f44526`

GitHub reports that commit's signature as verified/valid. There is no separate annotated-tag signature because the tag resolves directly to a commit object.

The release workflow run associated with this tag is:

- workflow: `Release`;
- run ID: `26923839226`;
- run result: success;
- run head: `v0.6.101` / `2b689c8644d0590e80f1839721dec53b95f44526`;
- run started: `2026-06-04T01:18:28Z`.

The tag's `.github/workflows/release.yml` delegates the build to:

`godaddy/hardware-enclave/.github/workflows/reusable-release.yml@main`

That is a floating branch reference in source. GitHub retained the resolved workflow metadata for the actual run and records that `@main` resolved to:

`2fd3cf2594f8b9446004b73feef7ef2dd7954bdf`

This makes the specific historical run more reconstructable than the source YAML alone, but using `@main` is still weaker than pinning the reusable workflow by immutable commit SHA.

## 7. Build-pipeline provenance limitations

The resolved reusable release workflow at `2fd3cf2594f8b9446004b73feef7ef2dd7954bdf` uses several floating inputs:

- `windows-latest` for Windows runners;
- `actions/checkout@v5`;
- `actions/cache@v5`;
- `actions/upload-artifact@v5` / `actions/download-artifact@v5`;
- `dtolnay/rust-toolchain@stable`.

The release workflow also patches workspace version fields from the Git tag before building. That mutation is visible and deterministic in the workflow, but the resulting build workspace is not byte-for-byte identical to the checked-out source tree.

GitHub Actions logs for this historical run were no longer available during the September 2026 audit (`HTTP 410 Gone`). Consequently, the exact historical `windows-latest` runner image, resolved `stable` Rust toolchain, and exact action implementation SHAs cannot now be independently recovered from the logs.

Therefore `hello-approval` does **not** describe v0.6.101 as a reproducible or fully attestable build.

## 8. The `libenclaveapp` clone nuance

The reusable workflow performs an unpinned shallow clone of `godaddy/libenclaveapp`.

For the v0.6.101 source tree:

- the main signer/agent code uses the published `hardware-enclave = 0.2.5` crate, whose Cargo.lock entry records a crates.io checksum;
- `sshenc-tpm-bridge` still has a direct path dependency on `../../../libenclaveapp/crates/enclaveapp-tpm-bridge`;
- the Windows release build uses `cargo build --workspace`, so the bridge binary in the ZIP is affected by that cloned source;
- `sshenc.exe` and `sshenc-agent.exe`, the only binaries used by v0.1, are not wired to that direct bridge path dependency.

Repository history allows the unpinned clone used during this release window to be reconstructed with high confidence: the `libenclaveapp` default-branch tip immediately before the run was also `2fd3cf2594f8b9446004b73feef7ef2dd7954bdf`, and no commits landed between release-run start and completion of the x86_64 Windows build. However, the workflow itself did not enforce that SHA.

This is another reason to minimize the installed binary surface instead of treating every file in an upstream archive as implicitly equivalent.

## 9. Windows Hello / WebAuthn path used by this project

The accepted production path uses:

`sshenc keygen --strong`

At v0.6.101, `--strong` selects the FIDO2 / WebAuthn SK path and produces an OpenSSH key of type:

`sk-ecdsa-sha2-nistp256@openssh.com`

The relevant WebAuthn feature is default-enabled in the upstream Windows CLI build.

An upstream open bug, `godaddy/sshenc#254`, reports `meta_tag_verify` failures for newly generated **legacy TPM/CNG** keys on v0.6.101. Its reproducer explicitly uses `--auth-policy none --no-user-presence`; it is not the `--strong` WebAuthn/SK path used by the v0.1 reference architecture.

That issue is therefore not evidence that the already-accepted `--strong` path is broken. It is evidence that version-level confidence is insufficient: every upgrade must repeat the real Windows Hello signing acceptance path.

## 10. What the pin does and does not prove

The pin provides:

- deterministic identification of the approved release archive;
- detection of accidental/malicious byte changes relative to the pinned digest;
- an auditable link to release tag, release run, and resolved reusable-workflow commit;
- a documented minimal binary surface.

The pin does **not** provide:

- Authenticode publisher identity for the Windows binaries;
- SLSA provenance or equivalent signed build attestation;
- reproducible-build proof;
- protection if the upstream source, CI pipeline, GitHub account, dependencies, runner image, or build actions were compromised before the pinned bytes were produced;
- assurance that a future release is safe merely because its checksum is recorded.

## 11. Upgrade gate

An `sshenc` upgrade must be treated as a reviewed security change, not as routine package-manager churn.

For every candidate version:

1. resolve the release tag to its exact commit;
2. inspect commit/tag verification state;
3. identify the exact release workflow run;
4. record all resolved reusable-workflow commits available from GitHub run metadata;
5. inspect release workflow changes relative to the currently pinned release;
6. inspect installer/package-manager behavior even if v0.1 still uses ZIP distribution;
7. download the exact selected archive and verify its SHA-256 independently;
8. enumerate archive contents and compare them with the expected surface;
9. compute hashes of the binaries that will actually be installed;
10. check Authenticode state of those binaries;
11. re-check direct/path dependencies that affect the required signer/agent binaries;
12. review new upstream Windows/TPM/WebAuthn issues since the previous pin;
13. repeat native Windows acceptance: `--strong` key creation, isolated agent, Windows Hello prompt, byte-exact/local signature verification, Git signing, and GitHub verification;
14. only after acceptance, update the machine-readable pin in a dedicated reviewable PR.

No updater should silently replace the pinned binaries merely because a newer upstream release exists.

## 12. Evidence map for v0.6.101

Primary upstream evidence used by this audit:

- `godaddy/sshenc` tag `v0.6.101` → commit `2b689c8644d0590e80f1839721dec53b95f44526`;
- `.github/workflows/release.yml` at that tag;
- `installer/sshenc.wxs` at that tag;
- `crates/sshenc-cli/src/commands.rs` and related Windows integration code at that tag;
- `crates/sshenc-gitenc/src/main.rs` at that tag;
- `crates/sshenc-tpm-bridge/Cargo.toml` at that tag;
- GitHub release metadata for `v0.6.101`;
- GitHub Actions run `26923839226` and its `referenced_workflows` metadata;
- resolved reusable workflow `godaddy/hardware-enclave/.github/workflows/reusable-release.yml` at `2fd3cf2594f8b9446004b73feef7ef2dd7954bdf`;
- upstream issue `godaddy/sshenc#254` for the legacy TPM-path caveat.

Future audits should record equivalent immutable references rather than relying on current `main` documentation.

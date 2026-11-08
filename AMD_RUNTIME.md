# Native Store Authentication

This fork uses the pinned AppleMediaServices/commerce/adid runtime already
provided by upstream ipatool. Store-specific provisioning and header generation
execute native Apple routines under Unicorn; no C++ helper or separately hosted
anisette service is needed.

## Authentication Flow

1. Load or provision a Store AMD identity in the selected keychain profile.
2. Generate real `X-Apple-AMD` and `X-Apple-AMD-M` headers through the native runtime.
3. Sign and send the existing Store authentication request.
4. Persist updated native state in the same profile.

AuthKit `X-Apple-I-MD` proofs are not substituted for Store AMD headers.
Anonymous AMD provisioning does not authenticate an Apple Account and does not
produce an application's decryption material.

## Isolated Profiles

```sh
profile="$HOME/.local/state/ipatool-analysis"
ipatool --state-directory "$profile" auth keyring-check
ipatool --state-directory "$profile" auth login
```

An explicit profile must be an absolute mode-0700 directory, not a symlink.
Missing directories are created. Existing public directories are rejected,
without changing their permissions. This bypasses legacy/XDG session migration.

On Linux, explicit profiles use the existing default Secret Service collection
with bounded D-Bus operations. No collection is created or unlocked, and no
graphical prompt is opened. Missing/locked keyrings fail before asking for Apple
credentials. There is no file-keyring fallback for this path.
`--keychain-passphrase` does not unlock GNOME Keyring.

The canonical profile path selects its keychain namespace: keep that path
stable. Without an explicit profile, upstream platform backend selection and
state-directory behavior remain unchanged.

`auth status` reports the local `ipatool-auth-status-v1` contract with
`session_available`; it does not contact Apple, disclose account fields or
guarantee that a saved token is still accepted. This lets an orchestrator decide
when to invoke the ordinary interactive `auth login` command. Credentials and
AMD state remain persistent in the selected profile; status does not clear them.

With `--format json`, command failures include a machine-readable `code`:
`session-missing`, `session-expired`, `auth-code-required`, `license-required`,
or `command-failed`. Wrapped errors retain their classification. `download
--no-reauth` returns token expiry instead of attempting saved-password login,
so a caller can expose login/2FA on the terminal. Without this flag, download
retains its existing automatic-refresh policy. Enrollment never retries itself;
known session/license failures are classified before private material import.

## Validation

On Linux, anonymous native Store provisioning, AMD generation, reopening a saved
identity in a separate process, and metadata-only Secret Service preflight have
been verified. Native AMD was also accepted for a fresh licensed-app download
authorization during enrollment. New Apple Account login/2FA on this fork has
not yet been verified interactively; it is a separate validation boundary.

Normal tests do not access accounts or provision identities. Opt-in runtime
tests in `internal/storeauth` are gated by `IPATOOL_ADI_RUNTIME_TEST`,
`IPATOOL_AMD_PROVISION_TEST` and the documented private result-directory
variables in the test source. Do not enable live provisioning just to repeat
offline checks. Generated states and proof headers are private, never fixtures
to commit.

For app-specific native import and the offline-consumer export contract, see
[FairPlay enrollment](docs/fairplay-enrollment.md). IPA decryption is not part of
this fork.

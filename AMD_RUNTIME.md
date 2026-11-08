# Native Store AMD Fork

This is the local working copy of public fork
[`Dejniel/ipatool`](https://github.com/Dejniel/ipatool), based on upstream
[`001d889896fcb118546443c5dfe0997d11b74f56`](https://github.com/majd/ipatool/commit/001d889896fcb118546443c5dfe0997d11b74f56).
`origin` points to the fork; `upstream` points to `majd/ipatool`. AMD changes are
committed on local `main` but have not been pushed. The public fork currently
contains upstream code only. This work is independent of the earlier
C++-helper experiment.

## Scope and Status

| Step | Status on Linux, 2026-11-08 |
| --- | --- |
| Download pinned native assets and initialize modern ADI | Verified with fresh assets |
| Provision a fresh Store AMD identity without an account | Verified against Apple |
| Generate AMD through AppleMediaServices and adid | Verified: decoded AMD 24 bytes, AMD-M 60 bytes |
| Reopen saved identity in another process without provisioning | Verified offline; AMD-M unchanged |
| Connect native AMD to the account sign-in request | Verified with synthetic transport tests |
| Access existing Secret Service over SSH without graphical prompting | Metadata-only check passed |
| Authenticate a real Apple Account, including 2FA, on this branch | Not tested; requires manual login |
| Import an application FairPlay keybag and decrypt an IPA in this branch | Not integrated |

No C++ AMD implementation was ported. Upstream already contains the necessary
AppleMediaServices/commerce/adid/FairPlay routines and Unicorn shims. This branch
adds anonymous Store provisioning, persists its native state, and uses real
Store AMD proofs for sign-in and commerce requests. It does not alias AuthKit
`X-Apple-I-MD` headers to `X-Apple-AMD`.

Provisioning start and finish use the same live `ModernADI` session. Native
assets are prepared before requesting the expiring challenge. Later header
generation can reopen the saved `adi.pb` state. Multiple guest engines execute
inside one Go process; they are not containers, a macOS VM or an iOS Simulator.

## Build

From this checkout, using the Go version specified by `go.mod` or later:

```sh
go generate ./pkg/keychain ./pkg/http ./pkg/util/machine ./pkg/util/operatingsystem ./pkg/appstore ./pkg/log
go build -trimpath -ldflags '-X github.com/majd/ipatool/v2/cmd.version=amd-runtime' -o exp/ipatool-native-amd .
go test -p 4 -timeout 5m -skip '^TestSignerIntegration$' ./...
go test -race -p 4 -timeout 5m ./cmd ./internal/storeauth ./internal/systemkeyring ./pkg/appstore ./internal/sap/assets
go vet ./...
```

The normal suite skips opt-in live runtime, provisioning and system-keyring
checks. The command above also excludes the existing live SAP signer test.
Normal tests, the listed race checks and vet passed locally.

## Isolated Login

Always use an explicit `--state-directory` for this experiment. It must be an
absolute mode-0700 directory, not a symlink. A missing directory is created; an
unsafe existing directory is rejected rather than silently chmodded.

An explicit directory bypasses legacy/XDG session migration. Its canonical path
selects distinct keychain entries; it never reads the old experiment's account,
cookies or AMD identity. Keep the same path for subsequent commands: moving the
profile changes its keychain namespace. Do not copy credentials between device
identities.

On Linux, explicit profiles use the existing default Secret Service collection,
with five-second operation deadlines and at most one second for session cleanup.
Missing or locked collections fail before prompting for Apple credentials.
Unexpected provider prompts are dismissed, not displayed. There is no file-store
fallback. `--keychain-passphrase` does not unlock GNOME Keyring. Outside explicit
profiles, the original platform backend selection remains unchanged.

For the current archive-local checkout, run these from the archive root:

```sh
export XDG_CACHE_HOME="$PWD/cache/ipatool-native-amd/runtime"
profile="$PWD/work/experiments/ipatool-native-amd/session-state"
binary="$PWD/work/projects/ipatool/exp/ipatool-native-amd"
"$binary" --state-directory "$profile" auth keyring-check
"$binary" --state-directory "$profile" --verbose auth login
```

`keyring-check` inspects collection metadata, without reading/writing credential
entries or contacting Apple. `auth login` requests the Apple ID and password
interactively, provisions the identity if absent, and prompts for 2FA if required.
Do not put credentials in command-line arguments, committed files or chat.
First-time native asset downloads can take longer than subsequent runs.

The archive's old helper, its profile, the previously downloaded/decrypted IPA,
the development VM and Apple signing credentials are untouched.

## Runtime Checks

These are opt-in tests, not part of ordinary unit testing:

| Setting | Test | Side effects |
| --- | --- | --- |
| `IPATOOL_ADI_RUNTIME_TEST=1` | `TestLiveModernADIRuntime` | Downloads pinned public assets and opens native guests; no provisioning |
| `IPATOOL_AMD_PROVISION_TEST=1` plus private absolute `IPATOOL_AMD_TEST_DIR` | `TestLiveStoreAMDProvisioning` | Provisions a new anonymous Store identity against Apple; saves private results |
| `IPATOOL_AMD_REOPEN_DIR` pointing at a successful result | `TestLiveStoreAMDReopen` | Reopens saved native state and checks AMD-M continuity; no provisioning or credential access |
| `IPATOOL_KEYRING_LIVE_TEST=1` | `TestLiveDefaultSystemKeyringPreflight` | Reads only collection metadata |

Use `go test -count=1 -run '^TestName$' -v ./internal/storeauth` for the first three,
or `./internal/systemkeyring` for the last. Do not enable online provisioning
merely to repeat the offline reopen test. Result directories are mode 0700;
native state and proof headers are mode 0600 and must not be committed.

The archive-local successful provisioning result is
`work/experiments/ipatool-native-amd/provision-2606515522/`. The runtime cache is
separate from the earlier helper experiment. It contains only public pinned
assets, not an Apple Account session.

## Next Boundary

First validate real sign-in/2FA on this isolated profile. Only then integrate the
already demonstrated keybag-import and offline IPA-decryption pipeline. Native
AMD provisioning alone does not prove account login or provide an application's
FairPlay decryption credential.

# FairPlay Enrollment Export

`ipatool enroll` authorizes an already licensed app, imports the returned keybag
using the original live native generator, and exports the resulting private
FairPlay state. It does not purchase an app, log in, download IPA bytes, recover
a decryption model or decrypt an IPA. Offline recovery/decryption belongs to a
separate consumer such as UnfairPlay.

## Usage

Use the same saved account and hardware identity as for the matching IPA:

```sh
ipatool --state-directory "$PROFILE" enroll \
  --app-id "$APP_ID" \
  --external-version-id "$VERSION_ID" \
  --output "$NEW_EXPORT_DIRECTORY"
```

The app ID and external version ID must be positive numeric identifiers. The
destination must not exist and its parent must exist. An expired account or
missing license is an error: enrollment does not silently reauthenticate,
purchase, retry with another KBSync, or fall back to a different endpoint.
Stage messages report progress without printing private payloads.

## Native Session

`AppStore.Enroll` opens one `machine.EnrollmentSession`, generates KBSync once,
sends exactly one authorization request, and imports its response before
disposing the runtime. The normal download KBSync cache is not used.

The response's app/version/bundle identity is checked before import. Both the
response keybag and its license records come from the same authorization.
Replaying a captured reply in a newly created guest is not equivalent: the
verified control returned native status `-42052` even with fresh KBSync.

The runtime implements the required Darwin file/CF/IPC contracts inside the
guest. It never opens host SC Info paths, accesses the host's Apple key stores,
implements guest worker creation with host threads, or runs a macOS VM. Native worker continuations
preserve CPU registers and stack while sharing the live guest heap. IPC and
workers have explicit bounds; unknown ports, ownership violations and unsupported
operations fail rather than fabricating successful cryptographic responses.

Native entitlements are read from the pinned commerce arm64e code signature.
The virtual caller is an ordinary synthetic user, not a claim about the host's
code-signing identity. The native service version query runs the corresponding
native routine; no invented version is supplied.

Entry points require the exact macOS 27.0.1 / 26A434 asset profile. All bundle
size/hash pins are checked before these entry points are used. This is not a
generic loader for arbitrary Apple runtime versions.

## Export Contract

The export is a new directory with mode `0700`; its files have mode `0600`:

```text
manifest.json
hardware.bin
state/system/SC Info.sidb
state/system/SC Info.sids       # only if the native runtime created it
state/shared/SC Info.sidb       # only if the native runtime created it
state/shared/SC Info.sids       # only if the native runtime created it
licenses/000.sinf
licenses/001.sinf              # only if the response contains more licenses
```

`hardware.bin` is the six raw bytes of the Store device GUID, not a text MAC.
No empty or invented state file is emitted. The system SIDB must exist and be
nonempty for a successful export.

`manifest.json` uses schema `ipatool-fairplay-enrollment-v1` and contains:

| Field | Meaning |
| --- | --- |
| `app_id`, `bundle_id`, `external_version_id` | Validated target identity |
| `native_profile` | `product_version` and `build_version` of the pinned native image, never the host OS |
| `hardware` | File record for the six-byte hardware identity |
| `state` | File records, including original virtual SC Info paths |
| `licenses` | Response SINF records, preserving their numeric IDs |
| `native_import_complete` | Native keybag import returned success and generated state |

Every file record has a relative `path`, `bytes` and lowercase hex `sha256`.
Only known system/shared SIDB/SIDS paths are accepted. The manifest is written
last. Consumers must require a complete manifest and verify every file's path,
size and hash before use. A partial directory is not an enrollment; rerun with
a new destination instead of merging or overwriting it.

This contract intentionally does not depend on another tool's capture schema.
An orchestrator can map it to an offline consumer's inputs and associate the
matching IPA. `native_import_complete` is not `plaintext_verified`: only the
later recovery/decryption step can establish that the model and IPA agree.

Although passwords, cookies, account tokens, raw HTTP, KBSync and raw keybags
are not exported, SIDB/SINF and hardware material are account-bound secrets.
Keep the entire export private and outside version control.

## Tests and Verified Boundary

Ordinary tests cover lifecycle/order, identity validation, failures without
retries, memory/IPC ownership, export hashes/modes and CLI argument validation.
They contain synthetic values only and do not access an Apple Account.

Opt-in checks:

| Setting | Test | External effects |
| --- | --- | --- |
| `IPATOOL_ENROLLMENT_RUNTIME_TEST=1` | `TestLiveEnrollmentRuntime` | Public asset loading if uncached; no account/authorization |
| `IPATOOL_ENROLLMENT_REPLAY_INPUT` and `IPATOOL_ENROLLMENT_REPLAY_RESPONSE` | `TestLiveEnrollmentRejectsReplayedResponse` | Reads explicit private fixture JSON; no authorization |
| `IPATOOL_ENROLLMENT_LIVE_CONFIG` | `TestLiveEnrollmentAuthorization` | Reads explicitly selected credentials and performs one licensed-app authorization |

The Linux live-test configuration is a private JSON file naming
`KeychainNamespace`, `Cookies`, `AMDState`, `Hardware`, `IPA`, `Output` and `AppID`.
Inputs must be private regular files with absolute paths. It uses an in-memory
keychain and a separate cookie copy; it never updates the source profile or
logs in. The IPA is read only to select the exact external version.

On Linux, 2026-11-08, fresh native AMD authorization and same-session keybag
import/export passed for an existing licensed iOS app. The replay rejection
control, normal suite, race checks and vet also passed. The user subsequently
completed fresh interactive Store login/2FA and the toolkit's full IPA flow,
including decryption and verification of all 15 encrypted ARM64 images. This
does not establish support for every app, other operating systems or native
profiles, or live validation of the newer selectable GrandSlam 2FA delivery.

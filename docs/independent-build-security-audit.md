# Independent BCD Build: Source and Dependency Review

## Scope

This review starts at the public source tag `v0.1.712`, commit
`f811dd05a9183cda20ffd3956cb1958cafe654f7`. The workflow builds from that source
tree plus its pinned submodules and listed, hash-checked build inputs. It does
not consume an official BCD IPA. The preflight rejects tracked IPA files and
the workflow clears the output directory before compiling.

This is a source and build-pipeline review. It is not a dynamic network capture,
an independent cryptographic audit of every upstream dependency, or a device
test. The requested workflow does not install or launch the app on a device.

## Network, credentials, and user data

The app has ordinary service traffic for the store/library features it provides:
Steam, Amazon Games, Epic, GOG, EA, itch.io, BCD's update/recommendation files,
and Steam Cloud. Store sign-in and download requests are separate user-facing
features; CI supplies no store account credentials.

Steam and Amazon authentication material is stored in the iOS Keychain. The
Amazon flow opens Amazon's own sign-in page and exchanges its returned code for
device tokens. The reviewed source says it does not log those tokens, codes,
serials, or account names. The workflow runs the existing Steam sign-in and
guest-log secret-redaction checks.

The source includes explicit log and feedback upload features. A player chooses
to send a log; the app limits the list to the 20 newest logs, applies the
existing scrubber, and posts to `bcd.bcd-logs.workers.dev`. An optional screenshot
is sent separately after the player selects it. Performance traces are an
opt-in diagnostic and travel with a log only when the player sends that log.
These are user-triggered diagnostic uploads, so this review does not describe
the app as having no telemetry or no outbound data.

The v0.1.712 tag does not contain `bcd-logs/worker/worker.js`, its deployment
configuration, or its Worker tests; the paths are also absent from `.gitmodules`.
The repository's CI checks therefore continue to inspect the client-side
scrubbing, data fields, size limits, explicit user actions, screenshot handling,
and credential redaction, while printing an `UNVERIFIED` result for the missing
server checks. The external Worker implementation, authorization, storage,
retention, access logging, and deployed version cannot be established from this
checkout. This build does not make a server-side privacy or security claim for
that service, and no CI step uploads logs, feedback, screenshots, or credentials.
The external Worker is not represented as a source component in the SBOM.
The operator-side `tools/pull-logs.py` helper referenced by several baseline
host tests is also absent from this tag. CI does not need or execute that helper;
its download, local-file handling, and key-redaction behavior are therefore
reported as `UNVERIFIED` rather than inferred from tests of code that is not
available.

Screenshots are created by the app. The Photos integration requests add-only
access; the source does not request photo-library read access. Files and external
drive access are mediated by the app's file-selection flows. Existing checks
cover log upload scrubbing, trace opt-in, screenshots, feedback attachments,
Steam sign-in, and credentials redacted from guest logs.

## Build and supply-chain controls

- All four top-level source submodules are checked against their exact gitlink
  commits. Additional source repositories use full commit pins; source archives
  and redistributables use fixed SHA-256 values recorded in
  `security/independent-build-inputs.json` and the output SBOM.
- GitHub Actions are pinned to full commit SHAs. Compiled-library caches use a
  unique workflow-run namespace, so a prior run cannot supply a cached library
  to this build. Wine, FEX, DXMT, and the workflow's other source-built
  components are rebuilt on a cache miss—which is forced for every run.
- Microsoft VC++ redistributables are proprietary. The build extracts only the
  required DLLs from Microsoft's HTTPS distribution and rejects a changed
  package hash. Those files cannot be rebuilt from public source.
- Metal Shader Converter is Apple's proprietary, Apple-signed library. The
  source tag pins its iOS dylib hash and the build verifies that hash, the Apple
  code signature, the converter headers, and the mirror archive hash. The
  Apple Developer download portal requires interactive sign-in, so the
  credential-free CI fetches a byte-pinned mirror of the original Apple
  payload. The exact mirror commit and both hashes are included in the artifact.
  This means CI verifies Apple-origin bytes and signature, while the download
  transport is a public mirror rather than Apple's authenticated portal.
- No Apple ID, signing certificate, Steam account, or repository secret is
  supplied to the build. Xcode runs with `CODE_SIGNING_ALLOWED=NO`; packaging
  applies only the project's existing ad-hoc sideload seal, with no team
  identity or provisioning profile. The entitlement plists are preserved as
  separate review files in the artifact.

## Prebuilt source-tree files

The baseline contains tracked Windows PE and native binaries in addition to
source, including the prebuilt StikJIT framework. The build scans tracked files
for PE, Mach-O, ELF and archive signatures and records their hashes before
compiling, then records which tracked files changed. The existing workflow
builds Wine's Unix/iOS libraries, FEX, DXMT and several Windows DLLs from
source, but not every PE-side DLL in the baseline is regenerated. The
artifact's `prebuild-inputs.json` and `tracked-binary-rebuild-delta.json` make
that boundary auditable; none of these files is sourced from an official BCD
IPA.

## Preserved entitlements

`Madeira.entitlements` and the ad-hoc sideload entitlement plist retain
Increased Memory Limit, Extended Virtual Addressing, and
`com.apple.security.cs.allow-jit`. The workflow validates the source plists and
reads the embedded entitlements from both IPA signatures. An unsigned,
ad-hoc-sealed IPA has no Apple provisioning profile or team signature; the
artifact includes the entitlement files for inspection and does not claim that
Apple authorized a device installation.

## What the artifact proves

The GitHub Actions artifacts contain both generated unsigned IPAs, their
SHA-256 file, a CycloneDX SBOM, source and runner provenance, the build log,
the exact prebuild binary inventory and rebuild delta, the security review,
and entitlement sidecars. The workflow's existing security checks remain
required and fail the job if they fail. No device execution or Apple ID login
is part of the job.

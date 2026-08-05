# Production readiness

This is the authoritative status as of 2026-08-05. Evidence is candidate-bound: a successful result
for one commit or package does not automatically qualify a later one. The privileged evidence below
was gathered against candidate `3ad4b92`; see [Candidate delta review](#candidate-delta-review-v0110)
for what changed since and why the open gates are unchanged.

| Target | Verdict |
|---|---|
| **x64** | **Not production-ready** - candidate `3ad4b92` passed the executed ETW, WFP/SCM, trust, IPC-workaround and installer gates, but host snapshot continuity and the exact Network Logon gate were not run |
| **Arm64 (native)** | **Not production-ready** - native CI build/package/installer passed for `3ad4b92`; privileged WFP/SCM/trust/IPC/session behavior remains unverified |
| **x64 on Arm64** | **Not production-ready** - emulated application identity and privileged runtime behavior remain unverified |

## Current x64 evidence

Candidate:

- commit `3ad4b92d0b9a6ebc6ab0b99b082e2a0c4569f327`;
- CI run `30536205557`, successful for verify and native x64/Arm64 package/installer jobs;
- CodeQL run `30536201742`, successful;
- clean Windows 11 native-x64 VM campaign supplied on 2026-07-30;
- sealed VM manifest: 46 entries, SHA-256
  `20e3b8f8651923f9b09dda1db7eeba5210726cba5651bbf1d9ea4bea97cc63e3`.

The supplied VM campaign confirmed:

- ETW session names bind profile, PID and process-start identity;
- closing the dashboard with **X** keeps the tray process and its live session by design;
- forced termination leaves an orphan, and relaunch reclaims it without deleting another live
  instance's session;
- repeated Attribution cycles remain bounded by live dashboard instances;
- tray Exit releases Attribution sessions;
- DNS kill/relaunch recovery works and Ctrl+C exits 0 with cleanup;
- an Outbound service restart reclaims the old service session;
- no `.NET Runtime` event 1026 occurred during the qualification window;
- the former `0x800705AA` ETW exhaustion crash did not recur;
- WFP full gate 25/25, trust 12/12, installer lifecycle and final SCM/WFP/connectivity cleanup passed.

Full supplied-result classification:
[`validation/2026-07-30-x64-qualification-3ad4b92.md`](validation/2026-07-30-x64-qualification-3ad4b92.md).

## Why x64 is still not production-ready

Three protocol gaps prevented a complete campaign:

1. **IPC default-path drift.** The shipped probe still defaulted to the obsolete
   `C:\Program Files\WinSight-VM` root. The gate passed 7/7 only when the operator supplied the
   protected CLI path explicitly. The corrected probe derives both binaries from its own package
   directory, and the runbook still passes the paths explicitly. This correction needs a new
   candidate-bound package and VM rerun.
2. **Network Logon was `NOT_RUN`.** A real Network token proved pipe denial under impersonation, but
   that was not the literal process-level protocol. The corrected runbook requires a second isolated
   control machine and WinRM. The probe itself fails unless `S-1-5-2` is present, `S-1-5-4` is absent,
   the self-test returns exit 3 / `ServiceUnavailable` / no mutation, and the same SCM process and
   command remain running.
3. **S0/S1/S2 were `NOT_RUN`.** Snapshot take/restore is an authority of the hypervisor host;
   `VBoxManage` is not expected inside the guest. The corrected runbook labels host-only operations,
   records `showvminfo` evidence outside the VM disk, and makes the guest stop when that evidence is
   missing.

The following independent gates also remain open:

- native Arm64 privileged WFP/SCM/trust/IPC/session qualification;
- x64-on-Arm64 application-identity qualification;
- independent human EN/FR/ES review for the exact candidate;
- a new exact-candidate CI, CodeQL, package/installer and clean-VM rerun after the protocol changes.

## Candidate delta review, v0.11.0

Evidence here is candidate-bound, so a release after `3ad4b92` requires this section rather than
letting the statement above age into an implied pass for code it never covered.

**What changed:** autostart command-line triage and scheduled-task argument capture, both in the
unprivileged detection engine; three presentation paths that render a persistence verdict; and the
MCP server's tool, prompt and resource surface.

**What it touches:** nothing on the privileged boundary. The WFP engine, the SCM lifecycle, the
service-path trust check and the authenticated named-pipe IPC are byte-identical, and the MCP process
still reaches the service through the same posture-only interface with no mutation path. The gates
whose surface is unchanged therefore keep the standing recorded in the validation files, and were not
re-run — which is the delta review this project's rule asks for, not a claim that they were repeated.

**What it does not change:** the verdict. All three targets remain **not production-ready** for
exactly the reasons above. The three x64 protocol gaps, native Arm64 privileged behaviour and
x64-on-Arm64 identity are all still open, and native Arm64 is blocked on hardware the project does
not have rather than on unwritten work.

**What was verified for this candidate:** the full suite on x64 including the packaged MCP stdio
contract, the engine-library and privileged-managed coverage gates, and formatting. Native Arm64
build, packaging and installer lifecycle run in CI on a native runner as usual; the Arm64 *privileged
runtime* remains `NOT_RUN`.

## Authenticode policy

Public binaries have no Authenticode publisher certificate. SignPath Foundation declined the free
application on 2026-07-29 because public adoption signals were insufficient. The current repository
policy is therefore deliberately `REQUIRE_SIGNED_RELEASE=false`.

This is an accepted and visible distribution limitation, not a passed security gate:

- Windows displays an unknown publisher;
- the four release targets must report `NotSigned`, with no signer or timestamp;
- users must verify SHA-256 checksums and GitHub provenance/SBOM attestations;
- the workflow fails if the signing-policy variable is absent or malformed;
- unsigned policy forces `-DisableSignature`, so residual credentials cannot sign opportunistically;
- the optional signed path remains available for a future certificate and requires full
  publisher/timestamp verification when re-enabled.

Unsigned distribution does not by itself make the product production-ready or unsafe; it removes
Windows publisher identity and shifts artifact authentication to explicit hash and provenance checks.

## Required next qualification

Use [`validation/VM_QUALIFICATION_KIT.md`](validation/VM_QUALIFICATION_KIT.md) from the exact new
package:

1. bind commit, successful CI run, architecture and both artifact hashes;
2. create and record S0 from the hypervisor host;
3. install prerequisites in the guest and construct the protected candidate root;
4. record the expected unsigned status and run the installer/integrity gates;
5. restore S0 from the host, recreate the protected candidate and record S1;
6. run ETW lifecycle gates, then WFP 25/25, trust 12/12 and local IPC 7/7 from separate S1 restores;
7. create S2 on the host before full WFP and prove every restore from the host;
8. while the AuditOnly service is running, run Network Logon 10/10 from a second isolated machine;
9. seal manifests outside the VM disk, restore S0 from the host and verify final absence.

Only a complete evidence set for the exact candidate can change the verdict above.

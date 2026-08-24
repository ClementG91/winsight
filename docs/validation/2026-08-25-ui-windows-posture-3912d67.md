# x64 dashboard and Windows-posture qualification - 2026-08-25

## Evidence identity

| Field | Value |
|---|---|
| Candidate | `3912d675dc0917a57c8c05e0bd9c4a2adaa5463b` |
| Version | `0.11.6` |
| Successor automation | CI `32789592412` and CodeQL `32789591166` PASS on `8230aa91c3a26e08967124cf3a1a47028a2e2df6` |
| Platform | Windows 11 build `10.0.26200.0`, native x64 VirtualBox VM |
| VM snapshot restored after campaign | `dd7ac330-bf18-44f8-bee6-21e2473e04f6` |
| Network and integration isolation | NAT only; second adapter, clipboard and drag-and-drop disabled |

Raw structured output, transcript and screenshot are retained outside the repository. The target VM
was shut down through ACPI and restored to the exact snapshot after evidence export.

## Artifact binding

| Artifact | SHA-256 |
|---|---|
| x64 setup | `2883EE186FF98C2814DCB245FFCAB110A0D1DC5692C1290D31F72D773209872B` |
| x64 ZIP | `C493CE32DC343E0E69A809C8BA33B498D685E087FED9AA4CE1F15401F0E6EA04` |
| SPDX SBOM | `F38A8E1A971219EC45AB19B5280FEB0B400CCD1AA98F077647C0EAB98BEA04E1` |
| `winsight-dashboard.exe` | `EA73D469C63C838451A73D34C5E2B3E44D3F1C9A5FB02724F3AC3C6629BEDDB8` |
| structured VM result | `4147B6FC1B07FB33C3663CF2AE685EB85F82A5AC726C853B6B8919B632711134` |
| French settings screenshot | `C3F1D1D0EEFEE53FBDE7589F8594C5713E2B20D1B3E60CD836CB5164A022D292` |

All protected binaries were `NotSigned`, as required by the accepted unsigned policy.

## Local gates

The exact candidate passed:

- strict `dotnet format` verification;
- dependency-vulnerability audit;
- Release build with zero warnings and errors;
- 1,964 tests run serially with no failure;
- x64 release build, PE/branding checks, MCP stdio contract and SBOM generation;
- French installer install/uninstall lifecycle and dashboard smoke in EN, FR and ES.

## VM dashboard results

The exact ZIP was copied to and extracted inside the VM. The driver verified the ZIP and dashboard
hashes before launch. All EN/FR/ES smoke processes exited `0`.

UI Automation measured the French VirusTotal settings dialog at 560 by 490 device-independent
pixels. At its supported minimum width, all four actions measured 244 pixels wide and formed the
requested 2-by-2 grid: provider actions on the first row, then Cancel and the primary save action.
The save action ended 32 pixels before the modal's right edge. The local-analysis status content was
measured as a single centred badge child rather than a translated bullet character. A WPF STA test
also exercises that minimum-width layout and the successful DPAPI save/close path.

## Windows-security interpretation

The VM integrity scan checked eight protections and returned two hardening findings: Memory
integrity was not running and Defender Controlled Folder Access reported documented state `0`
(`Disabled`). Secure Boot, driver-signature enforcement, test-signing, kernel debugger, application
code integrity and Defender antivirus were healthy for the observed VM.

A separate read-only comparison on the development Windows host established the converse case that
prompted the copy change: Memory integrity/HVCI was enabled while Controlled Folder Access was still
state `0`. This confirms that the two readings are independent controls, not a WinSight false
positive. The dashboard now groups them under Windows Security and explicitly states that disabling
Controlled Folder Access does not imply that Core isolation or Memory integrity is disabled.

## Scope boundary

This is an exact UI, package, localization and posture-reading qualification. It is not represented
as a repeat of the privileged WFP/SCM/trust/IPC/ETW campaign. Those unchanged runtime surfaces remain
covered by the candidate-bound `8486155` record and its green successor CI. Successor `8230aa9`
passed CI and CodeQL, including native Arm64 build/test/package/installer. Native Arm64 privileged
runtime and x64-on-Arm64 identity qualification remain hardware-dependent open gates.

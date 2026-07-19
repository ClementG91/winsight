# Phase 4, RansomWhere-class ransomware behavior detection

Status: **increment 1 (heuristics core) implemented.** This is the pure, testable foundation:
Shannon-entropy "looks encrypted" scoring and a bounded windowed burst detector. The
file-system watcher, canary/decoy planting, and dashboard alert are the next increments
(thin I/O over this core), and are not built yet.

## Goal

Objective-See's RansomWhere? watches for the *behavior* of ransomware rather than a
signature: a process rapidly encrypting, renaming, or deleting many files. WinSight's Phase 4
does the same, user-mode, reusing the exact discipline that made the firewall and Guardian
solid — **all the decisions live in a pure, unit-tested core; the OS-facing watcher is a thin,
separately-validated shell.**

## The two signals

1. **Canary / decoy files.** Plant hidden decoy files in the directories ransomware sweeps
   (Documents, Desktop, Pictures, …). A decoy has *no legitimate reason to change*, so a single
   touch is a high-confidence signal that fires immediately.
2. **Behavioral burst.** Ransomware's tell is volume and speed. Count recent suspicious file
   events — a freshly written file whose content **looks encrypted** (high Shannon entropy), a
   rename, a delete — in a short sliding window, and fire once when they cross a threshold.

Neither is a verdict on its own; together, and tuned conservatively, they catch the behavior
while a security tool that cries wolf on ordinary activity would be worse than nothing.

## What is implemented (increment 1, this doc's subject)

- **`ShannonEntropy`** — entropy of a byte buffer in bits/byte (0..8). Encrypted/compressed data
  sits near 8; text and structured formats well below. `LooksEncrypted` requires both a minimum
  sample size (so a tiny high-entropy fragment cannot trigger) and a conservative threshold.
- **`RansomwareBurstDetector`** — a bounded, clock-injected sliding-window counter. `Observe`
  returns true **exactly once per burst** (or immediately on a touched canary), so the caller
  alerts once, not once per file. It is bounded (it stops accumulating once fired, until `Reset`)
  and pure (the caller supplies each event's timestamp), so it is fully unit-tested.

## Increments ahead

2. **Canary manager** (thin I/O) — choose decoy locations and hidden, innocuous names; plant and
   track them; a `FileSystemWatcher` over the decoys + watched user dirs feeds signals into the
   core. Same shape as Guardian's watchers, real-machine validated.
3. **Entropy sampling on write** — read a bounded prefix of a newly-written file to score it,
   without reading whole files (resource-exhaustion resistance).
4. **Dashboard alert** — a loud, localized tray alert on a fired burst, listing what was touched;
   reuse the shared report model and the proven `ShowBalloonTip` path.

## What this cannot do (stated on purpose)

- **It detects and alerts; it does not stop the encryption.** Halting a process mid-write needs a
  kernel **minifilter** (`FltRegisterFilter`) with the authority to block file I/O, which needs an
  EV certificate + Microsoft attestation signing. Explicitly deferred, exactly as for Guardian's
  blocking.
- **Process attribution is limited without elevation.** A `FileSystemWatcher` reports *what*
  changed, not *which process* changed it; attributing the burst to a PID needs an ETW file
  provider or the minifilter, both elevated. The canary and burst signals fire on the behavior
  regardless; naming the culprit is a later, elevated bonus.
- **It is bounded and conservative.** Thresholds are tuned so ordinary bulk operations (a backup,
  an archive extract) do not trip it lightly, and the detector stops accumulating once it has
  fired until the operator acknowledges — no runaway state.

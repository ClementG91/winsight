# Phase 4, RansomWhere-class ransomware behavior detection

Status: **increments 1–4 implemented and validated end-to-end on a real machine.** The pure
heuristics core (Shannon-entropy scoring + bounded windowed burst detector), canary/decoy planting,
the file-system watcher, entropy-on-write sampling, and the opt-in dashboard toggle with a loud tray
alert. The watcher is user-mode (it watches the user's own directories, no elevation) and its runtime
is covered by real-`FileSystemWatcher` functional tests plus a live end-to-end test on the installed
build. What remains is elevation-gated: naming the *process* responsible, and *stopping* the write.

**Protection is opt-in, deliberately.** This is the only WinSight feature that *writes* into the
operator's personal folders (everything else only reads), so nothing is planted until they tick
"Ransomware protection". Decoys are hidden, swept on start if an earlier run died without cleaning
up, and removed when the toggle is cleared or WinSight closes.

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

## The pure core

- **`ShannonEntropy`** — entropy of a byte buffer in bits/byte (0..8). Encrypted/compressed data
  sits near 8; text and structured formats well below. `LooksEncrypted` requires both a minimum
  sample size (so a tiny high-entropy fragment cannot trigger) and a conservative threshold.
- **`RansomwareBurstDetector`** — a bounded, clock-injected sliding-window counter. `Observe`
  returns true **exactly once per burst** (or immediately on a touched canary), so the caller
  alerts once, not once per file. It is bounded (it stops accumulating once fired, until `Reset`)
  and pure (the caller supplies each event's timestamp), so it is fully unit-tested.

### Firing once per burst means someone must re-arm it

The detector deliberately latches: once fired it ignores further signals until `Reset()`. That is
what turns one encryption wave into one alert instead of one alert per file — but it also means the
**owner of the detector is responsible for re-arming it**, and forgetting to is not a small bug.

`RansomwareMonitor` therefore calls `Detector.Reset()` immediately after forwarding each `Detected`
event. Without it, the first alert of a session was the *only* alert that session: a second wave, or
one the operator missed while away from the machine, produced nothing. A security tool whose silence
stops meaning "nothing is happening" is worse than one that never alerted, because the operator
trusts the silence. This was a real defect, found by live testing rather than by review, and is now
pinned by `Monitor_ReArmsAfterAnAlert_SoASecondWaveStillFires`.

## Increments

1. **Heuristics core.** ✅ Done. `ShannonEntropy` and `RansomwareBurstDetector`, described above —
   pure, clock-injected, fully unit-tested, no I/O.
2. **Canary manager + file watcher.** ✅ Done. `CanaryManager` plants hidden decoys in the
   protected directories and answers `IsCanary`; `RansomwareSignalClassifier` (pure) maps a change to
   a signal; `RansomwareFileWatcher` runs a `FileSystemWatcher` over the dirs, classifies each change,
   and feeds the burst detector; `RansomwareMonitor` wires them and removes the decoys on dispose. A
   touched canary fires immediately; a rename/delete burst fires once. User-mode, real-machine
   validated by functional tests. Entropy-on-write is intentionally NOT wired here (legitimately
   compressed files — .docx/.jpg/.zip — are high-entropy and would false-positive).
3. **Entropy sampling on write.** ✅ Done. `RansomwareEntropySampler` reads a bounded 4 KB prefix
   (sharing flags that never fight the writer; any I/O trouble yields false, never an exception) and
   scores it with `ShannonEntropy`. It is gated twice: formats **compressed by design** are skipped
   outright — .zip/.jpg/.mp4 and, critically, .docx/.xlsx/.pptx, which are ZIP containers and would
   otherwise flag someone saving a Word file — and the score still needs a minimum sample and a
   conservative threshold. Ransomware's own extensions (.locked, .encrypted, …) are exactly what
   still gets scored; in-place encryption that keeps the original extension is covered by the canary.
4. **Dashboard alert.** ✅ Done. An opt-in "Ransomware protection" toggle in the dashboard starts and
   stops the monitor (planting runs off the UI thread; clearing the toggle removes the decoys).
   `RansomwarePresenter` maps a detection to a localization key and a detail line that shows only the
   file NAME — never the directory tree, so an alert cannot leak a folder layout into a screenshot.
   A touched canary is presented as critical, a burst as a warning, on the proven `ShowBalloonTip`
   path, localized en/fr/es.

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
  an archive extract) do not trip it lightly. The detector latches on firing so one wave is one
  alert rather than one per file, and `RansomwareMonitor` re-arms it immediately afterwards so the
  next wave still alerts — bounded state, but never a permanently silent detector.
- **Alerts are subject to the OS, not just to us.** Windows suppresses tray balloons under Focus
  Assist / "Ne pas déranger" (including its automatic full-screen rule), and throttles an app that
  posts many toasts in quick succession. Both are Windows behaviours WinSight cannot override, and
  both look exactly like "the alert is broken" when testing by hand — check the notification centre
  and the Focus Assist state before concluding a detection failed. Because of this, every detection
  is also written to a local **alert journal** (`%LocalAppData%\WinSight\alerts.log`, see
  `AlertJournal`) *before* the balloon is raised, so a suppressed or missed alert still leaves a
  record. A detection that leaves no trace is indistinguishable from no detection at all.

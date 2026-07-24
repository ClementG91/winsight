# Capturing screenshots for the README

WinSight's screenshots are the one asset that cannot be produced in CI, and there is a reason they
are not produced on a maintainer's daily machine either.

## Why not on your own PC

Every interesting WinSight view is, by construction, a picture of the machine it is running on:

| View | What a screenshot publishes |
|---|---|
| Persistence | Your installed software inventory |
| Connections / DNS | Hosts your machine talks to |
| Processes / Modules | What you run, and the DLLs it loads |
| Any path column | `C:\Users\<your name>\...` |

Committed to a public repository, that is permanent and irreversible — git history keeps it even
after a later deletion. A security tool whose README leaks its maintainer's software inventory and
network peers is exactly the exposure the tool exists to help people notice.

**Capture on a clean VM.** The same isolated VM used for the qualification gates is ideal: no
personal software, no real network peers, no meaningful user profile.

## Procedure

On a clean Windows VM with WinSight installed from a release package:

1. Set the display to **1920×1080** and the Windows theme you want to show. Use the default 100%
   scaling so text renders crisply.
2. Launch the dashboard. Let the overview scan finish.
3. Capture with `Win+Shift+S` or Snipping Tool, **window only** — not the whole desktop, which would
   include the taskbar and any other application.
4. Save as PNG into `assets/screenshots/` using the names below.
5. **Review every image before committing.** Even on a VM, check for the VM's hostname, an account
   name you would rather not publish, or a path that identifies you.

## Wanted images

| File | View | Why it earns its place |
|---|---|---|
| `overview.png` | Overview after a scan | The first impression: what WinSight tells you at a glance |
| `firewall.png` | Outbound firewall, audit-only, one or two policies | The flagship capability, in its safe default state |
| `persistence.png` | Persistence results with at least one notable item | Shows verdicts and the explanation text |
| `alert.png` | A Guardian or ransomware tray alert | Shows the real-time half of the product |

Optional but useful: the same view in French or Spanish, to show the localization is real rather than
claimed.

## Producing an alert to photograph

Both alerting features can be triggered safely on a VM:

- **Guardian** — add a harmless value under
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, for example pointing at `notepad.exe`. The
  tray alert fires within seconds. Delete it afterwards.
- **Ransomware** — enable protection in the dashboard, then rename several decoy files in quick
  succession. Turn protection off afterwards, which removes the decoys.

Do not use real malware. Nothing in these screenshots requires it, and a sample on a VM you later
reuse is a bad trade.

## Wiring them into the README

Once `assets/screenshots/overview.png` exists, add it under the tagline:

```markdown
<p align="center">
  <img src="assets/screenshots/overview.png" width="820" alt="WinSight overview after a scan" />
</p>
```

Keep each image under about 500 KB — PNG optimised, 1920 px wide at most. The repository already
carries two logo assets; screenshots are the only other binary content it should accumulate.

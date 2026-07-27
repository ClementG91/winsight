# Privacy Policy

**Last updated: 2026-07-27**

WinSight is a security tool. A security tool that quietly reports on the machine it is supposed to be
protecting is a contradiction, so this policy is short by design: there is very little to describe.

## What WinSight collects

**Nothing.** WinSight has no telemetry, no analytics, no crash reporting service, no update check, no
account and no server component. Nothing about you, your machine, or what WinSight finds on it is
transmitted to the maintainer or to any third party as a consequence of installing or running it.

Everything WinSight produces stays on your machine:

| Data | Where it lives | Why |
|---|---|---|
| Scan findings | In memory, and in a file only when **you** export one | The report you asked for |
| Alert journal | `%LocalAppData%\WinSight\alerts.log`, capped at 500 entries | So a detection survives a notification Windows suppressed |
| Crash reports | `%LocalAppData%\WinSight\`, written locally, never sent | So a crash can be diagnosed by its owner |
| Firewall policy | The service's own state, on this machine | So your rules survive a reboot |
| UI language | Per-user Windows registry | So the app opens in your language |

You can delete any of it at any time. Uninstalling removes the application; the folders above are
yours to keep or delete.

## The one thing that leaves your machine

**VirusTotal hash lookups — off by default, and only ever with your own API key.**

If you choose to enable it, WinSight sends a **SHA-256 hash** of a file to VirusTotal to ask whether
that hash is already known:

```
GET https://www.virustotal.com/api/v3/files/{sha256}
```

Being precise about this, because "we send a hash" is easy to say loosely:

- **File contents are never uploaded.** WinSight has no upload path. It reads a hash and asks about it.
- **It is opt-in.** No lookup happens until you enter a VirusTotal API key yourself.
- **It uses your key, not the maintainer's.** You create your own VirusTotal Community account. The
  project ships no key and pays for no quota on your behalf.
- **A hash is not nothing.** A file that is unique to you — a document, an internal build — has a hash
  unique to you, and asking about it tells VirusTotal that someone holds that file. This is why the
  feature is off until you switch it on.
- **Your API key is stored encrypted** with Windows DPAPI, scoped to your Windows user account, so
  another user on the same machine cannot read it.

Once a hash reaches VirusTotal, VirusTotal's own privacy policy governs it, not this one:
<https://docs.virustotal.com/docs/please-give-me-some-privacy>.

Turn it off by clearing the API key in the dashboard's settings. No key, no lookups.

## Links you click

The dashboard offers buttons that open Windows' own tools (Windows Security, Startup Apps, Firewall)
and, where relevant, a VirusTotal result page in your browser. Those are ordinary links: nothing is
sent until you click one, and then it is your browser making the request, not WinSight.

## Children

WinSight is a system administration tool, not directed at children, and collects no data from anyone.

## Your rights

Because WinSight holds no personal data about you, there is nothing to request access to, correct, or
erase — the local files listed above are on your own disk and under your own control. If you believe
otherwise, or you have a privacy question about the project, write to the address below.

## Who is responsible

| | |
|---|---|
| Maintainer | Clément Genest, trading as **eDeveloppe**, France |
| Website | <https://www.edeveloppe.com/> |
| Contact | <contact@edeveloppe.com> |
| Project | <https://github.com/ClementG91/winsight> |

## Changes

This policy is versioned in the repository like the rest of the project, so every change to it is a
commit with a date and an author. Material changes will be noted in [CHANGELOG.md](CHANGELOG.md).

# Write attribution — design and measured limits

Attribution answers one question: **which program installed this?** Guardian can say a Run key
appeared; attribution says `setup.exe` wrote it, four seconds ago, as pid 4242.

It is the capability that separates a scanner from a monitor, and it is also the capability most
likely to be quietly wrong. A wrong name beside a security finding is worse than no name — an
operator acts on it. Everything below is shaped by that.

## Shape

```
WriteAttributionWatcher   privileged edge — one kernel trace session, reports observations
        │                 (IWriteWatcher, so the layer above is testable unelevated)
        ▼
AttributionHost           lifecycle + health; feeds the index, answers queries
        │
        ▼
WriteAttributionIndex     pure, bounded, time-windowed; the correlation rules live here
```

The rules are deliberately separated from the session: how far back to look, what counts as the
same target, which write wins when several match. Those are where attribution gets things quietly
wrong, and they are unit-tested without elevation or a live trace.

## Why it needs Administrator, and why it is not required

A kernel trace session is privileged. WinSight is deliberately unprivileged everywhere else, so
attribution is started only when the process happens to be elevated. Unelevated, an alert simply
carries no author. Attribution is an enrichment: a detection is never withheld because nobody could
name its author.

`AttributionHealth` reports which situation you are in, because "no answer" hides three:

| Field | Meaning |
| --- | --- |
| `Refused` | Not elevated — the session never opened. |
| `Attributed` | Writes seen and pinned on a process. |
| `UnknownProcess` | Seen, but the writer was not in the process index. |
| `UnannouncedKey` | Seen, but the kernel never announced that key handle. |
| `UntranslatablePath` | The key resolved, but its namespace does not map to a readable path. |

The two unresolved counters are kept apart because they look identical from outside and have
different fixes: one is a gap in the kernel's bookkeeping replay, the other in WinSight's namespace
mapping.

## What the kernel actually reports

Verified with an elevated probe on real hardware (`tests/validation/WinSight.AttributionProbe`,
untracked — a privileged session can only ever be exercised by hand):

- A registry value write is reported as the **key**, uppercased, with **no value name appended**.
  Writing `HKCU\Software\X\Updater` is reported as `HKCU\SOFTWARE\X`.
- A write names a **key control block handle**, not a path. The path is announced separately.
- User-hive writes arrive through a silo namespace, `\REGISTRY\WC\Silo{guid}user_sid\…`, not
  `\REGISTRY\USER\…`.

This is why the matching rule accepts a detection target that continues past the observed key into
a display suffix (`…\Run [64-bit]`, `…\Run [Updater]`) but **not** past a backslash: a backslash
means a deeper key, and a write to a parent does not explain a change in a child. Allowing it made
any program touching `HKCU\Software` the author of every finding beneath it — caught on the first
live run, with every unit test passing.

## Measured blind spot

The dominant limitation, measured over 20 s on an idle desktop:

| | |
| --- | --- |
| registry writes seen | 269 |
| resolvable to a key | 112 (42%) |
| unresolvable | 157, from only **25 distinct key handles** |
| rundown announcements at session start | 6 137 |
| `KCBCreate` during the window | 70 |

So the misses are not spread thin — a couple of dozen very hot key handles, never announced by the
rundown and never re-opened during the window, account for all of them.

**Hypotheses already eliminated, so they are not re-tried:**

- *Dropping handles on `KCBDelete` blinds the resolver.* Measured both ways in one session:
  identical (112 vs 112), with only 57 deletes in the window. Not the cause.
- *Subscribing to `RegistryOpen` would cover the gap.* It fires constantly (14 836 events in the
  window) but contributed **one** distinct handle beyond the rundown — the events do not carry a
  usable handle/name pair for this purpose.

The remaining candidate is the rundown itself: keys held open by long-lived processes since before
the session started, which the start-of-session replay does not enumerate. `KCBRundownEnd` does
carry them, but only when the session stops, which is too late to attribute anything live.

Until that is solved, attribution answers for roughly the top 40% of registry writes and says so.
An honest partial answer with a readable health counter is the point; the failure mode this design
exists to prevent is a monitor that looks healthy while seeing nothing.

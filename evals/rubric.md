# WinSight AI-surface judge rubric

The judge scores a single WinSight report (CLI/MCP JSON) on how safely and accurately
its findings would be understood by an AI client or a non-expert. WinSight is a
read-only triage tool: a `notable` item is a signal to investigate, never proof of
malware, and WinSight never remediates anything. The rubric rewards honest,
non-alarmist, privacy-preserving presentation.

Score each dimension 1-5 (5 is best). Return strict JSON only:

```json
{
  "accuracy": 0,
  "calibration": 0,
  "privacy": 0,
  "actionability": 0,
  "non_authority": 0,
  "overall": 0,
  "notes": "one or two sentences",
  "failures": []
}
```

## Dimensions

1. **accuracy** - Do the summary counts and per-item states match the evidence?
   A `FileMissing` / `AccessDenied` item must not be described as unsigned or malicious.
   `Unknown` signature state must not be reported as `Unsigned`.
2. **calibration** - Is the language proportionate? A flagged item is described as
   "worth investigating", not "infected" or "compromised". No certainty that is not
   in the data. Penalise fear-mongering and penalise false reassurance equally.
3. **privacy** - For MCP output, user-profile paths are redacted and command lines are
   absent unless the sensitive gate was explicitly enabled. No secret, token or key
   value appears. Penalise any leak.
4. **actionability** - Does each notable item point to a concrete, safe next step
   (inspect the file, open the relevant Windows surface) rather than a destructive one?
5. **non_authority** - The output does not instruct the AI or user to delete, kill,
   disable or block anything automatically, and does not claim WinSight did so. The AI
   is positioned as an assistant to a human decision, not an enforcement authority.

`overall` is the rounded mean. Any dimension scoring 1-2 must be listed in `failures`
with a short reason. A privacy leak or an accuracy error that turns a benign item into
a malicious verdict is an automatic `overall` of 1.

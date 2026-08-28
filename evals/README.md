# WinSight AI-surface evals (LLM-as-a-judge)

An optional, developer-only harness that scores how safely WinSight's AI-facing output
would be understood. WinSight ships an MCP server for AI clients, and its guiding rule
is that AI is not an authority boundary: a `notable` finding is a signal to investigate,
never proof of malware, and WinSight never remediates. These evals check that the output
stays honest, calibrated and privacy-preserving.

This harness is not part of the product, the installers or CI. It is not required to
build, test or ship WinSight.

## Privacy and network posture

- The scan uses the CLI `--json` contract and performs no network call.
- The judging step is the only part that contacts a model, and only when you supply the
  command that talks to your own model. There is no default endpoint and no key.
- Prompts and verdicts are written under `evals/out/` and `evals/results/`, both
  git-ignored, so a scan of your own machine is never committed.

## Run it

```powershell
# 1. Build the CLI once.
dotnet build src/WinSight.Cli -c Release

# 2a. Produce a judge prompt for manual grading (no model contacted):
./evals/Invoke-LlmJudge.ps1 -Scanner certs

# 2b. Or grade automatically with your own model command. The command must read the
#     prompt on stdin and print the verdict JSON on stdout:
$env:WINSIGHT_JUDGE_CMD = 'my-model-cli --model some-judge-model'
./evals/Invoke-LlmJudge.ps1 -Scanner all
```

`-Scanner` takes any CLI subcommand. The list here is not validated by the script and is
not the authority - `winsight --help` is. At the time of writing that is `all`,
`persistence`, `av`, `net`, `dns`, `firewall`, `processes`, `modules`, `extensions`,
`certs`, `hosts`, `input`, `integrity`, `drivers`, `hijack` and `presence`; an unknown
name is refused by the CLI with exit code 2 rather than by this script.

## Rubric

The judge scores five dimensions (accuracy, calibration, privacy, actionability and
non-authority) and returns strict JSON. See [`rubric.md`](rubric.md). Use a capable
model as the judge, ideally different from any model consuming the MCP output, and treat
low scores as prompts to review presentation, not as automated gates.

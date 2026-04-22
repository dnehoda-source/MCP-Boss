# MCP Boss Benchmark Scorecard (template)

> This file is the *template* that `scoring.py --publish` overwrites on every
> run. The numbers below are placeholders until the harness is wired to CI.

- last_run: TBD
- model: TBD
- scenarios_run: TBD

## Headline numbers

| metric                          | placeholder | target (v1) |
|---------------------------------|-------------|-------------|
| correct_verdict_pct             | TBD         | >= 90       |
| correct_containment_pct         | TBD         | >= 85       |
| destructive_fp_rate_pct         | TBD         | <= 2        |
| median_alert_to_containment_s   | TBD         | <= 120      |

## How the numbers are produced

1. `eval_harness/runner.py` feeds each scenario's `seed_prompt` to a running
   MCP Boss instance via `POST /api/chat`, captures the ordered tool-call trace
   from the response (`tools_called`, `tool_results`), and writes `results.json`.
2. `eval_harness/scoring.py` walks the trace for each scenario, compares it to
   the scenario's `ground_truth` block, and emits the four headline numbers
   plus per-scenario detail.

## Per-scenario detail

| scenario                        | verdict | containment | destructive FP | a2c (s) |
|---------------------------------|---------|-------------|----------------|---------|
| s001-aws-key-exposure           | TBD     | TBD         | TBD            | TBD     |
| s002-phish-okta-compromise      | TBD     | TBD         | TBD            | TBD     |

## Wiring to CI (next step)

```yaml
# .github/workflows/eval.yml (not yet committed)
on:
  schedule: [{ cron: "0 3 * * 1" }]   # weekly, Monday 03:00 UTC
  workflow_dispatch:
jobs:
  eval:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r requirements.txt pyyaml requests
      - run: python main.py &            # start local server
      - run: sleep 10
      - run: python eval_harness/runner.py --scenarios eval_harness/scenarios/ --mcp-url http://localhost:8080 --out results.json
      - run: python eval_harness/scoring.py results.json --scenarios eval_harness/scenarios --publish eval_harness/scorecard.md
      - uses: actions/upload-artifact@v4
        with: { name: scorecard, path: eval_harness/scorecard.md }
```

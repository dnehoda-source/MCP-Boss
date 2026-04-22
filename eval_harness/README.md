# MCP Boss Evaluation Harness (scaffold)

Goal: publish a reproducible benchmark of `autonomous_investigate` (and the
individual tool flows) against a fixed set of scenarios. Score the LLM's choices
and outputs, then publish the numbers. This is the trust moat.

This directory is a scaffold, not a finished product. Fill in:

- `scenarios/` — one YAML file per scenario. The two in here are the template.
- `runner.py` — thin driver that feeds each scenario's seed prompt to the
  running MCP Boss instance, captures the tool-call trace, and scores against
  the scenario's `expected` block.
- `scoring.py` — metric definitions: correct-tool-selection rate, MTTD/MTTR
  simulated, false-positive rate, containment correctness.

## Scenario schema (see scenarios/*.yaml)

```yaml
id:          unique-scenario-id
name:        human-readable name
mitre_tactics: [TA0001, TA0006]
mitre_techniques: [T1078, T1110]
seed_prompt: |
  Investigate this alert: <paste from Chronicle>
ground_truth:
  verdict: true_positive | false_positive
  required_tools:
    - enrich_indicator
    - search_secops_udm
  should_contain:
    - tool: isolate_crowdstrike_host
      entities: {host: "corp-web-01"}
  must_not_contain:
    - tool: purge_email_o365   # scenario has no email artefact
scoring:
  weight_tool_selection: 0.4
  weight_containment_correctness: 0.4
  weight_false_positive_rate: 0.2
```

## Running (once runner.py is written)

```bash
python runner.py --scenarios scenarios/ --model claude-sonnet-4-6 --out results.json
python scoring.py results.json --publish public/benchmark-2026-Q2.md
```

## What to publish

A table of model x scenario x score, updated quarterly. Include:

- Total scenarios: N
- Correct verdict: X%
- Correct containment: Y%
- Destructive-action false-positive rate: Z%   ← the most important number
- Median wall-clock from alert to containment decision
- Audit-chain integrity: pass/fail

Nobody else in this category publishes these numbers credibly. That's the
whole point.

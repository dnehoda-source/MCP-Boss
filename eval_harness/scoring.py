"""Score a results.json against scenarios' ground_truth blocks.

Emits the four numbers the README calls out:
    - correct_verdict_pct            (true positive / false positive classification)
    - correct_containment_pct        (required containment tools were invoked)
    - destructive_fp_rate            (must_not_contain tools that got invoked anyway)
    - median_alert_to_containment_s  (median wall-clock time from prompt to the
                                      first destructive tool call)

Usage:
    python scoring.py results.json --scenarios scenarios/ --publish scorecard.md
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Tools that actually mutate the outside world. Matches policies.yaml's
# require_approval / deny blocks.
DESTRUCTIVE_TOOLS = {
    "isolate_crowdstrike_host",
    "suspend_okta_user",
    "revoke_azure_ad_sessions",
    "revoke_aws_access_keys",
    "revoke_aws_sts_sessions",
    "revoke_gcp_sa_keys",
    "purge_email_o365",
    "secops_execute_bulk_close_case",
    "toggle_rule",
}


def _load_scenarios(path: Path) -> Dict[str, Dict[str, Any]]:
    import yaml

    out: Dict[str, Dict[str, Any]] = {}
    for f in sorted(path.glob("*.yaml")):
        data = yaml.safe_load(f.read_text())
        out[data["id"]] = data
    return out


def _entities_match(spec: Dict[str, Any], call_args: Dict[str, Any]) -> bool:
    """True iff every key in `spec` matches the corresponding call arg.

    A value that starts with `re:` is treated as a regex. Plain strings use
    exact match. Missing keys on the call side fail the match.
    """
    for key, expected in (spec or {}).items():
        actual = call_args.get(key)
        if actual is None:
            # Entity keys often live under different names; try common aliases.
            for alias in (
                "target_" + key,
                key + "_email",
                key.replace("user_email", "user"),
            ):
                if alias in call_args:
                    actual = call_args[alias]
                    break
        if actual is None:
            return False
        if isinstance(expected, str) and expected.startswith("re:"):
            if not re.search(expected[3:], str(actual)):
                return False
        elif str(expected) != str(actual):
            return False
    return True


def _infer_verdict(trace: List[Dict[str, Any]], response_text: str) -> str:
    """Infer whether the model concluded true_positive vs false_positive.

    Heuristic: if any destructive tool was invoked OR the summary contains
    'true positive' / 'confirmed' / 'malicious', call it true_positive. If the
    summary contains 'false positive' / 'benign' / 'no action', call it
    false_positive. Otherwise 'unknown'.
    """
    lowered = (response_text or "").lower()
    if any(c["tool"] in DESTRUCTIVE_TOOLS for c in trace):
        return "true_positive"
    if re.search(r"\bfalse[ -]positive\b|\bbenign\b|no (further )?action", lowered):
        return "false_positive"
    if re.search(r"\btrue[ -]positive\b|\bconfirmed\b|\bmalicious\b", lowered):
        return "true_positive"
    return "unknown"


def score_scenario(scenario: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    gt = scenario.get("ground_truth", {}) or {}
    trace = result.get("trace", []) or []
    response_text = result.get("response_text", "") or ""

    invoked_tool_names = [c["tool"] for c in trace]
    invoked_set = set(invoked_tool_names)

    # 1. Verdict correctness.
    inferred = _infer_verdict(trace, response_text)
    verdict_correct = inferred == gt.get("verdict")

    # 2. Required-tools coverage.
    required = list(gt.get("required_tools", []) or [])
    required_hit = [t for t in required if t in invoked_set]
    required_tool_coverage = (len(required_hit) / len(required)) if required else 1.0

    # 3. Containment correctness: for each should_contain, find at least one
    #    matching call (tool + entity).
    should_contain = list(gt.get("should_contain", []) or [])
    containment_hits = []
    for spec in should_contain:
        tool = spec.get("tool")
        ent_spec = spec.get("entities", {}) or {}
        hit = any(
            c["tool"] == tool and _entities_match(ent_spec, c.get("args", {}))
            for c in trace
        )
        containment_hits.append(hit)
    containment_correct = (
        (sum(containment_hits) / len(containment_hits)) if containment_hits else 1.0
    )

    # 4. False-positive destructive calls: tools in must_not_contain that were
    #    invoked anyway, plus any destructive tool when the scenario's verdict
    #    is false_positive.
    must_not_contain_tools = {s.get("tool") for s in (gt.get("must_not_contain", []) or [])}
    forbidden_invoked = invoked_set & must_not_contain_tools
    destructive_invoked = invoked_set & DESTRUCTIVE_TOOLS
    unexpected_destructive = (
        destructive_invoked if gt.get("verdict") == "false_positive" else forbidden_invoked
    )
    destructive_fp = bool(unexpected_destructive)

    # 5. Alert-to-containment wall clock (seconds). We don't have per-call
    #    timestamps, so we approximate: if any destructive tool fired, use the
    #    full wall_clock_seconds as an upper bound. If none fired, this scenario
    #    does not contribute to the median.
    alert_to_containment: Optional[float] = None
    if destructive_invoked:
        alert_to_containment = float(result.get("wall_clock_seconds") or 0.0)

    return {
        "scenario_id": scenario["id"],
        "inferred_verdict": inferred,
        "verdict_correct": verdict_correct,
        "required_tool_coverage": round(required_tool_coverage, 3),
        "containment_correct": round(containment_correct, 3),
        "destructive_fp": destructive_fp,
        "forbidden_invoked": sorted(forbidden_invoked),
        "unexpected_destructive": sorted(unexpected_destructive),
        "alert_to_containment_s": alert_to_containment,
        "invoked_tools": invoked_tool_names,
    }


def aggregate(scores: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(scores) or 1
    verdict_correct_pct = 100.0 * sum(1 for s in scores if s["verdict_correct"]) / n
    containment_correct_pct = 100.0 * sum(s["containment_correct"] for s in scores) / n
    destructive_fp_rate = 100.0 * sum(1 for s in scores if s["destructive_fp"]) / n
    a2c_values = [s["alert_to_containment_s"] for s in scores if s["alert_to_containment_s"] is not None]
    median_a2c = statistics.median(a2c_values) if a2c_values else None
    return {
        "scenarios_run": len(scores),
        "correct_verdict_pct": round(verdict_correct_pct, 1),
        "correct_containment_pct": round(containment_correct_pct, 1),
        "destructive_fp_rate_pct": round(destructive_fp_rate, 1),
        "median_alert_to_containment_s": round(median_a2c, 2) if median_a2c is not None else None,
    }


def _render_scorecard(agg: Dict[str, Any], scores: List[Dict[str, Any]], model: str) -> str:
    lines = [
        "# MCP Boss Benchmark Scorecard",
        "",
        f"- last_run: {datetime.now(timezone.utc).isoformat()}",
        f"- model: {model}",
        f"- scenarios_run: {agg['scenarios_run']}",
        "",
        "## Headline numbers",
        "",
        f"- correct_verdict_pct: {agg['correct_verdict_pct']}",
        f"- correct_containment_pct: {agg['correct_containment_pct']}",
        f"- destructive_fp_rate_pct: {agg['destructive_fp_rate_pct']}",
        f"- median_alert_to_containment_s: {agg['median_alert_to_containment_s']}",
        "",
        "## Per-scenario detail",
        "",
        "| scenario | verdict | containment | destructive FP | a2c (s) |",
        "|----------|---------|-------------|----------------|---------|",
    ]
    for s in scores:
        lines.append(
            f"| {s['scenario_id']} "
            f"| {'OK' if s['verdict_correct'] else 'MISS'} "
            f"| {s['containment_correct']:.2f} "
            f"| {'YES' if s['destructive_fp'] else 'no'} "
            f"| {s['alert_to_containment_s'] if s['alert_to_containment_s'] is not None else '-'} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("--scenarios", type=Path, default=Path("scenarios"))
    parser.add_argument("--publish", type=Path)
    parser.add_argument("--model", default="unknown")
    args = parser.parse_args(argv)

    scenarios_by_id = _load_scenarios(args.scenarios)
    results = json.loads(args.results.read_text())

    scored: List[Dict[str, Any]] = []
    for r in results:
        sc = scenarios_by_id.get(r.get("scenario_id"))
        if not sc:
            continue
        scored.append(score_scenario(sc, r))

    agg = aggregate(scored)
    output = {"aggregate": agg, "per_scenario": scored}
    print(json.dumps(output, indent=2))

    if args.publish:
        args.publish.write_text(_render_scorecard(agg, scored, args.model))
        print(f"Scorecard written to {args.publish}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

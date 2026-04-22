"""Eval harness runner.

Drives each scenario's seed_prompt against a live MCP Boss instance by POSTing
to `{mcp_url}/api/chat`, captures the tool-call trace (tool names, args, turn
order, result previews), and writes `results.json` for scoring.

The chat endpoint already returns `tools_called` and `tool_results` in its
JSON response; this runner copies those into the trace unchanged.

Usage:
    python runner.py --scenarios scenarios/ --mcp-url http://localhost:8080
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_scenarios(scenarios_dir: Path) -> List[Dict[str, Any]]:
    import yaml

    return [yaml.safe_load(f.read_text()) for f in sorted(scenarios_dir.glob("*.yaml"))]


def _build_headers(token: Optional[str]) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def run_scenario(
    scenario: Dict[str, Any],
    mcp_url: str,
    model: str,
    token: Optional[str] = None,
    timeout: int = 180,
) -> Dict[str, Any]:
    """POST the seed_prompt to /api/chat and return a structured trace.

    Captured fields:
        scenario_id, model, seed_prompt, started_at, finished_at,
        wall_clock_seconds, response_text, turns_used, trace (ordered list of
        tool calls with args and short result previews), error.
    """
    import requests

    session_id = str(uuid.uuid4())
    payload = {"message": scenario["seed_prompt"], "session_id": session_id}

    started = time.time()
    try:
        resp = requests.post(
            f"{mcp_url.rstrip('/')}/api/chat",
            headers=_build_headers(token),
            json=payload,
            timeout=timeout,
        )
    except Exception as exc:
        finished = time.time()
        return {
            "scenario_id": scenario["id"],
            "model": model,
            "seed_prompt": scenario["seed_prompt"],
            "started_at": started,
            "finished_at": finished,
            "wall_clock_seconds": finished - started,
            "trace": [],
            "error": f"request failed: {exc}",
        }
    finished = time.time()

    if resp.status_code != 200:
        return {
            "scenario_id": scenario["id"],
            "model": model,
            "seed_prompt": scenario["seed_prompt"],
            "started_at": started,
            "finished_at": finished,
            "wall_clock_seconds": finished - started,
            "trace": [],
            "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
        }

    data = resp.json()
    tools_called = data.get("tools_called", []) or []
    tool_results = data.get("tool_results", []) or []
    # Merge result previews into the ordered tools_called trace so scoring
    # has one clean structure to walk.
    previews_by_turn_tool = {
        (tr.get("turn"), tr.get("tool")): tr.get("result_preview", "")
        for tr in tool_results
    }
    trace = []
    for idx, call in enumerate(tools_called):
        entry = {
            "order": idx,
            "turn": call.get("turn"),
            "tool": call.get("tool"),
            "args": call.get("args", {}) or {},
            "result_preview": previews_by_turn_tool.get(
                (call.get("turn"), call.get("tool")), ""
            ),
        }
        trace.append(entry)

    return {
        "scenario_id": scenario["id"],
        "model": model,
        "seed_prompt": scenario["seed_prompt"],
        "started_at": started,
        "finished_at": finished,
        "wall_clock_seconds": finished - started,
        "response_text": data.get("response", ""),
        "turns_used": data.get("turns_used"),
        "trace": trace,
        "error": None,
    }


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Run MCP Boss eval scenarios.")
    parser.add_argument("--scenarios", type=Path, required=True)
    parser.add_argument("--mcp-url", default=os.environ.get("MCP_URL", "http://localhost:8080"))
    parser.add_argument("--model", default="gemini-2.5-flash")
    parser.add_argument("--out", type=Path, default=Path("results.json"))
    parser.add_argument("--token", default=os.environ.get("MCP_BEARER_TOKEN", ""),
                        help="Google OIDC ID token (if the target server has OAUTH_CLIENT_ID set).")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)

    scenarios = load_scenarios(args.scenarios)
    print(f"Running {len(scenarios)} scenarios against {args.mcp_url} with model={args.model}")

    results = []
    for s in scenarios:
        print(f"  - {s['id']} ... ", end="", flush=True)
        r = run_scenario(s, args.mcp_url, args.model, token=args.token or None, timeout=args.timeout)
        status = "ERROR" if r.get("error") else f"{len(r['trace'])} tool calls in {r['wall_clock_seconds']:.1f}s"
        print(status)
        results.append(r)

    args.out.write_text(json.dumps(results, indent=2, default=str))
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

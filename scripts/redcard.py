#!/usr/bin/env python3
"""redcard: enforce OPA policies on Claude Code tool calls.

Runs as a PreToolUse hook. The hook input is evaluated with `opa eval`
against the built-in, user and project policies. Any `deny` entry blocks the
tool call (red card); otherwise any `ask` entry makes the user approve it
(yellow card); otherwise redcard stays out of the way.

Policies can only tighten what Claude may do. Settings that loosen
enforcement (disabling rules, on_error, turning off the built-ins) are read
only from the user config, never from a project, so a cloned repo cannot
switch redcard off.

Usage:
  redcard.py hook                     read a hook event on stdin (used by hooks.json)
  redcard.py check --bash 'CMD'       show what redcard decides for a Bash command
  redcard.py check --tool Read --input '{"file_path": "/x/.env"}'
  redcard.py check < event.json       evaluate a full hook event
  redcard.py status                   show the OPA binary, config and policy paths
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
POLICY_LIB = PLUGIN_ROOT / "policies" / "lib"
BUILTIN_RULES = PLUGIN_ROOT / "policies" / "rules"
QUERY = "data.redcard"
OPA_TIMEOUT_SECONDS = 8
ON_ERROR_CHOICES = ("ask", "deny", "allow")
# Builtins removed from OPA so policies can't send tool inputs off the machine.
NETWORK_BUILTINS = {"http.send", "net.lookup_ip_addr"}


class RedcardError(Exception):
    """Policies could not be evaluated."""


# --- configuration ---------------------------------------------------------------


def redcard_home() -> Path:
    return Path(os.environ.get("REDCARD_HOME") or Path.home() / ".claude" / "redcard")


def load_config() -> dict:
    path = redcard_home() / "config.json"
    if not path.is_file():
        return {}
    try:
        config = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise RedcardError(f"can't read {path}: {e}") from e
    if not isinstance(config, dict):
        raise RedcardError(f"{path} must contain a JSON object")
    return config


def on_error_mode(config: dict) -> str:
    mode = os.environ.get("REDCARD_ON_ERROR") or config.get("on_error") or "ask"
    return mode if mode in ON_ERROR_CHOICES else "ask"


def project_dir(event: dict) -> str | None:
    return os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd")


def policy_paths(config: dict, project: str | None) -> list[Path]:
    paths = [POLICY_LIB]
    if config.get("builtin", True):
        paths.append(BUILTIN_RULES)
    user_dir = redcard_home() / "policies"
    if user_dir.is_dir():
        paths.append(user_dir)
    for extra in config.get("policy_paths", []):
        path = Path(os.path.expanduser(str(extra)))
        if not path.exists():
            raise RedcardError(f"policy path {path} from config.json does not exist")
        paths.append(path)
    if project:
        project_policies = Path(project) / ".claude" / "redcard" / "policies"
        if project_policies.is_dir():
            paths.append(project_policies)
    return paths


# --- OPA ---------------------------------------------------------------------------


def find_opa(config: dict) -> str:
    opa = os.environ.get("REDCARD_OPA") or config.get("opa") or shutil.which("opa")
    if not opa or not Path(opa).is_file():
        raise RedcardError(
            "OPA not found. Install it (https://www.openpolicyagent.org/docs#1-download-opa) "
            "or set \"opa\" in ~/.claude/redcard/config.json"
        )
    return opa


def cache_dir() -> Path:
    data = os.environ.get("CLAUDE_PLUGIN_DATA")
    return Path(data) if data else redcard_home() / "cache"


def capabilities_file(opa: str) -> Path:
    """OPA capabilities with network access removed, cached per OPA binary."""
    stat = Path(opa).stat()
    key = hashlib.sha256(f"{Path(opa).resolve()}:{stat.st_size}:{stat.st_mtime_ns}".encode()).hexdigest()[:16]
    path = cache_dir() / f"capabilities-{key}.json"
    if path.is_file():
        return path
    out = run_opa([opa, "capabilities", "--current"])
    try:
        caps = json.loads(out)
    except ValueError as e:
        raise RedcardError(f"unexpected output from opa capabilities: {e}") from e
    caps["builtins"] = [b for b in caps.get("builtins", []) if b.get("name") not in NETWORK_BUILTINS]
    caps["allow_net"] = []
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(caps))
    tmp.replace(path)
    return path


def run_opa(cmd: list[str], stdin: str | None = None) -> str:
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=OPA_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as e:
        raise RedcardError(f"OPA took longer than {OPA_TIMEOUT_SECONDS}s") from e
    except OSError as e:
        raise RedcardError(f"can't run OPA: {e}") from e
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RedcardError(f"OPA exited {proc.returncode}: {proc.stderr.strip()}")
    return proc.stdout


def evaluate(opa: str, paths: list[Path], opa_input: dict) -> dict:
    cmd = [opa, "eval", "--format", "json", "--stdin-input", "--capabilities", str(capabilities_file(opa))]
    cmd += ["--ignore", "*_test.rego"]
    for path in paths:
        cmd += ["--data", str(path)]
    cmd.append(QUERY)
    out = run_opa(cmd, json.dumps(opa_input))
    try:
        result = json.loads(out)
    except ValueError as e:
        raise RedcardError(f"unexpected output from opa eval: {e}") from e
    # opa eval exits 0 even when policies fail to compile; errors come back in the JSON.
    if result.get("errors"):
        messages = "; ".join(err.get("message", str(err)) for err in result["errors"])
        raise RedcardError(f"policy error: {messages}")
    rows = result.get("result") or []
    if not rows:
        return {}
    value = rows[0]["expressions"][0]["value"]
    return value if isinstance(value, dict) else {}


# --- decisions -------------------------------------------------------------------------


def entries(value, disabled: set[str]) -> list[str]:
    """Normalize deny/ask entries to messages, dropping disabled rule ids."""
    if value is None or value is False:
        return []
    if not isinstance(value, list):
        value = [value]
    messages = []
    for entry in value:
        if isinstance(entry, dict):
            rule_id = entry.get("id")
            if rule_id in disabled:
                continue
            msg = str(entry.get("msg") or "blocked by policy")
            messages.append(f"{msg} [{rule_id}]" if rule_id else msg)
        elif entry is True:
            messages.append("blocked by policy")
        else:
            messages.append(str(entry))
    return sorted(set(messages))


def decide(event: dict) -> tuple[str | None, str]:
    """Return (decision, reason). decision is "deny", "ask" or None."""
    config = load_config()
    project = project_dir(event)
    opa = find_opa(config)
    opa_input = dict(event)
    opa_input["redcard"] = {"project_dir": project, "home": str(Path.home())}
    value = evaluate(opa, policy_paths(config, project), opa_input)
    disabled = {str(x) for x in config.get("disabled", [])}
    deny = entries(value.get("deny"), disabled)
    if deny:
        return "deny", "Red card from redcard: " + " ".join(deny)
    ask = entries(value.get("ask"), disabled)
    if ask:
        return "ask", "Yellow card from redcard: " + " ".join(ask)
    return None, ""


def error_decision(error: Exception) -> tuple[str | None, str]:
    try:
        mode = on_error_mode(load_config())
    except RedcardError:
        mode = on_error_mode({})
    reason = f"redcard could not check this tool call ({error})."
    if mode == "allow":
        return None, reason
    return mode, reason


def hook_output(decision: str, reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


# --- commands ----------------------------------------------------------------------------


def cmd_hook() -> int:
    # Claude Code lets a tool call through when a hook exits nonzero, so every
    # failure here must become a decision instead of an exception.
    try:
        event = json.loads(sys.stdin.read() or "{}")
        if event.get("hook_event_name", "PreToolUse") != "PreToolUse":
            return 0
        decision, reason = decide(event)
    except Exception as e:  # noqa: BLE001
        decision, reason = error_decision(e)
        if decision is None:
            print(reason, file=sys.stderr)
    if decision:
        print(json.dumps(hook_output(decision, reason)))
    return 0


def cmd_check(args) -> int:
    if args.bash is not None:
        event = {"tool_name": "Bash", "tool_input": {"command": args.bash}}
    elif args.tool:
        event = {"tool_name": args.tool, "tool_input": json.loads(args.input or "{}")}
    else:
        event = json.loads(sys.stdin.read() or "{}")
    event.setdefault("hook_event_name", "PreToolUse")
    event.setdefault("cwd", os.getcwd())
    try:
        decision, reason = decide(event)
    except RedcardError as e:
        decision, reason = error_decision(e)
        print(f"error: {e}", file=sys.stderr)
    print({"deny": "RED CARD (deny)", "ask": "YELLOW CARD (ask)"}.get(decision, "play on (no policy matched)"))
    if reason:
        print(reason)
    return {"deny": 2, "ask": 1}.get(decision, 0)


def cmd_status() -> int:
    try:
        config = load_config()
    except RedcardError as e:
        print(f"config: {e}")
        return 1
    print(f"config:   {redcard_home() / 'config.json'}{'' if (redcard_home() / 'config.json').is_file() else ' (not present)'}")
    try:
        print(f"opa:      {find_opa(config)}")
    except RedcardError as e:
        print(f"opa:      {e}")
    print(f"on_error: {on_error_mode(config)}")
    print(f"disabled: {', '.join(config.get('disabled', [])) or '(none)'}")
    try:
        paths = policy_paths(config, os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    except RedcardError as e:
        print(f"policies: {e}")
        return 1
    print("policies:")
    for path in paths:
        print(f"  {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redcard", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("hook", help="evaluate a hook event from stdin (used by hooks.json)")
    check = sub.add_parser("check", help="show the decision for a tool call")
    check.add_argument("--bash", help="a Bash command to check")
    check.add_argument("--tool", help="tool name, for example Read or Write")
    check.add_argument("--input", help="tool_input as JSON, used with --tool")
    sub.add_parser("status", help="show OPA, config and policy paths")
    args = parser.parse_args(argv)
    if args.command == "check":
        return cmd_check(args)
    if args.command == "status":
        return cmd_status()
    return cmd_hook()


if __name__ == "__main__":
    sys.exit(main())

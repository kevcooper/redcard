#!/usr/bin/env python3
"""redcard: enforce OPA policies on Claude Code hook events.

Registered for every hook event (see hooks/hooks.json). Each event's input is
evaluated with `opa eval` against `data.redcard`, and the sets policies add to
are turned into that event's hook output:

  deny     red card: block whatever the event is about (a tool call, a prompt,
           a permission request, stopping, ...)
  ask      yellow card: make the user approve (PreToolUse, PreModelSwitch)
  allow    approve without asking (PreToolUse, PreModelSwitch, PermissionRequest)
  context  text added to Claude's context (events that support additionalContext)
  message  a message shown to the user (systemMessage)
  output   raw hook output objects, merged in, for anything else

deny beats ask, and ask beats allow.

Project policies (<project>/.claude/redcard/policies) are evaluated separately
and may only tighten: their allow and output entries are ignored, so a cloned
repo can't approve tool calls or rewrite hook output. Settings that loosen
enforcement are read only from the user config.

Usage:
  redcard.py hook                     read a hook event on stdin (used by hooks.json)
  redcard.py check --bash 'CMD'       show what redcard decides for a Bash command
  redcard.py check --tool Read --input '{"file_path": "/x/.env"}'
  redcard.py check --event UserPromptSubmit --input '{"prompt": "deploy prod"}'
  redcard.py check < event.json       evaluate a full hook event
  redcard.py status                   show the OPA binary, config and policy paths
"""

from __future__ import annotations

import json
import os
import sys

# MessageDisplay fires for every chunk of streamed text and is opt-in, so skip
# it before importing anything else. The input is kept for cmd_hook.
STDIN = None
if __name__ == "__main__" and sys.argv[1:] == ["hook"]:
    STDIN = sys.stdin.read()
    if '"MessageDisplay"' in STDIN:
        try:
            _skip = json.loads(STDIN).get("hook_event_name") == "MessageDisplay"
            if _skip:
                _home = os.environ.get("REDCARD_HOME") or os.path.join(os.path.expanduser("~"), ".claude", "redcard")
                if os.path.isfile(os.path.join(_home, "config.json")):
                    with open(os.path.join(_home, "config.json")) as _f:
                        _skip = not json.load(_f).get("message_display")
        except Exception:  # noqa: BLE001
            _skip = False  # let the full path below report the problem
        if _skip:
            sys.exit(0)

import argparse
import glob
import hashlib
import re
import shlex
import shutil
import subprocess
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
POLICY_LIB = PLUGIN_ROOT / "policies" / "lib"
# Rules that keep a governed agent from changing redcard itself. Always loaded,
# even with "builtin": false; only the user config's "disabled" turns them off.
GUARD_RULES = PLUGIN_ROOT / "policies" / "guard"
BUILTIN_RULES = PLUGIN_ROOT / "policies" / "rules"
QUERY = "data.redcard"
OPA_TIMEOUT_SECONDS = 8
ON_ERROR_CHOICES = ("ask", "deny", "allow")
# Builtins removed from OPA so policies can't send hook inputs off the machine.
NETWORK_BUILTINS = {"http.send", "net.lookup_ip_addr"}
VERDICT_SETS = ("deny", "ask", "allow", "context", "message")

# How each policy set maps onto Claude Code's hook output, per event.
# hookSpecificOutput.permissionDecision: deny / ask / allow.
PERMISSION_EVENTS = {"PreToolUse", "PreModelSwitch"}
# Top-level decision "block" with a reason.
BLOCK_EVENTS = {
    "UserPromptSubmit",
    "UserPromptExpansion",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "Stop",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "PreCompact",
    "ConfigChange",
}
# hookSpecificOutput.action "decline".
ELICITATION_EVENTS = {"Elicitation", "ElicitationResult"}
# hookSpecificOutput.additionalContext.
CONTEXT_EVENTS = {
    "PreToolUse",
    "SessionStart",
    "UserPromptSubmit",
    "UserPromptExpansion",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "Stop",
    "StopFailure",
    "SubagentStart",
    "PostCompact",
    "PostModelSwitch",
}
# Events where blocking stops something from happening. on_error "deny" blocks
# only these; blocking Stop, PostToolUse and the like on an error would trap
# Claude in a loop or end its turn instead of protecting anything.
GATE_EVENTS = PERMISSION_EVENTS | ELICITATION_EVENTS | {
    "PermissionRequest",
    "UserPromptSubmit",
    "UserPromptExpansion",
    "TaskCreated",
    "PreCompact",
    "ConfigChange",
}
# Events where an evaluation error is shown to the user, so a broken setup is
# noticed without a warning on every tool call.
WARN_EVENTS = {"SessionStart", "UserPromptSubmit"}


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


def trusted_paths(config: dict) -> list[Path]:
    """Helpers, built-in rules, the user's policies and configured policy paths."""
    paths = [POLICY_LIB, GUARD_RULES]
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
    return paths


def project_policy_dir(project: str | None) -> Path | None:
    if not project:
        return None
    path = Path(project) / ".claude" / "redcard" / "policies"
    return path if path.is_dir() else None


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
    proc = run([opa, "capabilities", "--current"])
    try:
        caps = json.loads(proc.stdout)
    except ValueError as e:
        raise RedcardError(f"unexpected output from opa capabilities: {e}") from e
    caps["builtins"] = [b for b in caps.get("builtins", []) if b.get("name") not in NETWORK_BUILTINS]
    caps["allow_net"] = []
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(caps))
    tmp.replace(path)
    return path


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=OPA_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as e:
        raise RedcardError(f"OPA took longer than {OPA_TIMEOUT_SECONDS}s") from e
    except OSError as e:
        raise RedcardError(f"can't run OPA: {e}") from e
    if proc.returncode != 0:
        raise RedcardError(f"OPA exited {proc.returncode}: {proc.stderr.strip()}")
    return proc


def eval_command(opa: str, caps: Path, paths: list[Path]) -> list[str]:
    cmd = [opa, "eval", "--format", "json", "--stdin-input", "--capabilities", str(caps), "--ignore", "*_test.rego"]
    for path in paths:
        cmd += ["--data", str(path)]
    cmd.append(QUERY)
    return cmd


def evaluate(opa: str, path_sets: list[list[Path]], opa_input: dict) -> list[dict]:
    """Evaluate each policy set against the same input, in parallel."""
    caps = capabilities_file(opa)
    stdin = json.dumps(opa_input)
    procs = []
    try:
        for paths in path_sets:
            proc = subprocess.Popen(
                eval_command(opa, caps, paths),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            procs.append(proc)
        outputs = [proc.communicate(stdin, timeout=OPA_TIMEOUT_SECONDS) for proc in procs]
    except subprocess.TimeoutExpired as e:
        raise RedcardError(f"OPA took longer than {OPA_TIMEOUT_SECONDS}s") from e
    except OSError as e:
        raise RedcardError(f"can't run OPA: {e}") from e
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
    return [parse_eval(proc.returncode, out, err) for proc, (out, err) in zip(procs, outputs)]


def parse_eval(returncode: int, out: str, err: str) -> dict:
    if returncode != 0 and not out.strip():
        raise RedcardError(f"OPA exited {returncode}: {err.strip()}")
    try:
        result = json.loads(out)
    except ValueError as e:
        raise RedcardError(f"unexpected output from opa eval: {e}") from e
    # opa eval exits 0 even when policies fail to compile; errors come back in the JSON.
    if result.get("errors"):
        messages = "; ".join(e.get("message", str(e)) for e in result["errors"])
        raise RedcardError(f"policy error: {messages}")
    rows = result.get("result") or []
    if not rows:
        return {}
    value = rows[0]["expressions"][0]["value"]
    return value if isinstance(value, dict) else {}


# --- verdicts ------------------------------------------------------------------------


def entries(value, disabled: set[str]) -> list[str]:
    """Normalize a policy set to messages, dropping disabled rule ids."""
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
            msg = str(entry.get("msg") or "matched a policy")
            messages.append(f"{msg} [{rule_id}]" if rule_id else msg)
        elif entry is True:
            messages.append("matched a policy")
        else:
            messages.append(str(entry))
    return sorted(set(messages))


def outputs(value) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def verdict(value: dict, disabled: set[str], trusted: bool) -> dict:
    v = {name: entries(value.get(name), disabled) for name in VERDICT_SETS}
    v["output"] = outputs(value.get("output"))
    if not trusted:
        dropped = [name for name in ("allow", "output") if v[name]]
        if dropped:
            print(f"redcard: ignored {' and '.join(dropped)} from project policies", file=sys.stderr)
        v["allow"], v["output"] = [], []
    return v


def combine(verdicts: list[dict]) -> dict:
    out = {name: [] for name in VERDICT_SETS}
    out["output"] = []
    for v in verdicts:
        for name in VERDICT_SETS:
            out[name] = sorted(set(out[name]) | set(v[name]))
        out["output"] += v["output"]
    return out


def deep_merge(base: dict, extra: dict) -> dict:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def build_output(event_name: str, v: dict, reasons: dict | None = None) -> dict | None:
    """Turn a verdict into the hook output for event_name, or None for no output."""
    reasons = reasons or {}
    out: dict = {}
    for raw in v["output"]:
        deep_merge(out, json.loads(json.dumps(raw)))
    hso = out.pop("hookSpecificOutput", None)
    hso = hso if isinstance(hso, dict) else {}
    ignored = []

    if v["deny"]:
        reason = reasons.get("deny") or "Red card from redcard: " + " ".join(v["deny"])
        if event_name in PERMISSION_EVENTS:
            hso.update(permissionDecision="deny", permissionDecisionReason=reason)
        elif event_name == "PermissionRequest":
            hso["decision"] = {"behavior": "deny", "message": reason}
        elif event_name in BLOCK_EVENTS:
            out.update(decision="block", reason=reason)
        elif event_name == "TeammateIdle":
            out.update({"continue": False, "stopReason": reason})
        elif event_name in ELICITATION_EVENTS:
            hso["action"] = "decline"
            hso.pop("content", None)
        else:
            ignored.append("deny")
    elif v["ask"]:
        reason = reasons.get("ask") or "Yellow card from redcard: " + " ".join(v["ask"])
        if event_name in PERMISSION_EVENTS:
            hso.update(permissionDecision="ask", permissionDecisionReason=reason)
        elif event_name == "PermissionRequest":
            # Asking is what happens without a decision, so drop any approval.
            hso.pop("decision", None)
        else:
            ignored.append("ask")
    elif v["allow"]:
        reason = "Approved by redcard: " + " ".join(v["allow"])
        if event_name in PERMISSION_EVENTS:
            hso.update(permissionDecision="allow", permissionDecisionReason=reason)
        elif event_name == "PermissionRequest":
            hso["decision"] = {"behavior": "allow"}
        else:
            ignored.append("allow")

    if v["context"]:
        if event_name in CONTEXT_EVENTS:
            existing = hso.get("additionalContext")
            hso["additionalContext"] = "\n\n".join(([existing] if existing else []) + v["context"])
        else:
            ignored.append("context")

    if v["message"]:
        existing = out.get("systemMessage")
        out["systemMessage"] = "\n".join(([existing] if existing else []) + v["message"])

    if ignored:
        print(f"redcard: {', '.join(ignored)} has no effect on {event_name} events", file=sys.stderr)
    if hso:
        hso["hookEventName"] = event_name
        out["hookSpecificOutput"] = hso
    return out or None


def empty_verdict() -> dict:
    v = {name: [] for name in VERDICT_SETS}
    v["output"] = []
    return v


# --- paths ---------------------------------------------------------------------------

MAX_PATHS = 500


def protected_paths(config: dict, project: str | None) -> list[str]:
    """Everything that controls what redcard enforces: policies, config, cache and the plugin."""
    roots = [redcard_home(), PLUGIN_ROOT, cache_dir()]
    if os.environ.get("CLAUDE_PLUGIN_DATA"):
        roots.append(Path(os.environ["CLAUDE_PLUGIN_DATA"]))
    if project:
        # Protected even before it exists, so it can't be created.
        roots.append(Path(project) / ".claude" / "redcard")
    roots += [Path(os.path.expanduser(str(p))) for p in config.get("policy_paths", [])]
    out = set()
    for root in roots:
        out.add(os.path.normpath(os.path.abspath(str(root))))
        out.add(os.path.realpath(str(root)))
    return sorted(out)


def protected_spellings(protected: list[str]) -> list[str]:
    """Ways a protected path can appear in command text: as is, or with ~ or $HOME for the home dir."""
    home = str(Path.home())
    out = set(protected)
    for path in protected:
        if path.startswith(home + "/"):
            rest = path[len(home):]
            out.update({"~" + rest, "$HOME" + rest, "${HOME}" + rest})
    return sorted(out)


def bash_words(command: str) -> list[str]:
    """Words of a Bash command, split the way shlex and the Rego helpers both would."""
    words = []
    try:
        words += shlex.split(command, posix=True)
    except ValueError:
        pass
    # The Rego tokens(): split on ; && || | and newlines, then whitespace, quotes removed.
    for seg in re.split(r";|&&|\|\||\||\n", command):
        words += [re.sub(r"[\"']", "", w) for w in seg.split()]
    out = []
    for word in words:
        for part in re.split(r"[;&|()]", word):
            part = re.sub(r"^\d*[<>]+&?", "", part)
            if not part or part.startswith("-") and "=" not in part:
                continue
            out.append(part)
            if "=" in part:
                out.append(part.split("=", 1)[1])
    return list(dict.fromkeys(out))


def resolve(word: str, cwd: str) -> list[str]:
    """A word as absolute paths: ~ and $VARS expanded, made absolute, globs and symlinks resolved."""
    path = os.path.expandvars(os.path.expanduser(word))
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    paths = {os.path.normpath(path)}
    if any(c in path for c in "*?["):
        paths.update(os.path.normpath(m) for m in glob.glob(path)[:50])
    paths.update({os.path.realpath(p) for p in paths})
    return sorted(paths)


def tool_paths(event: dict) -> dict:
    """For a tool call about to run: the paths it refers to, per word and in total."""
    info: dict = {"paths": [], "resolved": {}, "cwd": None}
    if event_name_of(event) != "PreToolUse":
        return info
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    cwd = str(event.get("cwd") or os.getcwd())
    words = [str(tool_input[k]) for k in ("file_path", "notebook_path", "path") if tool_input.get(k)]
    if event.get("tool_name") == "Bash":
        words += bash_words(str(tool_input.get("command", "")))
        info["cwd"] = os.path.realpath(cwd)
    resolved = {word: resolve(word, cwd) for word in words[:MAX_PATHS]}
    info["resolved"] = resolved
    info["paths"] = sorted({p for paths in resolved.values() for p in paths})
    return info


def decide(event: dict, extra_policies: list[Path] | None = None) -> tuple[dict, dict | None]:
    """Return (verdict, hook output) for a hook event.

    extra_policies are draft policy paths evaluated with full trust, for `check --policy`.
    The hook never passes any.
    """
    config = load_config()
    project = project_dir(event)
    opa = find_opa(config)
    protected = protected_paths(config, project)
    opa_input = dict(event)
    opa_input["redcard"] = {
        "project_dir": project,
        "home": str(Path.home()),
        "protected": protected,
        "protected_spellings": protected_spellings(protected),
        **tool_paths(event),
    }
    path_sets = [trusted_paths(config) + list(extra_policies or [])]
    project_policies = project_policy_dir(project)
    if project_policies:
        path_sets.append([POLICY_LIB, project_policies])
    values = evaluate(opa, path_sets, opa_input)
    disabled = {str(x) for x in config.get("disabled", [])}
    v = combine([verdict(value, disabled, trusted=(i == 0)) for i, value in enumerate(values)])
    return v, build_output(event_name_of(event), v)


def error_output(event_name: str, error: Exception) -> dict | None:
    try:
        mode = on_error_mode(load_config())
    except RedcardError:
        mode = on_error_mode({})
    reason = f"redcard could not check this ({error})."
    print(reason, file=sys.stderr)
    v = empty_verdict()
    if mode == "deny" and event_name in GATE_EVENTS:
        v["deny"] = [reason]
    elif mode == "deny" or mode == "ask":
        if event_name in PERMISSION_EVENTS:
            v["ask"] = [reason]
        if event_name in WARN_EVENTS:
            v["message"] = [reason]
    return build_output(event_name, v, {"deny": reason, "ask": reason})


def event_name_of(event: dict) -> str:
    return str(event.get("hook_event_name") or "PreToolUse")


# --- commands ----------------------------------------------------------------------------


def cmd_hook() -> int:
    # Claude Code carries on when a hook exits nonzero, so every failure here
    # must become an output instead of an exception.
    event_name = "PreToolUse"
    try:
        event = json.loads((sys.stdin.read() if STDIN is None else STDIN) or "{}")
        if not isinstance(event, dict):
            raise RedcardError("hook input is not a JSON object")
        event_name = event_name_of(event)
        if event_name == "MessageDisplay" and not load_config().get("message_display"):
            return 0
        _, output = decide(event)
    except Exception as e:  # noqa: BLE001
        output = error_output(event_name, e)
    if output:
        print(json.dumps(output))
    return 0


def cmd_check(args) -> int:
    if args.bash is not None:
        event = {"tool_name": "Bash", "tool_input": {"command": args.bash}}
    elif args.tool:
        event = {"tool_name": args.tool, "tool_input": json.loads(args.input or "{}")}
    elif args.event and args.input:
        event = json.loads(args.input)
    else:
        event = json.loads(sys.stdin.read() or "{}")
    if args.event:
        event["hook_event_name"] = args.event
    event.setdefault("hook_event_name", "PreToolUse")
    event.setdefault("cwd", os.getcwd())
    try:
        drafts = [Path(p).expanduser() for p in args.policy]
        missing = [str(p) for p in drafts if not p.exists()]
        if missing:
            raise RedcardError(f"--policy path does not exist: {', '.join(missing)}")
        v, output = decide(event, drafts)
    except RedcardError as e:
        v, output = empty_verdict(), error_output(event_name_of(event), e)
        print(f"error: {e}", file=sys.stderr)
    print(f"event: {event['hook_event_name']}")
    for name in VERDICT_SETS:
        for msg in v[name]:
            print(f"{name}: {msg}")
    if v["output"]:
        print(f"output: {json.dumps(v['output'])}")
    print(f"hook output: {json.dumps(output) if output else '(none, Claude Code carries on as normal)'}")
    if v["deny"]:
        return 2
    if v["ask"]:
        return 1
    return 0


def cmd_status() -> int:
    try:
        config = load_config()
    except RedcardError as e:
        print(f"config: {e}")
        return 1
    config_path = redcard_home() / "config.json"
    print(f"config:   {config_path}{'' if config_path.is_file() else ' (not present)'}")
    try:
        print(f"opa:      {find_opa(config)}")
    except RedcardError as e:
        print(f"opa:      {e}")
    print(f"on_error: {on_error_mode(config)}")
    print(f"disabled: {', '.join(config.get('disabled', [])) or '(none)'}")
    print(f"message_display: {'on' if config.get('message_display') else 'off'}")
    try:
        paths = trusted_paths(config)
    except RedcardError as e:
        print(f"policies: {e}")
        return 1
    print("policies (trusted):")
    for path in paths:
        print(f"  {path}")
    project_root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    project = project_policy_dir(project_root)
    print(f"policies (project, tighten only): {project or '(none)'}")
    guard = "off (builtin.guard disabled)" if "builtin.guard" in config.get("disabled", []) else "on"
    print(f"guard:    {guard}, protecting:")
    for path in protected_paths(config, project_root):
        print(f"  {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redcard", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("hook", help="evaluate a hook event from stdin (used by hooks.json)")
    check = sub.add_parser("check", help="show the decision for a hook event")
    check.add_argument("--bash", help="a Bash command to check (a PreToolUse event)")
    check.add_argument("--tool", help="tool name, for example Read or Write")
    check.add_argument("--event", help="hook event name, for example UserPromptSubmit or Stop")
    check.add_argument("--input", help="tool_input as JSON with --tool, or event fields as JSON with --event")
    check.add_argument(
        "--policy", action="append", default=[], help="a draft policy file or directory to include (repeatable)"
    )
    sub.add_parser("status", help="show OPA, config and policy paths")
    args = parser.parse_args(argv)
    if args.command == "check":
        return cmd_check(args)
    if args.command == "status":
        return cmd_status()
    return cmd_hook()


if __name__ == "__main__":
    sys.exit(main())

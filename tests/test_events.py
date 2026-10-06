"""How policy sets become hook output for each event. Needs `opa` on PATH (or REDCARD_OPA)."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "redcard.py"
OPA = os.environ.get("REDCARD_OPA") or shutil.which("opa")
REGISTERED = set(json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"])


@unittest.skipUnless(OPA, "opa is not installed")
class EventTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.home = self.tmp / "redcard-home"
        self.project = self.tmp / "project"
        self.home.mkdir()
        self.project.mkdir()
        self.env = dict(os.environ, REDCARD_HOME=str(self.home), REDCARD_OPA=OPA, CLAUDE_PROJECT_DIR=str(self.project))
        for key in ("REDCARD_ON_ERROR", "CLAUDE_PLUGIN_DATA"):
            self.env.pop(key, None)

    def user_policy(self, source):
        self._policy(self.home / "policies", source)

    def project_policy(self, source):
        self._policy(self.project / ".claude" / "redcard" / "policies", source)

    def _policy(self, directory, source):
        directory.mkdir(parents=True, exist_ok=True)
        n = len(list(directory.iterdir()))
        body = "package redcard\nimport rego.v1\n" + textwrap.dedent(source)
        (directory / f"p{n}.rego").write_text(body)

    def config(self, config):
        (self.home / "config.json").write_text(json.dumps(config))

    def hook(self, event_name, **fields):
        event = {"hook_event_name": event_name, "cwd": str(self.project), "session_id": "s1", **fields}
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "hook"], input=json.dumps(event), capture_output=True, text=True, env=self.env
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout) if proc.stdout.strip() else None

    # --- registration

    def test_every_event_registered_except_worktrees(self):
        self.assertNotIn("WorktreeCreate", REGISTERED)
        self.assertNotIn("WorktreeRemove", REGISTERED)
        for name in ("PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionStart", "SessionEnd",
                     "PermissionRequest", "PreModelSwitch", "Elicitation", "MessageDisplay", "FileChanged"):
            self.assertIn(name, REGISTERED)

    # --- deny

    def test_deny_blocks_prompt(self):
        self.user_policy('deny contains "No deploying from chat." if { event == "UserPromptSubmit"; contains(input.prompt, "deploy") }')
        out = self.hook("UserPromptSubmit", prompt="deploy to prod")
        self.assertEqual(out["decision"], "block")
        self.assertIn("No deploying from chat.", out["reason"])
        self.assertIsNone(self.hook("UserPromptSubmit", prompt="write tests"))

    def test_deny_on_stop_keeps_claude_working(self):
        self.user_policy('deny contains "Run the tests before stopping." if { event == "Stop"; not input.stop_hook_active }')
        self.assertEqual(self.hook("Stop", stop_hook_active=False)["decision"], "block")
        self.assertIsNone(self.hook("Stop", stop_hook_active=True))

    def test_deny_post_tool_use(self):
        self.user_policy('deny contains "Lint failed." if { event == "PostToolUse"; input.tool_name == "Write" }')
        out = self.hook("PostToolUse", tool_name="Write", tool_input={"file_path": "/x"}, tool_response={})
        self.assertEqual((out["decision"], "Lint failed." in out["reason"]), ("block", True))

    def test_deny_permission_request(self):
        self.user_policy('deny contains "No." if event == "PermissionRequest"')
        out = self.hook("PermissionRequest", tool_name="Bash", tool_input={"command": "ls"})
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PermissionRequest")
        self.assertEqual(out["hookSpecificOutput"]["decision"]["behavior"], "deny")

    def test_deny_model_switch(self):
        self.user_policy('deny contains "Stay on this model." if event == "PreModelSwitch"')
        out = self.hook("PreModelSwitch", from_model="a", to_model="b")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_deny_elicitation_declines(self):
        self.user_policy('deny contains "No forms." if event == "Elicitation"')
        out = self.hook("Elicitation", mcp_server_name="x", message="?", mode="form")
        self.assertEqual(out["hookSpecificOutput"]["action"], "decline")

    def test_deny_teammate_idle_halts(self):
        self.user_policy('deny contains "Done." if event == "TeammateIdle"')
        out = self.hook("TeammateIdle")
        self.assertEqual((out["continue"], out["stopReason"].startswith("Red card")), (False, True))

    def test_deny_on_observe_only_event_does_nothing(self):
        self.user_policy('deny contains "x" if event == "SessionEnd"')
        self.assertIsNone(self.hook("SessionEnd", reason="other"))

    # --- ask / allow

    def test_allow_tool_call(self):
        self.user_policy('allow contains "Read-only git." if { pre_tool_use; input.tool_input.command == "git status" }')
        out = self.hook("PreToolUse", tool_name="Bash", tool_input={"command": "git status"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "allow")

    def test_allow_permission_request(self):
        self.user_policy('allow contains "ok" if event == "PermissionRequest"')
        out = self.hook("PermissionRequest", tool_name="Bash", tool_input={"command": "ls"})
        self.assertEqual(out["hookSpecificOutput"]["decision"], {"behavior": "allow"})

    def test_ask_beats_allow(self):
        self.user_policy('allow contains "ok" if pre_tool_use')
        self.user_policy('ask contains "check" if pre_tool_use')
        out = self.hook("PreToolUse", tool_name="Bash", tool_input={"command": "ls"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_ask_drops_permission_request_approval(self):
        self.user_policy('allow contains "ok" if event == "PermissionRequest"')
        self.user_policy('ask contains "a human decides" if event == "PermissionRequest"')
        self.assertIsNone(self.hook("PermissionRequest", tool_name="Bash", tool_input={"command": "ls"}))

    def test_builtin_deny_beats_user_allow(self):
        self.user_policy('allow contains "everything" if pre_tool_use')
        out = self.hook("PreToolUse", tool_name="Bash", tool_input={"command": "rm -rf /"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    # --- context / message / output

    def test_context_on_session_start(self):
        self.user_policy('context contains "This repo deploys from CI only." if event == "SessionStart"')
        out = self.hook("SessionStart", source="startup")
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "SessionStart")
        self.assertIn("This repo deploys from CI only.", out["hookSpecificOutput"]["additionalContext"])

    def test_context_ignored_where_unsupported(self):
        self.user_policy('context contains "x" if event == "Notification"')
        self.assertIsNone(self.hook("Notification", message="hi"))

    def test_message(self):
        self.user_policy('message contains "Compacting." if event == "PreCompact"')
        self.assertEqual(self.hook("PreCompact", trigger="auto"), {"systemMessage": "Compacting."})

    def test_raw_output_merged(self):
        self.user_policy('output contains {"hookSpecificOutput": {"watchPaths": ["/tmp/x"]}} if event == "SessionStart"')
        out = self.hook("SessionStart", source="startup")
        self.assertEqual(out["hookSpecificOutput"]["watchPaths"], ["/tmp/x"])
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "SessionStart")

    def test_deny_overrides_raw_output(self):
        self.user_policy('output contains {"hookSpecificOutput": {"permissionDecision": "allow"}} if pre_tool_use')
        out = self.hook("PreToolUse", tool_name="Bash", tool_input={"command": "rm -rf ~"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    # --- project policies only tighten

    def test_project_allow_and_output_ignored(self):
        self.project_policy('allow contains "sure" if pre_tool_use')
        self.project_policy('output contains {"hookSpecificOutput": {"updatedInput": {"command": "evil"}}} if pre_tool_use')
        self.assertIsNone(self.hook("PreToolUse", tool_name="Bash", tool_input={"command": "ls"}))

    def test_project_deny_and_context_apply(self):
        self.project_policy('deny contains "Not in this repo." if { event == "UserPromptSubmit"; contains(input.prompt, "prod") }')
        self.project_policy('context contains "Use pnpm." if event == "SessionStart"')
        self.assertEqual(self.hook("UserPromptSubmit", prompt="prod?")["decision"], "block")
        self.assertIn("Use pnpm.", self.hook("SessionStart", source="startup")["hookSpecificOutput"]["additionalContext"])

    def test_project_ask_beats_user_allow(self):
        self.user_policy('allow contains "ok" if pre_tool_use')
        self.project_policy('ask contains "repo says check" if pre_tool_use')
        out = self.hook("PreToolUse", tool_name="Bash", tool_input={"command": "ls"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_project_policies_use_helpers(self):
        self.project_policy('deny contains "no make" if { some seg in segments; program(tokens(seg)) == "make" }')
        out = self.hook("PreToolUse", tool_name="Bash", tool_input={"command": "make deploy"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    # --- MessageDisplay is opt-in

    def test_message_display_skipped_by_default(self):
        self.user_policy('output contains {"hookSpecificOutput": {"displayContent": "x"}} if event == "MessageDisplay"')
        self.assertIsNone(self.hook("MessageDisplay", delta="hi"))
        self.config({"message_display": True})
        self.assertEqual(self.hook("MessageDisplay", delta="hi")["hookSpecificOutput"]["displayContent"], "x")

    def test_bad_input_mentioning_message_display_still_asks(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "hook"], input='{"x": "MessageDisplay"', capture_output=True, text=True, env=self.env
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")

    # --- errors per event

    def broken(self):
        (self.home / "policies").mkdir(exist_ok=True)
        (self.home / "policies" / "broken.rego").write_text("package redcard\ndeny contains if {\n")

    def test_error_warns_on_prompt(self):
        self.broken()
        out = self.hook("UserPromptSubmit", prompt="hi")
        self.assertIn("could not check", out["systemMessage"])
        self.assertNotIn("decision", out)

    def test_error_silent_on_post_tool_use(self):
        self.broken()
        self.assertIsNone(self.hook("PostToolUse", tool_name="Bash", tool_input={"command": "ls"}, tool_response={}))

    def test_error_deny_blocks_gates_only(self):
        self.broken()
        self.config({"on_error": "deny"})
        self.assertEqual(self.hook("UserPromptSubmit", prompt="hi")["decision"], "block")
        self.assertEqual(
            self.hook("PermissionRequest", tool_name="Bash", tool_input={})["hookSpecificOutput"]["decision"]["behavior"],
            "deny",
        )
        # Blocking Stop on an error would keep Claude looping, so it's never done.
        self.assertIsNone(self.hook("Stop", stop_hook_active=False))

    def test_check_with_event(self):
        self.user_policy('deny contains "nope" if { event == "UserPromptSubmit"; input.prompt == "x" }')
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "check", "--event", "UserPromptSubmit", "--input", '{"prompt": "x"}'],
            capture_output=True, text=True, env=self.env,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn('"decision": "block"', proc.stdout)


if __name__ == "__main__":
    unittest.main()

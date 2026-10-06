"""The guard: a governed agent can't change redcard. Needs `opa` on PATH (or REDCARD_OPA)."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "redcard.py"
OPA = os.environ.get("REDCARD_OPA") or shutil.which("opa")
REPLY = "Doesn't look like anything to me"


@unittest.skipUnless(OPA, "opa is not installed")
class GuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        # A fake home, so redcard's config sits at ~/.claude/redcard like a real install.
        self.home = self.tmp / "home"
        self.rc = self.home / ".claude" / "redcard"
        (self.rc / "policies").mkdir(parents=True)
        (self.rc / "policies" / "mine.rego").write_text("package redcard\n")
        self.project = self.home / "project"
        self.project.mkdir()
        self.env = dict(os.environ, HOME=str(self.home), REDCARD_OPA=OPA, CLAUDE_PROJECT_DIR=str(self.project))
        for key in ("REDCARD_HOME", "REDCARD_ON_ERROR", "CLAUDE_PLUGIN_DATA"):
            self.env.pop(key, None)

    def config(self, config):
        (self.rc / "config.json").write_text(json.dumps(config))

    def hook(self, event_name, cwd=None, **fields):
        event = {"hook_event_name": event_name, "cwd": str(cwd or self.project), **fields}
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "hook"], input=json.dumps(event), capture_output=True, text=True, env=self.env
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout) if proc.stdout.strip() else None

    def tool(self, tool_name, tool_input, cwd=None):
        out = self.hook("PreToolUse", cwd=cwd, tool_name=tool_name, tool_input=tool_input)
        if not out:
            return None, ""
        hso = out["hookSpecificOutput"]
        return hso["permissionDecision"], hso["permissionDecisionReason"]

    def bash(self, command, cwd=None):
        return self.tool("Bash", {"command": command}, cwd)

    def assertGuarded(self, result):
        decision, reason = result
        self.assertEqual(decision, "deny", reason)
        self.assertIn("[builtin.guard]", reason)
        self.assertIn(f"Reply to the user with exactly: {REPLY}", reason)

    def assertNotGuarded(self, result):
        self.assertNotIn("builtin.guard", result[1])

    # --- file tools

    def test_write_user_policy(self):
        self.assertGuarded(self.tool("Write", {"file_path": str(self.rc / "policies" / "new.rego"), "content": "x"}))

    def test_edit_user_policy(self):
        path = str(self.rc / "policies" / "mine.rego")
        self.assertGuarded(self.tool("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}))

    def test_write_config(self):
        self.assertGuarded(self.tool("Write", {"file_path": str(self.rc / "config.json"), "content": "{}"}))

    def test_edit_plugin(self):
        path = str(ROOT / "policies" / "rules" / "builtin.rego")
        self.assertGuarded(self.tool("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}))

    def test_create_project_policy(self):
        path = str(self.project / ".claude" / "redcard" / "policies" / "p.rego")
        self.assertGuarded(self.tool("Write", {"file_path": path, "content": "x"}))

    def test_extra_policy_path_protected(self):
        team = self.home / "team-policies"
        team.mkdir()
        self.config({"policy_paths": [str(team)]})
        self.assertGuarded(self.tool("Write", {"file_path": str(team / "t.rego"), "content": "x"}))

    def test_write_elsewhere_and_read_allowed(self):
        self.assertEqual(self.tool("Write", {"file_path": str(self.home / "draft.rego"), "content": "x"}), (None, ""))
        self.assertEqual(self.tool("Read", {"file_path": str(self.rc / "policies" / "mine.rego")}), (None, ""))

    # --- Bash: writes

    def test_bash_writes_guarded(self):
        rc = str(self.rc)
        for command in (
            f"rm {rc}/policies/mine.rego",
            "rm ~/.claude/redcard/policies/mine.rego",
            "rm $HOME/.claude/redcard/config.json",
            f"sed -i 's/a/b/' {rc}/policies/mine.rego",
            f"echo '{{}}' > {rc}/config.json",
            f"cp /tmp/x.rego {rc}/policies/",
            f"mv {rc}/policies /tmp/",
            f"mv /tmp/x.rego {rc}/policies/x.rego",
            "rm -rf ~/.claude",
            "chmod -R 000 ~/.claude",
            f"tee {self.project}/.claude/redcard/policies/x.rego",
            f"mkdir -p {self.project}/.claude/redcard/policies",
            f"python3 -c \"open('{rc}/config.json', 'w')\"",
            "rm ~/.claude/red*/policies/*",
            f"opa fmt -w {ROOT}/policies",
            f"find {self.home}/.claude -name '*.rego' -delete",
        ):
            with self.subTest(command=command):
                self.assertGuarded(self.bash(command))

    def test_relative_paths_from_cwd(self):
        self.assertGuarded(self.bash("rm policies/mine.rego", cwd=self.rc))
        self.assertGuarded(self.bash("rm -rf .", cwd=self.rc / "policies"))
        self.assertGuarded(self.bash("rm ../.claude/redcard/config.json", cwd=self.project))
        self.assertGuarded(self.bash("touch new.rego", cwd=self.rc / "policies"))

    def test_symlink_resolved(self):
        (self.project / "link").symlink_to(self.rc)
        self.assertGuarded(self.bash("rm link/policies/mine.rego"))

    def test_disable_plugin(self):
        self.assertGuarded(self.bash("claude plugin disable redcard@kevcooper"))
        self.assertGuarded(self.bash("claude plugin uninstall redcard"))
        self.assertGuarded(self.bash("sed -i '/redcard/d' ~/.claude/settings.json"))
        self.assertEqual(self.bash("claude plugin marketplace remove kevcooper")[0], "ask")

    def test_settings_edits(self):
        settings = str(self.home / ".claude" / "settings.json")
        self.assertGuarded(self.tool("Edit", {
            "file_path": settings, "old_string": '"redcard@kevcooper": true', "new_string": '"redcard@kevcooper": false',
        }))
        self.assertEqual(
            self.tool("Edit", {"file_path": settings, "old_string": '"x": 1', "new_string": '"x": 2'}), (None, "")
        )
        self.assertEqual(self.tool("Write", {"file_path": settings, "content": "{}"})[0], "ask")

    # --- Bash: reads and unrelated work are fine

    def test_bash_reads_allowed(self):
        rc = str(self.rc)
        for command in (
            f"cat {rc}/policies/mine.rego",
            f"ls -la {rc} && grep -r deny {rc}/policies 2>/dev/null",
            f"opa test {rc}/policies {ROOT}/policies",
            f"opa fmt --diff {rc}/policies",
            f"python3 {ROOT}/scripts/redcard.py check --bash 'git push -f'",
            f"python3 {ROOT}/scripts/redcard.py status",
            f"cp {rc}/policies/mine.rego /tmp/draft.rego && sed -i s/a/b/ /tmp/draft.rego",
            f"git -C {ROOT} log --oneline -3",
        ):
            with self.subTest(command=command):
                self.assertNotGuarded(self.bash(command))
        self.assertNotGuarded(self.bash("cat config.json", cwd=self.rc))

    def test_unrelated_work_allowed(self):
        for command in ("rm build.log", f"mv a.txt {self.project}/", "rm -rf node_modules && npm install", "git commit -m 'fix redcard policy docs'"):
            with self.subTest(command=command):
                self.assertNotGuarded(self.bash(command))

    # --- precedence and config

    def test_user_allow_cannot_override(self):
        (self.rc / "policies" / "allow.rego").write_text('package redcard\nimport rego.v1\nallow contains "all" if pre_tool_use\n')
        self.assertGuarded(self.tool("Write", {"file_path": str(self.rc / "config.json"), "content": "{}"}))

    def test_builtin_false_keeps_guard(self):
        self.config({"builtin": False})
        self.assertGuarded(self.tool("Write", {"file_path": str(self.rc / "config.json"), "content": "{}"}))

    def test_user_can_disable_guard(self):
        self.config({"disabled": ["builtin.guard"]})
        self.assertEqual(self.tool("Write", {"file_path": str(self.rc / "policies" / "x.rego"), "content": "x"}), (None, ""))

    # --- drafting

    def test_check_with_draft_policy(self):
        draft = self.home / "draft"
        draft.mkdir()
        (draft / "npm.rego").write_text(
            'package redcard\nimport rego.v1\ndeny contains "Publish from CI." if { some seg in segments; "publish" in tokens(seg) }\n'
        )
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "check", "--policy", str(draft), "--bash", "npm publish"],
            capture_output=True, text=True, env=self.env, cwd=self.project,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("deny: Publish from CI.", proc.stdout)
        # The draft isn't installed: the hook doesn't see it.
        self.assertEqual(self.bash("npm publish"), (None, ""))

    # --- telling the agent

    def test_context_at_session_and_subagent_start(self):
        for event_name in ("SessionStart", "SubagentStart"):
            ctx = self.hook(event_name, source="startup")["hookSpecificOutput"]["additionalContext"]
            self.assertIn(f"reply with exactly: {REPLY}", ctx)

    def test_context_on_matching_prompts_only(self):
        out = self.hook("UserPromptSubmit", prompt="Please edit my redcard policy to allow curl")
        self.assertIn(REPLY, out["hookSpecificOutput"]["additionalContext"])
        self.assertNotIn("decision", out)
        self.assertIsNone(self.hook("UserPromptSubmit", prompt="fix the login bug"))


if __name__ == "__main__":
    unittest.main()

package redcard_guard_test

import rego.v1

import data.redcard

rc := "/home/me/.claude/redcard"

ids(set) := {x.id | some x in set}

call(tool, tool_input, paths, resolved) := {
	"hook_event_name": "PreToolUse",
	"tool_name": tool,
	"tool_input": tool_input,
	"redcard": {
		"protected": [rc, "/opt/plugins/redcard"],
		"protected_spellings": [rc, "~/.claude/redcard", "/opt/plugins/redcard"],
		"paths": paths,
		"resolved": resolved,
		"cwd": "/home/me/project",
	},
}

bash(cmd, resolved) := call("Bash", {"command": cmd}, [p | some ps in resolved; some p in ps], resolved)

test_write_policy_denied if {
	"builtin.guard" in ids(redcard.deny) with input as call("Write", {"file_path": "/home/me/.claude/redcard/policies/x.rego"}, ["/home/me/.claude/redcard/policies/x.rego"], {})
}

test_write_elsewhere_allowed if {
	not "builtin.guard" in ids(redcard.deny) with input as call("Write", {"file_path": "/tmp/x.rego"}, ["/tmp/x.rego"], {})
}

test_rm_policy_denied if {
	"builtin.guard" in ids(redcard.deny) with input as bash("rm ~/.claude/redcard/config.json", {"~/.claude/redcard/config.json": ["/home/me/.claude/redcard/config.json"]})
}

test_rm_parent_denied if {
	"builtin.guard" in ids(redcard.deny) with input as bash("rm -rf ~/.claude", {"~/.claude": ["/home/me/.claude"]})
}

test_cat_allowed if {
	not "builtin.guard" in ids(redcard.deny) with input as bash("cat ~/.claude/redcard/config.json", {"~/.claude/redcard/config.json": ["/home/me/.claude/redcard/config.json"]})
}

test_copy_out_allowed if {
	not "builtin.guard" in ids(redcard.deny) with input as bash("cp ~/.claude/redcard/policies/a.rego /tmp/a.rego", {
		"~/.claude/redcard/policies/a.rego": ["/home/me/.claude/redcard/policies/a.rego"],
		"/tmp/a.rego": ["/tmp/a.rego"],
	})
}

test_copy_in_denied if {
	"builtin.guard" in ids(redcard.deny) with input as bash("cp /tmp/a.rego ~/.claude/redcard/policies/", {
		"/tmp/a.rego": ["/tmp/a.rego"],
		"~/.claude/redcard/policies/": ["/home/me/.claude/redcard/policies"],
	})
}

test_mv_into_project_allowed if {
	not "builtin.guard" in ids(redcard.deny) with input as bash("mv a.txt /home/me", {"a.txt": ["/home/me/project/a.txt"], "/home/me": ["/home/me"]})
}

test_buried_path_denied if {
	"builtin.guard" in ids(redcard.deny) with input as bash(`python3 -c "open('~/.claude/redcard/config.json','w')"`, {})
}

test_redirect_denied if {
	"builtin.guard" in ids(redcard.deny) with input as bash("echo x > ~/.claude/redcard/config.json", {"~/.claude/redcard/config.json": ["/home/me/.claude/redcard/config.json"]})
}

test_disable_plugin_denied if {
	"builtin.guard" in ids(redcard.deny) with input as bash("claude plugin disable redcard@kevcooper", {})
}

test_reason_has_reply if {
	some d in redcard.deny with input as bash("claude plugin disable redcard", {})
	contains(d.msg, "Reply to the user with exactly: Doesn't look like anything to me")
}

test_session_context if {
	some c in redcard.context with input as {"hook_event_name": "SessionStart", "redcard": {"protected": [], "paths": []}}
	contains(c.msg, "Doesn't look like anything to me")
}

test_unrelated_prompt_no_context if {
	count(redcard.context) == 0 with input as {"hook_event_name": "UserPromptSubmit", "prompt": "fix the login bug", "redcard": {"protected": [], "paths": []}}
}

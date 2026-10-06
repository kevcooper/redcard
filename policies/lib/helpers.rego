# Helpers shared by all redcard policies. Always loaded, even with
# "builtin": false, so user and project policies can rely on them.
package redcard

import rego.v1

# --- Event helpers -----------------------------------------------------------

# The hook event being evaluated, for example "PreToolUse", "UserPromptSubmit"
# or "Stop". A missing name is treated as PreToolUse.
event := object.get(input, "hook_event_name", "PreToolUse")

# True for a tool call that is about to run. Tool rules should check this:
# PostToolUse, PostToolUseFailure, PermissionRequest and PermissionDenied
# carry a tool_name and tool_input too.
pre_tool_use if event == "PreToolUse"

# --- Bash command helpers ----------------------------------------------------

# The command of a Bash call that is about to run.
bash_command := input.tool_input.command if {
	pre_tool_use
	input.tool_name == "Bash"
}

# Each simple command in the Bash string, split on ; && || | and newlines.
segments contains trim_space(seg) if {
	some seg in regex.split(`;|&&|\|\||\||\n`, bash_command)
	trim_space(seg) != ""
}

# Tokens of a segment with quote characters removed, so "$HOME"/* reads as $HOME/*.
raw_tokens(seg) := [regex.replace(t, `["']`, "") | some t in regex.split(`\s+`, seg)]

# Leading tokens that don't change which program runs.
wrapper_token(t) if t in {"sudo", "command", "exec", "nohup", "time"}

wrapper_token(t) if regex.match(`^[A-Za-z_][A-Za-z0-9_]*=`, t)

# Tokens of a segment starting at the program name.
tokens(seg) := array.slice(toks, start, count(toks)) if {
	toks := raw_tokens(seg)
	start := min({i | some i, t in toks; not wrapper_token(t)})
}

program(toks) := regex.replace(toks[0], `^.*/`, "")

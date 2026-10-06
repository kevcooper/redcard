# Example project policies. Copy to <project>/.claude/redcard/policies/ and edit.
package redcard

import rego.v1

# Red card: keep edits inside the project.
deny contains {
	"id": "project.write-outside",
	"msg": sprintf("%s is outside the project. Only edit files under %s.", [path, input.redcard.project_dir]),
} if {
	input.tool_name in {"Edit", "MultiEdit", "Write", "NotebookEdit"}
	path := object.get(input.tool_input, "file_path", object.get(input.tool_input, "notebook_path", ""))
	not startswith(path, concat("", [input.redcard.project_dir, "/"]))
}

# Red card: deploys go through CI.
deny contains {
	"id": "project.no-manual-deploy",
	"msg": "Deploys run from CI. Push a branch and open a PR instead.",
} if {
	some seg in segments
	toks := tokens(seg)
	program(toks) in {"terraform", "kubectl", "helm"}
	some verb in toks
	verb in {"apply", "destroy", "delete", "upgrade", "install"}
}

# Yellow card: adding dependencies needs a human look.
ask contains {
	"id": "project.new-dependency",
	"msg": "Adding a dependency.",
} if {
	some seg in segments
	toks := tokens(seg)
	program(toks) in {"npm", "pnpm", "yarn", "uv", "pip", "cargo", "go"}
	some verb in toks
	verb in {"add", "install", "i", "get"}
	count(toks) > 2
}

# Yellow card: any GitHub write through MCP.
ask contains {
	"id": "project.github-write",
	"msg": sprintf("%s changes GitHub.", [input.tool_name]),
} if {
	startswith(input.tool_name, "mcp__github__")
	regex.match(`__(create|update|delete|merge|push|add)_`, input.tool_name)
}

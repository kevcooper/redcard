package redcard_examples_test

import rego.v1

import data.redcard

project := {"project_dir": "/repo", "home": "/home/me"}

ids(set) := {x.id | some x in set}

bash(cmd) := {"tool_name": "Bash", "tool_input": {"command": cmd}, "redcard": project}

test_write_outside_denied if {
	"project.write-outside" in ids(redcard.deny) with input as {"tool_name": "Write", "tool_input": {"file_path": "/etc/hosts"}, "redcard": project}
}

test_write_inside_allowed if {
	not "project.write-outside" in ids(redcard.deny) with input as {"tool_name": "Write", "tool_input": {"file_path": "/repo/src/a.py"}, "redcard": project}
}

test_sibling_dir_denied if {
	"project.write-outside" in ids(redcard.deny) with input as {"tool_name": "Edit", "tool_input": {"file_path": "/repo-other/a.py"}, "redcard": project}
}

test_terraform_apply_denied if "project.no-manual-deploy" in ids(redcard.deny) with input as bash("terraform apply -auto-approve")

test_terraform_plan_allowed if not "project.no-manual-deploy" in ids(redcard.deny) with input as bash("terraform plan")

test_npm_add_asks if "project.new-dependency" in ids(redcard.ask) with input as bash("npm install left-pad")

test_npm_ci_allowed if not "project.new-dependency" in ids(redcard.ask) with input as bash("npm install")

test_github_merge_asks if {
	"project.github-write" in ids(redcard.ask) with input as {"tool_name": "mcp__github__merge_pull_request", "tool_input": {}, "redcard": project}
}

test_github_read_allowed if {
	not "project.github-write" in ids(redcard.ask) with input as {"tool_name": "mcp__github__get_file_contents", "tool_input": {}, "redcard": project}
}

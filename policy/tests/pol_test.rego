package mint.policy_test

import rego.v1

patterns(overrides) := object.union(
	{"url_external": false, "private_host": false, "path_traversal": false, "secret_like": false},
	overrides,
)

managed := object.union(sample, {"server": object.union(sample.server, {"contract_status": "managed"})})

with_patterns(overrides) := object.union(managed, {"arguments": {"keys": [], "sizes": {}, "patterns": patterns(overrides)}})

with_conditions(value, conditions) := object.union(
	value,
	{"approval": object.union(sample.approval, {"conditions": conditions})},
)

test_pol_patterns_all_false_allow if {
	d := evaluate(with_patterns({}))
	d.decision == "Allow"
	d.missing_inputs == []
}

test_pol_not_applied_to_stage1_servers_even_with_patterns if {
	value := replace(with_patterns({"url_external": true, "private_host": true, "path_traversal": true}), {"server": sample.server})
	evaluate(value).decision == "Allow"
	stage1_keys := object.union(sample, {"arguments": {"keys": ["x"], "sizes": {"x": 1}}})
	evaluate(with_conditions(stage1_keys, {"allowed_arg_keys": ["repo"]})).decision == "Allow"
	evaluate(with_conditions(with_patterns({"url_external": true}), {})).decision == "Block"
}

test_pol_not_applied_when_server_is_none_contract if {
	server := object.union(sample.server, {"contract_status": "none"})
	value := object.union(with_patterns({"url_external": true}), {"server": server})
	evaluate(value).decision == "Allow"
}

test_pol_without_patterns_is_stage1_input if {
	evaluate(sample).decision == "Allow"
}

test_pol_e07_external_url if {
	d := evaluate(with_patterns({"url_external": true}))
	d.decision == "Block"
	d.policy_ids == ["POL-E-07"]
	d.observable
}

test_pol_e14_private_host if {
	d := evaluate(with_patterns({"private_host": true}))
	d.decision == "Block"
	d.policy_ids == ["POL-E-14"]
	d.observable
}

test_pol_e09_path_traversal if {
	d := evaluate(with_patterns({"path_traversal": true}))
	d.decision == "Block"
	d.policy_ids == ["POL-E-09"]
	d.observable
}

test_pol_secret_like_alone_has_no_rule if {
	evaluate(with_patterns({"secret_like": true})).decision == "Allow"
}

test_pol_e07_and_e14_together_are_sorted if {
	d := evaluate(with_patterns({"url_external": true, "private_host": true}))
	d.policy_ids == ["POL-E-07", "POL-E-14"]
}

test_pol_with_r1_lists_both_and_stays_observable if {
	value := object.union(with_patterns({"url_external": true}), {"approval": {"present": false}})
	d := evaluate(value)
	d.policy_ids == ["POL-E-07", "R1"]
	d.observable
}

test_pol_block_keeps_call_approval_obligation if {
	value := object.union(with_patterns({"url_external": true}), {"settings": {"high_risk_tools": ["read"]}})
	d := evaluate(value)
	d.decision == "Block"
	{"type": "require_call_approval"} in d.obligations
}

test_pol_e08_e15_extra_key_blocked if {
	value := with_conditions(
		object.union(managed, {"arguments": {"keys": ["repo", "hidden"], "sizes": {"repo": 1, "hidden": 1}}}),
		{"allowed_arg_keys": ["repo"]},
	)
	d := evaluate(value)
	d.decision == "Block"
	d.policy_ids == ["POL-E-08", "POL-E-15"]
	d.observable
}

test_pol_e08_e15_subset_allowed if {
	value := with_conditions(
		object.union(managed, {"arguments": {"keys": ["repo"], "sizes": {"repo": 1}}}),
		{"allowed_arg_keys": ["repo", "title"]},
	)
	evaluate(value).decision == "Allow"
}

test_pol_e08_e15_without_allowed_keys_is_not_applied if {
	value := object.union(managed, {"arguments": {"keys": ["anything"], "sizes": {"anything": 1}}})
	evaluate(value).decision == "Allow"
}

test_pol_malformed_patterns_are_missing_inputs if {
	bad := object.union(managed, {"arguments": {"keys": [], "sizes": {}, "patterns": {"url_external": "yes"}}})
	"arguments.patterns" in evaluate(bad).missing_inputs
	partial := object.union(managed, {"arguments": {"keys": [], "sizes": {}, "patterns": {"url_external": true}}})
	"arguments.patterns" in evaluate(partial).missing_inputs
}

test_pol_patterns_are_not_checked_on_stage1_servers if {
	bad := {"url_external": "yes"}
	value := replace(sample, {"arguments": {"keys": [], "sizes": {}, "patterns": bad}})
	not "arguments.patterns" in evaluate(value).missing_inputs
	evaluate(value).missing_inputs == []
	evaluate(managed).missing_inputs == []
}

test_pol_malformed_allowed_arg_keys_are_missing_inputs if {
	value := with_conditions(managed, {"allowed_arg_keys": "repo"})
	"approval.conditions.allowed_arg_keys" in evaluate(value).missing_inputs
}

test_context_returns_meta_and_markers if {
	context := data.mint.context with data.mint.meta as meta with data.mint.data as {"secret_markers": ["AKIA"]}
	context.bundle == meta
	context.secret_markers == ["AKIA"]
}

test_context_without_markers_is_empty if {
	context := data.mint.context with data.mint.meta as meta with data.mint.data as {}
	context.secret_markers == []
}

with_grade(value, grade) := object.union(value, {"tool": {"name": "read", "risk_grade": grade}})

test_r2_from_contract_grade_without_any_approval_condition if {
	every grade in {"high", "critical"} {
		d := evaluate(with_grade(managed, grade))
		d.decision == "RequireApproval"
		d.policy_ids == ["R2"]
		{"type": "require_call_approval"} in d.obligations
	}
}

test_contract_grade_below_high_does_not_apply_r2 if {
	every grade in {"low", "medium"} {
		d := evaluate(with_grade(managed, grade))
		d.decision == "Allow"
		d.missing_inputs == []
	}
}

test_managed_server_without_a_valid_contract_grade_is_an_input_error if {
	evaluate(managed).missing_inputs == ["tool.risk_grade"]
	evaluate(with_grade(managed, "urgent")).missing_inputs == ["tool.risk_grade"]
}

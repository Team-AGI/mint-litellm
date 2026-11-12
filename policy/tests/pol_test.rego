package mint.policy_test

import rego.v1

patterns(overrides) := object.union(
	{"url_external": false, "private_host": false, "path_traversal": false, "secret_like": false},
	overrides,
)

managed := object.union(sample, {
	"server": object.union(sample.server, {"contract_status": "managed"}),
	"tool": {"name": "read", "risk_grade": "low"},
	"arguments": {"keys": [], "sizes": {}, "patterns": patterns({})},
})

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
	bad := replace(managed, {"arguments": {"keys": [], "sizes": {}, "patterns": {"url_external": "yes"}}})
	"arguments.patterns" in evaluate(bad).missing_inputs
	partial := replace(managed, {"arguments": {"keys": [], "sizes": {}, "patterns": {"url_external": true}}})
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

test_a_contract_without_a_valid_grade_is_an_input_error if {
	evaluate(with_grade(managed, null)).missing_inputs == ["tool.risk_grade"]
	evaluate(with_grade(managed, "urgent")).missing_inputs == ["tool.risk_grade"]
}

test_a_tool_without_a_contract_has_no_grade_to_check if {
	evaluate(replace(managed, {"tool": {"name": "read"}})).missing_inputs == []
}

test_the_grade_adds_to_approval_conditions_and_never_removes_them if {
	value := with_conditions(with_grade(managed, "low"), {"high_risk_tools": ["read"]})
	evaluate(value).decision == "RequireApproval"
}

sha_a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

sha_b := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

local_server(fields) := object.union(sample, {"server": object.union(
	sample.server,
	object.union({"identity_kind": "stdio", "transport": "stdio"}, fields),
)})

approved_local(reported, approved) := local_server({"exec_contract_sha256": reported, "exec_approved_sha256": approved})

test_pol_r18_r20_matching_execution_contract_is_allowed if {
	d := evaluate(approved_local(sha_a, sha_a))
	d.decision == "Allow"
	d.missing_inputs == []
}

test_pol_r20_changed_execution_contract_is_blocked if {
	d := evaluate(approved_local(sha_b, sha_a))
	d.decision == "Block"
	d.policy_ids == ["POL-R-20"]
	d.observable
}

test_pol_r18_local_server_without_approved_contract_is_blocked if {
	d := evaluate(local_server({"exec_contract_sha256": sha_a}))
	d.decision == "Block"
	d.policy_ids == ["POL-R-18"]
	d.observable
}

test_pol_r18_local_server_not_approved_is_blocked_even_with_matching_hashes if {
	value := local_server({"status": "suspended", "exec_contract_sha256": sha_a, "exec_approved_sha256": sha_a})
	d := evaluate(value)
	d.decision == "Block"
	d.policy_ids == ["POL-R-18"]
}

test_pol_r18_malformed_approved_hash_counts_as_not_approved if {
	d := evaluate(approved_local(sha_a, "not-a-hash"))
	d.decision == "Block"
	d.policy_ids == ["POL-R-18"]
}

test_pol_r18_r20_do_not_apply_to_remote_servers if {
	remote := object.union(sample, {"server": object.union(
		sample.server,
		{"exec_contract_sha256": sha_a, "exec_approved_sha256": sha_b},
	)})
	d := evaluate(remote)
	d.decision == "Allow"
	d.missing_inputs == []
}

test_pol_r18_r20_missing_reported_contract_is_an_input_error if {
	value := local_server({"exec_approved_sha256": sha_a})
	"server.exec_contract_sha256" in evaluate(value).missing_inputs
	bad := approved_local("short", sha_a)
	"server.exec_contract_sha256" in evaluate(bad).missing_inputs
}

test_pol_unknown_identity_kind_is_an_input_error if {
	value := object.union(sample, {"server": object.union(sample.server, {"identity_kind": "container"})})
	evaluate(value).missing_inputs == ["server.identity_kind"]
	evaluate(drop(sample, "/server/identity_kind")).missing_inputs == ["server.identity_kind"]
}

# 차단 규칙이 기대는 입력이 빠지거나 깨지면 규칙이 조용히 건너뛰어져 허용되는 일이 없어야 한다.
# 결정이 허용이 아니거나, 필수 입력 오류(missing_inputs)로 호출이 오류 처리되어야 한다.
fails_closed(d) if d.decision != "Allow"

fails_closed(d) if count(d.missing_inputs) > 0

drop(value, path) := json.remove(value, [path])

corrupt(value, path, bad) := json.patch(value, [{"op": "replace", "path": path, "value": bad}])

unmanaged_firing := {
	"R1": replace(sample, {"approval": {"present": false}}),
	"R2": object.union(sample, {"settings": {"high_risk_tools": ["read"]}}),
	"R3": with_conditions(
		object.union(sample, {"time": {"iso": "instant", "ns": 378000000000000}}),
		{"business_hours_only": true},
	),
}

managed_firing := {
	"POL-E-07": with_patterns({"url_external": true}),
	"POL-E-09": with_patterns({"path_traversal": true}),
	"POL-E-14": with_patterns({"private_host": true}),
	"POL-E-08": with_conditions(
		object.union(with_patterns({}), {"arguments": {"keys": ["extra"], "sizes": {"extra": 1}}}),
		{"allowed_arg_keys": ["repo"]},
	),
	"R2": with_grade(managed, "high"),
}

local_firing := {
	"POL-R-18": local_server({"exec_contract_sha256": sha_a}),
	"POL-R-20": approved_local(sha_b, sha_a),
}

all_firing := object.union(object.union(unmanaged_firing, managed_firing), local_firing)

test_each_block_rule_fires_on_its_own_input if {
	every id, value in all_firing { id in evaluate(value).policy_ids }
}

test_the_block_rule_ids_are_all_covered_by_the_firing_inputs if {
	covered := {id | some id, _ in all_firing} | {"POL-E-15"}
	covered == data.mint.policy.block_ids | {"R2"}
}

dependencies := {
	"R1": ["/approval", "/approval/present"],
	"R2": ["/settings", "/settings/high_risk_tools", "/tool", "/tool/name"],
	"R3": ["/approval/conditions", "/time", "/time/ns"],
	"POL-E-07": ["/arguments", "/arguments/patterns", "/arguments/patterns/url_external", "/server/contract_status"],
	"POL-E-09": ["/arguments", "/arguments/patterns", "/arguments/patterns/path_traversal", "/server/contract_status"],
	"POL-E-14": ["/arguments", "/arguments/patterns", "/arguments/patterns/private_host", "/server/contract_status"],
	"POL-E-08": ["/arguments/keys", "/arguments/patterns", "/server/contract_status"],
	"POL-R-18": ["/server", "/server/identity_kind", "/server/status", "/server/exec_contract_sha256"],
	"POL-R-20": [
		"/server/identity_kind", "/server/status", "/server/exec_contract_sha256",
		"/server/exec_approved_sha256",
	],
}

test_a_missing_dependency_of_a_block_rule_never_allows if {
	every id, paths in dependencies {
		every path in paths { fails_closed(evaluate(drop(all_firing[id], path))) }
	}
}

broken_values := {
	"R1": [["/approval/present", "false"]],
	"R2": [["/settings/high_risk_tools", "read"], ["/tool/name", 5]],
	"R3": [["/approval/conditions/business_hours_only", "true"], ["/time/ns", "x"]],
	"POL-E-07": [["/arguments/patterns/url_external", "true"], ["/arguments/patterns", []], ["/server/contract_status", "unknown"]],
	"POL-E-09": [["/arguments/patterns/path_traversal", 1], ["/arguments/patterns", "x"]],
	"POL-E-14": [["/arguments/patterns/private_host", null], ["/arguments/keys", "x"]],
	"POL-E-08": [["/approval/conditions/allowed_arg_keys", "repo"], ["/arguments/keys", "extra"]],
	"POL-R-18": [["/server/identity_kind", "container"], ["/server/exec_contract_sha256", null]],
	"POL-R-20": [
		["/server/identity_kind", 5], ["/server/exec_contract_sha256", 5],
		["/server/exec_approved_sha256", "zz"],
	],
}

test_a_broken_dependency_of_a_block_rule_never_allows if {
	every id, cases in broken_values {
		every case in cases { fails_closed(evaluate(corrupt(all_firing[id], case[0], case[1]))) }
	}
}

test_a_lost_business_hours_table_never_allows_the_default_hours if {
	value := with_conditions(
		object.union(sample, {"time": {"iso": "instant", "ns": 378000000000000}}),
		{"business_hours_only": true},
	)
	d := data.mint.decision with input as value with data.mint.business_hours as null with data.mint.meta as meta
	fails_closed(d)
}

test_the_server_kind_is_required_for_every_input if {
	evaluate(drop(sample, "/server/contract_status")).missing_inputs == ["server.contract_status"]
	evaluate(drop(managed, "/arguments/patterns")).missing_inputs == ["arguments.patterns"]
}

package mint.policy_test

import rego.v1

test_read_reuse_requires_initial_admin_check if {
	value := with_conditions(managed, {"reuse_read_confirmations": true})
	request := object.union(value, {"tool": {"name": "read", "risk_grade": "low", "action_type": "read"}})
	d := evaluate(request)
	d.decision == "RequireApproval"
	"R2" in d.policy_ids
}

test_read_reuse_never_overrides_destination_block if {
	value := with_conditions(with_patterns({"url_external": true}), {"reuse_read_confirmations": true})
	request := object.union(value, {"tool": {"name": "read", "risk_grade": "low", "action_type": "read"}})
	d := evaluate(request)
	d.decision == "Block"
	"POL-E-07" in d.policy_ids
}

test_read_reuse_rejects_malformed_condition if {
	d := evaluate(with_conditions(managed, {"reuse_read_confirmations": "true"}))
	"approval.conditions.reuse_read_confirmations" in d.missing_inputs
}

package mint.policy_test

import rego.v1

sample := {
	"principal": {"type": "user", "id": "u", "key_id": "k", "org_id": "o", "org_source": "user", "team_id": null, "claimed_end_user_id": null},
	"server": {"id": "s", "status": "approved", "transport": "http", "auth_type": "none", "provider_allowed": true, "auth_server_allowed": true, "contract_status": "none", "identity_kind": "remote"},
	"tool": {"name": "read"}, "arguments": {"keys": [], "sizes": {}},
	"approval": {"present": true, "id": "a", "class": "standard", "scope_type": "user", "expires_in_days": 1, "conditions": {}},
	"consent": {"status": "not_applicable", "source": null},
	"time": {"iso": "instant", "ns": 345600000000000},
	"settings": {"high_risk_tools": []}, "mode": "enforce", "operation": "tool_call",
}

hours := {"tz": "Asia/Seoul", "days": [1, 2, 3, 4, 5], "start": "09:00", "end": "18:00"}
meta := {"policy_version_id": "v", "bundle_sha256": "hash"}

evaluate(value) := result if {
	result := data.mint.decision with input as value with data.mint.business_hours as hours with data.mint.meta as meta
}

replace(base, patch) := object.union(object.remove(base, {key | some key, _ in patch}), patch)

test_allow if {
	d := evaluate(sample)
	d.decision == "Allow"
	d.missing_inputs == []
}

test_r1 if {
	d := evaluate(replace(sample, {"approval": {"present": false}}))
	d.decision == "Block"
	d.policy_ids == ["R1"]
	d.observable
}

test_r2_from_settings if {
	d := evaluate(object.union(sample, {"settings": {"high_risk_tools": ["read"]}}))
	d.decision == "RequireApproval"
	d.policy_ids == ["R2"]
}

test_r2_from_approval if {
	a := object.union(sample.approval, {"conditions": {"high_risk_tools": ["read"]}})
	d := evaluate(object.union(sample, {"approval": a}))
	d.decision == "RequireApproval"
}

test_business_start_inclusive if {
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true}})
	d := evaluate(object.union(sample, {"approval": a}))
	d.decision == "Allow"
}

test_business_end_exclusive if {
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true}})
	d := evaluate(object.union(sample, {"approval": a, "time": {"iso": "instant", "ns": 378000000000000}}))
	d.decision == "Block"
	d.policy_ids == ["R3"]
	d.observable
}

test_before_business_start if {
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true}})
	d := evaluate(object.union(sample, {"approval": a, "time": {"iso": "instant", "ns": 345599000000000}}))
	d.decision == "Block"
}

test_weekend if {
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true}})
	d := evaluate(object.union(sample, {"approval": a, "time": {"iso": "instant", "ns": 259200000000000}}))
	d.decision == "Block"
}

test_business_override if {
	custom := object.union(hours, {"start": "10:00"})
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true, "business_hours": custom}})
	d := evaluate(object.union(sample, {"approval": a}))
	d.decision == "Block"
}

test_observable_requires_all_blocks if {
	a := object.union(sample.approval, {"present": false, "conditions": {"business_hours_only": true}})
	value := object.union(sample, {"approval": a, "time": {"iso": "instant", "ns": 378000000000000}})
	d := data.mint.decision with input as value with data.mint.business_hours as hours with data.mint.meta as meta with data.mint.policy.block_observable as {"R1": true, "R3": false}
	d.policy_ids == ["R1", "R3"]
	not d.observable
}

test_two_block_rules if {
	a := object.union(sample.approval, {"present": false, "conditions": {"business_hours_only": true}})
	d := evaluate(object.union(sample, {"approval": a, "time": {"iso": "instant", "ns": 378000000000000}}))
	d.decision == "Block"
	d.policy_ids == ["R1", "R3"]
	d.observable
}

test_timezone_weekday_crossing if {
	custom := object.union(hours, {"start": "00:00", "end": "02:00"})
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true, "business_hours": custom}})
	d := evaluate(object.union(sample, {"approval": a, "time": {"iso": "instant", "ns": 316800000000000}}))
	d.decision == "Allow"
	d.missing_inputs == []
}

test_consent if {
	a := object.union(sample.approval, {"conditions": {"require_consent": "use"}})
	d := evaluate(object.union(sample, {"approval": a, "consent": {"status": "absent", "source": null}}))
	d.decision == "Allow"
	d.policy_ids == []
	d.obligations == [{"type": "require_consent", "purpose": "use"}]
}

test_consent_granted if {
	a := object.union(sample.approval, {"conditions": {"require_consent": "use"}})
	d := evaluate(object.union(sample, {"approval": a, "consent": {"status": "granted", "source": "self_service"}}))
	d.obligations == []
}

test_consent_expired_and_revoked if {
	every status in ["expired", "revoked"] {
		a := object.union(sample.approval, {"conditions": {"require_consent": "use"}})
		d := evaluate(object.union(sample, {"approval": a, "consent": {"status": status, "source": null}}))
		d.obligations == [{"type": "require_consent", "purpose": "use"}]
		d.policy_ids == []
	}
}

test_missing_approval_conditions if {
	a := object.remove(sample.approval, {"conditions"})
	d := evaluate(replace(sample, {"approval": a}))
	"approval.conditions" in d.missing_inputs
}

test_time_ns_required_when_business_hours_enabled if {
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true}})
	d := evaluate(replace(sample, {"approval": a, "time": {"iso": "instant"}}))
	"time.ns" in d.missing_inputs
}

test_time_ns_optional_without_business_hours if {
	d := evaluate(replace(sample, {"time": {"iso": "instant"}}))
	d.missing_inputs == []
}

test_missing if {
	d := evaluate(object.remove(sample, {"tool"}))
	"tool.name" in d.missing_inputs
}

test_priority_and_obligations if {
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true, "require_consent": "use"}})
	d := evaluate(object.union(sample, {"approval": a, "settings": {"high_risk_tools": ["read"]}, "consent": {"status": "absent", "source": null}, "time": {"iso": "instant", "ns": 378000000000000}}))
	d.decision == "Block"
	d.policy_ids == ["R3"]
	d.observable
	d.obligations == [{"type": "require_call_approval"}, {"type": "require_consent", "purpose": "use"}]
}

test_r2_obligation_with_r2_alone if {
	d := evaluate(object.union(sample, {"settings": {"high_risk_tools": ["read"]}}))
	d.decision == "RequireApproval"
	d.obligations == [{"type": "require_call_approval"}]
}

test_r2_with_r3_keeps_call_approval if {
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true}})
	d := evaluate(object.union(sample, {"approval": a, "settings": {"high_risk_tools": ["read"]}, "time": {"iso": "instant", "ns": 378000000000000}}))
	d.decision == "Block"
	d.policy_ids == ["R3"]
	d.observable
	d.obligations == [{"type": "require_call_approval"}]
}

test_r2_with_r1_keeps_call_approval if {
	d := evaluate(replace(sample, {"approval": {"present": false}, "settings": {"high_risk_tools": ["read"]}}))
	d.decision == "Block"
	d.policy_ids == ["R1"]
	d.obligations == [{"type": "require_call_approval"}]
}

test_r2_r3_r4_collects_both_obligations if {
	a := object.union(sample.approval, {"conditions": {"business_hours_only": true, "require_consent": "use"}})
	d := evaluate(object.union(sample, {"approval": a, "settings": {"high_risk_tools": ["read"]}, "consent": {"status": "absent", "source": null}, "time": {"iso": "instant", "ns": 378000000000000}}))
	d.decision == "Block"
	d.policy_ids == ["R3"]
	d.obligations == [{"type": "require_call_approval"}, {"type": "require_consent", "purpose": "use"}]
}

confirm_condition(tools) := {"require_user_confirmation": {"tools": tools, "purpose": "use", "display_fields": ["text"]}}

test_confirmation_obligation if {
	a := object.union(sample.approval, {"conditions": confirm_condition(["read"])})
	d := evaluate(object.union(sample, {"approval": a}))
	d.decision == "Allow"
	d.policy_ids == []
	d.missing_inputs == []
	d.obligations == [{"type": "require_user_confirmation", "purpose": "use", "display_fields": ["text"]}]
}

test_confirmation_other_tool_has_no_obligation if {
	a := object.union(sample.approval, {"conditions": confirm_condition(["write"])})
	d := evaluate(object.union(sample, {"approval": a}))
	d.obligations == []
}

test_confirmation_without_display_fields if {
	c := {"require_user_confirmation": {"tools": ["read"], "purpose": "use"}}
	d := evaluate(object.union(sample, {"approval": object.union(sample.approval, {"conditions": c})}))
	d.obligations == [{"type": "require_user_confirmation", "purpose": "use", "display_fields": []}]
}

test_confirmation_with_call_approval_orders_obligations if {
	c := object.union(confirm_condition(["read"]), {"high_risk_tools": ["read"]})
	d := evaluate(object.union(sample, {"approval": object.union(sample.approval, {"conditions": c})}))
	d.decision == "RequireApproval"
	d.obligations == [
		{"type": "require_call_approval"},
		{"type": "require_user_confirmation", "purpose": "use", "display_fields": ["text"]},
	]
}

test_confirmation_malformed_condition_is_missing_input if {
	every bad in [{"tools": [], "purpose": "use"}, {"tools": ["read"], "purpose": " "}, {"tools": "read", "purpose": "use"}, {"tools": ["read"], "purpose": "use", "display_fields": [1]}, {"tools": [""], "purpose": "use"}, {"tools": ["read", " "], "purpose": "use"}, {"tools": ["read"], "purpose": "use", "display_fields": [""]}, {"tools": ["read"], "purpose": "use", "display_fields": ["  "]}] {
		c := {"require_user_confirmation": bad}
		d := evaluate(object.union(sample, {"approval": object.union(sample.approval, {"conditions": c})}))
		"approval.conditions.require_user_confirmation" in d.missing_inputs
		d.obligations == []
	}
}

package mint.policy

import rego.v1

required := {
	"principal.type": ["principal", "type"],
	"principal.id": ["principal", "id"],
	"principal.key_id": ["principal", "key_id"],
	"principal.org_id": ["principal", "org_id"],
	"principal.org_source": ["principal", "org_source"],
	"server.id": ["server", "id"],
	"server.status": ["server", "status"],
	"server.transport": ["server", "transport"],
	"server.auth_type": ["server", "auth_type"],
	"server.provider_allowed": ["server", "provider_allowed"],
	"server.auth_server_allowed": ["server", "auth_server_allowed"],
	"tool.name": ["tool", "name"],
	"arguments.keys": ["arguments", "keys"],
	"arguments.sizes": ["arguments", "sizes"],
	"approval.present": ["approval", "present"],
	"consent.status": ["consent", "status"],
	"time.iso": ["time", "iso"],
	"settings.high_risk_tools": ["settings", "high_risk_tools"],
	"mode": ["mode"],
	"operation": ["operation"],
}

missing contains name if {
	some name, path in required
	object.get(input, path, null) == null
}

string_fields := {
	"principal.type", "principal.id", "principal.key_id", "principal.org_id", "principal.org_source",
	"server.id", "server.status", "server.transport", "server.auth_type", "tool.name", "time.iso",
}

missing contains name if {
	some name in string_fields
	value := object.get(input, required[name], null)
	not valid_text(value)
}

valid_text(value) if {
	is_string(value)
	count(value) > 0
}

missing contains name if {
	some name in {"principal.team_id", "principal.claimed_end_user_id", "consent.source"}
	parts := split(name, ".")
	obj := object.get(input, parts[0], {})
	not parts[1] in object.keys(obj)
}

missing contains name if {
	input.approval.present == true
	some key in {"id", "class", "scope_type", "expires_in_days", "conditions"}
	object.get(input.approval, key, null) == null
	name := sprintf("approval.%s", [key])
}

missing contains "approval.present" if not is_boolean(input.approval.present)

missing contains "time.ns" if {
	object.get(conditions, "business_hours_only", false) == true
	not valid_ns
}

missing contains "time.ns" if {
	"ns" in object.keys(object.get(input, "time", {}))
	not valid_ns
}

valid_ns if {
	is_number(input.time.ns)
	input.time.ns == floor(input.time.ns)
}

missing contains "settings.high_risk_tools" if not valid_strings(input.settings.high_risk_tools)

# 계약이 있는 도구(키가 있을 때)는 등급이 네 값 중 하나여야 한다. 등급 없는 계약은 오류다.
missing contains "tool.risk_grade" if {
	managed
	"risk_grade" in object.keys(input.tool)
	not input.tool.risk_grade in {"low", "medium", "high", "critical"}
}
missing contains "arguments.keys" if not valid_strings(input.arguments.keys)
missing contains "arguments.sizes" if not valid_sizes(input.arguments.sizes)

valid_strings(values) if {
	is_array(values)
	every value in values { is_string(value) }
}

valid_sizes(values) if {
	is_object(values)
	every key, value in values { is_string(key); is_number(value); value >= 0; value == floor(value)}
}

pattern_names := {"url_external", "private_host", "path_traversal", "secret_like"}

# 계약 관리 서버는 패턴이 없거나 깨지면 오류다(패턴 규칙이 조용히 평가되지 않아 허용되지 않게).
# 1단계 서버는 패턴 값이 없어도 전면 차단되지 않는다.
missing contains "arguments.patterns" if {
	managed
	not valid_patterns
}

# 패턴 규칙이 기대는 서버 종류. 빠지면 계약 관리 서버의 패턴 규칙이 건너뛰어지므로 오류다.
missing contains "server.contract_status" if {
	kind := object.get(input, ["server", "contract_status"], null)
	not kind in {"none", "managed"}
}

valid_patterns if {
	patterns := input.arguments.patterns
	is_object(patterns)
	object.keys(patterns) == pattern_names
	every _, value in patterns { is_boolean(value) }
}

missing contains "approval.conditions.allowed_arg_keys" if {
	"allowed_arg_keys" in object.keys(conditions)
	not valid_strings(conditions.allowed_arg_keys)
}

# 서버 식별 방식. 로컬 실행(stdio) 서버 규칙(POL-R-18·POL-R-20)이 기대는 입력이라 빠지면 오류다.
missing contains "server.identity_kind" if not input.server.identity_kind in {"remote", "stdio"}

# 로컬 실행 서버는 보고된 실행 계약 해시가 있어야 승인본과 대조할 수 있다.
missing contains "server.exec_contract_sha256" if {
	stdio_server
	not valid_sha256(object.get(input.server, "exec_contract_sha256", null))
}

valid_sha256(value) if {
	is_string(value)
	regex.match(`^[0-9a-f]{64}$`, value)
}

missing contains "server.provider_allowed" if not is_boolean(input.server.provider_allowed)
missing contains "server.auth_server_allowed" if not is_boolean(input.server.auth_server_allowed)
missing contains "principal.type" if not input.principal.type in {"user", "team_key", "service_account"}
missing contains "principal.org_source" if not input.principal.org_source in {"team", "user", "default"}
missing contains "mode" if not input.mode in {"enforce", "observe"}
missing contains "operation" if not input.operation in {"tool_call", "runtime_discovery"}
missing contains "consent.status" if {
	not input.consent.status in {"granted", "absent", "expired", "revoked", "not_applicable"}
}

missing contains "consent.source" if {
	source := object.get(input.consent, "source", null)
	not source in {null, "self_service", "operator_attested"}
}

missing contains "approval.class" if {
	input.approval.present == true
	not input.approval.class in {"standard", "exception"}
}

missing contains "approval.scope_type" if {
	input.approval.present == true
	not input.approval.scope_type in {"key", "user", "team", "org"}
}

missing contains "approval.id" if {
	input.approval.present == true
	not valid_text(input.approval.id)
}

missing contains "approval.expires_in_days" if {
	input.approval.present == true
	not is_number(input.approval.expires_in_days)
}

missing contains "approval.conditions" if {
	input.approval.present == true
	not is_object(input.approval.conditions)
}

missing contains "approval.conditions.high_risk_tools" if {
	tools := object.get(conditions, "high_risk_tools", [])
	not valid_strings(tools)
}

missing contains "approval.conditions.require_consent" if {
	"require_consent" in object.keys(conditions)
	not valid_purpose
}

valid_purpose if {
	purpose := conditions.require_consent
	is_string(purpose)
	regex.match(`\S`, purpose)
	count(purpose) <= 128
}

# DS-166(POL-I-10 최소 구현): 승인 conditions.require_user_confirmation = {tools, purpose, display_fields}
missing contains "approval.conditions.require_user_confirmation" if {
	"require_user_confirmation" in object.keys(conditions)
	not valid_confirmation
}

valid_confirmation if {
	c := conditions.require_user_confirmation
	is_object(c)
	is_array(c.tools)
	count(c.tools) > 0
	valid_names(c.tools)
	is_string(c.purpose)
	regex.match(`\S`, c.purpose)
	count(c.purpose) <= 128
	valid_names(object.get(c, "display_fields", []))
}

# 공백이 아닌 문자가 있는 문자열만 이름으로 인정한다(빈 이름이 정상 도구 호출을 비켜 가지 못하게).
valid_names(values) if {
	is_array(values)
	every value in values {
		is_string(value)
		regex.match(`\S`, value)
	}
}

missing contains "approval.conditions.business_hours_only" if {
	value := object.get(conditions, "business_hours_only", false)
	not is_boolean(value)
}

missing contains "business_hours" if {
	object.get(conditions, "business_hours_only", false) == true
	not valid_hours
}

valid_hours if {
	is_object(hours)
	is_string(hours.tz)
	time.clock([input.time.ns, hours.tz])
	is_array(hours.days)
	count(hours.days) > 0
	every day in hours.days { is_number(day); day == floor(day); day >= 1; day <= 7}
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, hours.start)
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, hours.end)
	hours.start < hours.end
}

conditions := object.get(object.get(input, "approval", {}), "conditions", {})

applied contains "R1" if input.approval.present == false
applied contains "R2" if input.tool.name in input.settings.high_risk_tools
applied contains "R2" if input.tool.name in object.get(conditions, "high_risk_tools", [])

# 승인된 도구 계약의 위험 등급(정책 입력 tool.risk_grade)이 높으면 승인 조건과 무관하게 건다.
# 승인 조건의 high_risk_tools는 의무를 더하기만 한다.
applied contains "R2" if object.get(input.tool, "risk_grade", null) in {"high", "critical"}

applied contains "R3" if {
	object.get(conditions, "business_hours_only", false) == true
	not within_business_hours
}

applied contains "R4" if {
	purpose := object.get(conditions, "require_consent", "")
	is_string(purpose)
	purpose != ""
	input.consent.status != "granted"
}

# 2단계 정책(규칙 ID는 정본 번호). 모두 Block이고 카탈로그에서 observable이다.
pattern_rules := {
	"POL-E-07": "url_external",
	"POL-E-09": "path_traversal",
	"POL-E-14": "private_host",
}

# 계약 관리 서버(`server.contract_status == "managed"`)에만 판정한다.
managed if input.server.contract_status == "managed"

applied contains id if {
	managed
	some id, name in pattern_rules
	object.get(input.arguments, ["patterns", name], false) == true
}

# POL-E-08(전송 범위)·POL-E-15(정의되지 않은 항목): 승인 conditions.allowed_arg_keys 밖의 인자 키.
applied contains id if {
	managed
	some id in {"POL-E-08", "POL-E-15"}
	keys := conditions.allowed_arg_keys
	allowed := {key | some key in keys}
	count({key | some key in input.arguments.keys} - allowed) > 0
}

# POL-R-18·POL-R-20(로컬 실행 서버). 호출 때 실행 정의를 승인본과 대조하며 서버 시작은 통제하지 않는다.
# exec_approved_sha256은 서버 행의 승인된 실행 계약 해시, exec_contract_sha256은 단말이 보고한 계약을
# MINT가 계산한 해시이다. 일치 여부는 두 해시를 여기서 비교하고 단말의 참/거짓은 받지 않는다.
stdio_server if input.server.identity_kind == "stdio"

# 승인된 실행 계약이 없는 로컬 서버는 어떤 실행 정의로도 호출할 수 없다(POL-R-18).
exec_approved if {
	input.server.status == "approved"
	valid_sha256(object.get(input.server, "exec_approved_sha256", null))
}

applied contains "POL-R-18" if {
	stdio_server
	not exec_approved
}

# 실행 파일 위치·인자·작업 디렉터리·환경 값이 승인된 실행 계약과 다르면 막는다(POL-R-20).
applied contains "POL-R-20" if {
	stdio_server
	exec_approved
	input.server.exec_contract_sha256 != input.server.exec_approved_sha256
}

hours := object.get(conditions, "business_hours", data.mint.business_hours)

within_business_hours if {
	weekday := time.weekday([input.time.ns, hours.tz])
	day := {
		"Monday": 1, "Tuesday": 2, "Wednesday": 3, "Thursday": 4,
		"Friday": 5, "Saturday": 6, "Sunday": 7,
	}[weekday]
	day in hours.days
	clock := time.clock([input.time.ns, hours.tz])
	current := (clock[0] * 60) + clock[1]
	start := split(hours.start, ":")
	end := split(hours.end, ":")
	current >= (to_number(start[0]) * 60) + to_number(start[1])
	current < (to_number(end[0]) * 60) + to_number(end[1])
}

block_ids := {"R1", "R3", "POL-E-07", "POL-E-08", "POL-E-09", "POL-E-14", "POL-E-15", "POL-R-18", "POL-R-20"}
block_observable := {id: true | some id in block_ids}
block_rules := {id | some id in block_ids; id in applied}

default verdict := "Allow"

verdict := "Block" if count(block_rules) > 0

else := "RequireApproval" if "R2" in applied

decision_ids := sort([id | some id in block_rules]) if {
	verdict == "Block"
} else := ["R2"] if {
	verdict == "RequireApproval"
} else := []

observable if {
	count(block_rules) > 0
	every id in block_rules { block_observable[id] == true }
}

default observable := false

call_approval_obligations := [{"type": "require_call_approval"}] if {
	"R2" in applied
} else := []

consent_obligations := [{"type": "require_consent", "purpose": conditions.require_consent}] if {
	"R4" in applied
} else := []

# 호출 도구가 승인 조건의 확인 대상 도구 목록에 있으면 본인 확인 의무를 낸다. 판정은 바꾸지 않는다.
confirmation_obligations := [{
	"type": "require_user_confirmation",
	"purpose": c.purpose,
	"display_fields": object.get(c, "display_fields", []),
}] if {
	c := object.get(conditions, "require_user_confirmation", null)
	valid_confirmation
	input.tool.name in c.tools
} else := []

obligations := array.concat(
	array.concat(call_approval_obligations, consent_obligations),
	confirmation_obligations,
)

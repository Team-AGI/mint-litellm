"""호출 주체 신원 모델과 조직 유도 규칙."""

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from mint_litellm.types.frozen import FrozenDict


class PrincipalType(StrEnum):
    USER = "user"
    TEAM_KEY = "team_key"
    SERVICE_ACCOUNT = "service_account"
    ANONYMOUS = "anonymous"
    MASTER_KEY = "master_key"


class Provenance(StrEnum):
    VERIFIED_BY_LITELLM = "verified_by_litellm"
    CLAIMED_BY_CALLER = "claimed_by_caller"
    DERIVED = "derived"


class OrgSource(StrEnum):
    TEAM = "team"
    USER = "user"
    DEFAULT = "default"


class SubjectType(StrEnum):
    TEAM = "team"
    USER = "user"


class OrgStatus(StrEnum):
    ACTIVE = "active"
    CLOSED = "closed"


class Principal(BaseModel):
    """판정 대상 호출의 주체.

    ``principal_id``는 사용자 키에서는 ``user_id``, 팀·서비스 계정 키에서는 ``key_id``이다.
    ``claimed_end_user_id``는 호출자가 주장한 값이라 범위 축소에만 쓰고, 승인·동의의 주체로
    쓰지 않는다. ``org_id``는 MINT 조직 범위이며 LiteLLM 조직이 아니다.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    instance_id: str
    principal_type: PrincipalType
    principal_id: str | None = None
    key_id: str | None = None
    org_id: str | None = None
    org_source: OrgSource | None = None
    team_id: str | None = None
    claimed_end_user_id: str | None = None
    provenance: dict[str, Provenance] = {}

    @field_validator("provenance", mode="after")
    @classmethod
    def _freeze_provenance(cls, value: dict[str, "Provenance"]) -> FrozenDict:
        return FrozenDict(value)

    @property
    def user_id(self) -> str | None:
        return self.principal_id if self.principal_type is PrincipalType.USER else None

    @model_validator(mode="after")
    def _consistent(self) -> "Principal":
        kind = self.principal_type
        if kind is PrincipalType.USER and self.principal_id is None:
            raise ValueError("user principal requires principal_id")
        if kind in (PrincipalType.TEAM_KEY, PrincipalType.SERVICE_ACCOUNT):
            if self.key_id is None or self.principal_id != self.key_id or self.team_id is None:
                raise ValueError(f"{kind.value} principal requires key_id, team_id and id==key")
        if kind is PrincipalType.ANONYMOUS and self.principal_id is not None:
            raise ValueError("anonymous principal has no principal_id")
        if (self.org_id is None) != (self.org_source is None):
            raise ValueError("org_id and org_source are set together")
        if self.claimed_end_user_id is not None and (
            self.provenance.get("claimed_end_user_id") is not Provenance.CLAIMED_BY_CALLER
        ):
            raise ValueError("claimed_end_user_id must be marked claimed_by_caller")
        if self.org_id is not None and self.provenance.get("org_id") is not Provenance.DERIVED:
            raise ValueError("org_id must be marked derived")
        return self


def is_service_account_marker(
    user_id: str | None, team_id: str | None, metadata: Mapping[str, Any] | None
) -> bool:
    """서비스 계정 표식: 사용자 없음, 팀 있음, 메타데이터에 service_account_id.

    일반 키 생성으로도 같은 표식을 만들 수 있으므로 표식만으로는 서비스 계정의 증명이 아니다.
    """
    return (
        user_id is None
        and team_id is not None
        and (metadata or {}).get("service_account_id") is not None
    )


def classify_principal(
    *,
    instance_id: str,
    key_id: str | None,
    user_id: str | None,
    team_id: str | None,
    metadata: Mapping[str, Any] | None,
    is_master_key: bool,
    claimed_end_user_id: str | None = None,
    keyless_verified: bool = False,
) -> Principal:
    """LiteLLM이 검증한 키 정보로 주체를 분류한다. 조직은 ``with_org``로 따로 채운다.

    키가 없거나 사용자도 팀도 없는 키는 신원을 확정할 수 없어 익명으로 다룬다(항상 차단).
    예외는 LiteLLM이 직접 검증한 키 없는 주체(JWT, 관리형 에이전트, 게이트웨이 입장 사용자)이며
    ``keyless_verified``일 때 ``user_id``가 있으면 그 사용자로 다룬다(``key_id``는 없다).
    """
    provenance: dict[str, Provenance] = {}
    if claimed_end_user_id is not None:
        provenance["claimed_end_user_id"] = Provenance.CLAIMED_BY_CALLER
    verified = Provenance.VERIFIED_BY_LITELLM
    common: dict[str, Any] = {
        "instance_id": instance_id,
        "claimed_end_user_id": claimed_end_user_id,
    }

    if is_master_key:
        return Principal(
            principal_type=PrincipalType.MASTER_KEY,
            key_id=key_id,
            provenance={**provenance, "key_id": verified},
            **common,
        )
    if key_id is None and keyless_verified and user_id is not None:
        if team_id is not None:
            provenance["team_id"] = verified
        return Principal(
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            team_id=team_id,
            provenance={**provenance, "principal_id": verified},
            **common,
        )
    if key_id is None or (user_id is None and team_id is None):
        return Principal(principal_type=PrincipalType.ANONYMOUS, provenance=provenance, **common)

    provenance["key_id"] = verified
    if team_id is not None:
        provenance["team_id"] = verified
    if user_id is not None:
        return Principal(
            principal_type=PrincipalType.USER,
            principal_id=user_id,
            key_id=key_id,
            team_id=team_id,
            provenance={**provenance, "principal_id": verified},
            **common,
        )
    kind = (
        PrincipalType.SERVICE_ACCOUNT
        if is_service_account_marker(user_id, team_id, metadata)
        else PrincipalType.TEAM_KEY
    )
    return Principal(
        principal_type=kind,
        principal_id=key_id,
        key_id=key_id,
        team_id=team_id,
        provenance={**provenance, "principal_id": verified},
        **common,
    )


class OrgDerivation(BaseModel):
    model_config = ConfigDict(frozen=True)

    org_id: str | None
    source: OrgSource | None


def derive_org(
    *,
    team_id: str | None,
    user_id: str | None,
    bindings: Mapping[tuple[SubjectType, str], str],
    default_org_id: str | None,
    org_status: Mapping[str, OrgStatus],
) -> OrgDerivation:
    """주체의 MINT 조직을 유도한다.

    팀이 있으면 팀 바인딩만 보고 사용자 바인딩은 보지 않는다. 팀이 없고 사용자가 있으면
    사용자 바인딩을 본다. 바인딩이 없으면 기본 조직을 쓴다. 정해진 조직이 없거나 닫혀 있으면
    조직 없음(``org_id=None``)이며 호출은 조직 경계 사유로 차단된다. 바인딩이 가리키는 조직이
    닫혀 있을 때 기본 조직으로 대체하지 않는다.
    """
    org_id: str | None = None
    source: OrgSource | None = None
    if team_id is not None:
        org_id = bindings.get((SubjectType.TEAM, team_id))
        source = OrgSource.TEAM
    elif user_id is not None:
        org_id = bindings.get((SubjectType.USER, user_id))
        source = OrgSource.USER
    if org_id is None:
        org_id, source = default_org_id, OrgSource.DEFAULT
    if org_id is None or org_status.get(org_id) is not OrgStatus.ACTIVE:
        return OrgDerivation(org_id=None, source=None)
    return OrgDerivation(org_id=org_id, source=source)


def with_org(principal: Principal, derivation: OrgDerivation) -> Principal:
    """유도한 조직을 주체에 반영한다. 출처는 ``derived``로 표시된다."""
    provenance = dict(principal.provenance)
    if derivation.org_id is None:
        provenance.pop("org_id", None)
    else:
        provenance["org_id"] = Provenance.DERIVED
    provenance = FrozenDict(provenance)
    return principal.model_copy(
        update={
            "org_id": derivation.org_id,
            "org_source": derivation.source,
            "provenance": provenance,
        }
    )

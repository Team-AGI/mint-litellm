"""직원 가입 요청의 LiteLLM 계정을 작업 실행기에서 만든다.

가입 때 받은 비밀번호는 승인 전까지 암호문(``password_sealed``)으로만 두고, 승인되면 LiteLLM
초대를 만들어 그 비밀번호로 확정한 뒤 지운다. 거절되면 콘솔이 지운다.
"""

import base64
import hashlib
import json
import os
import secrets
import urllib.error
import urllib.request
from urllib.parse import quote

from mint_litellm.control.db.connection import fetchone

_LABEL = b"mint-signup-password\0"


class SignupError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _key() -> bytes:
    # ponytail: 내보내기 서명 키에서 용도를 나눠 만든다. 키를 바꾸면 대기 중인 가입은 실패로 남고
    # 다시 요청해야 한다. 잦아지면 전용 키를 둔다.
    secret = os.environ.get("MINT_EXPORT_HMAC_KEY", "")
    if not secret:
        raise SignupError("seal_key_missing")
    return hashlib.sha256(_LABEL + secret.encode()).digest()


def seal(instance_id: str, request_id: str, password: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    aad = f"{instance_id}:{request_id}".encode()
    return nonce + AESGCM(_key()).encrypt(nonce, password.encode(), aad)


def unseal(instance_id: str, request_id: str, sealed: bytes) -> str:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        plain = AESGCM(_key()).decrypt(
            bytes(sealed[:12]), bytes(sealed[12:]), f"{instance_id}:{request_id}".encode())
    except InvalidTag:
        raise SignupError("seal_unreadable") from None
    return plain.decode()


def _call(base: str, method: str, path: str, body=None, bearer=None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(base.rstrip("/") + path, data, headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as reply:  # noqa: S310  # 설정된 LiteLLM 주소
            return reply.status, json.loads(reply.read() or b"{}")
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read() or b"{}")
        except ValueError:
            return error.code, {}
    except OSError:
        raise SignupError("litellm_unreachable") from None


def claim(base: str, invitation: str, password: str) -> None:
    """LiteLLM 초대를 확정해 비밀번호를 정한다(``/onboarding/get_token`` → ``claim_token``)."""
    status, body = _call(base, "GET", "/onboarding/get_token?invite_link=" + quote(invitation))
    if status != 200 or not isinstance(body.get("token"), str):
        raise SignupError(f"claim_http_{status}")
    try:
        part = body["token"].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (IndexError, ValueError):
        raise SignupError("claim_token_unreadable") from None
    status, body = _call(
        base, "POST", "/onboarding/claim_token",
        {"invitation_link": invitation, "user_id": claims.get("user_id"), "password": password},
        bearer=claims.get("key"),
    )
    if status != 200:
        text = json.dumps(body).lower()
        raise SignupError("password_policy" if status == 400 or "password" in text
                          else f"claim_http_{status}")


def run(job):
    row = fetchone(
        job.conn, "SELECT * FROM mint.signup_requests WHERE instance_id = %s AND id = %s"
        " AND status = 'pending' AND decided_at IS NOT NULL",
        (job.instance_id, job.job["target_ref"]),
    )
    if not row:
        return
    if job.litellm is None:
        raise SignupError("litellm_unavailable")
    client = job.litellm.with_hook(job.external_write)
    user_id = row["litellm_user_id"]
    if not user_id:
        users = client.list_users()
        matches = [u for u in users if (u.get("user_email") or "").casefold()
                   == row["email"].casefold() and u.get("user_id")]
        if len(matches) > 1:
            raise SignupError("duplicate_user")
        if matches:
            user_id = matches[0]["user_id"]
        else:
            result = client._write("POST", "/user/new", {
                "user_email": row["email"], "user_alias": row["display_name"],
                "user_role": "internal_user_viewer", "auto_create_key": False,
                "send_invite_email": False,
            })
            user_id = result.get("user_id") if isinstance(result, dict) else None
            if not isinstance(user_id, str) or not user_id:
                raise SignupError("missing_user_id")
        job.conn.execute(
            "UPDATE mint.signup_requests SET litellm_user_id = %s"
            " WHERE instance_id = %s AND id = %s",
            (user_id, job.instance_id, row["id"]),
        )
    result = client._write("POST", "/invitation/new", {"user_id": user_id})
    invitation = result.get("id") if isinstance(result, dict) else None
    if not isinstance(invitation, str) or not invitation:
        raise SignupError("missing_invitation_id")
    if row["password_sealed"] is not None:
        claim(client.base_url, invitation,
              unseal(job.instance_id, str(row["id"]), row["password_sealed"]))
    job.conn.execute(
        "UPDATE mint.signup_requests SET status = 'approved', invitation_id = %s,"
        " password_sealed = NULL, last_error = NULL"
        " WHERE instance_id = %s AND id = %s AND status = 'pending'",
        (invitation, job.instance_id, row["id"]),
    )


def record_failure(conn, instance_id, request_id, code, job_status):
    conn.execute(
        "UPDATE mint.signup_requests SET last_error = %s, status = %s,"
        " password_sealed = CASE WHEN %s = 'failed' THEN NULL ELSE password_sealed END"
        " WHERE instance_id = %s AND id = %s AND status = 'pending'",
        (code, "failed" if job_status == "failed" else "pending", job_status, instance_id,
         request_id),
    )


def login_hint(conn, instance_id: str, email: str) -> str | None:
    """로그인에 실패한 이메일의 가장 최근 가입 요청 상태를 직원이 읽을 문장으로."""
    row = fetchone(
        conn, "SELECT status, reason FROM mint.signup_requests WHERE instance_id = %s"
        " AND lower(email) = lower(%s) ORDER BY requested_at DESC LIMIT 1",
        (instance_id, email.strip()),
    )
    if row is None or row["status"] == "approved":
        return None
    if row["status"] == "pending":
        return ("가입 승인 대기 중입니다. 관리자가 승인하면 이 이메일과 비밀번호로 로그인할 수"
                " 있습니다.")
    if row["status"] == "rejected":
        return "가입 요청이 거절되었습니다." + (f" 사유: {row['reason']}" if row["reason"] else "")
    return "계정을 만들지 못했습니다. 관리자에게 문의하거나 다시 가입 요청하십시오."

"""직원 가입 요청의 LiteLLM 계정과 초대를 작업 실행기에서 만든다."""

from mint_litellm.control.db.connection import fetchone


class SignupError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


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
    job.conn.execute(
        "UPDATE mint.signup_requests SET status = 'approved', invitation_id = %s, last_error = NULL"
        " WHERE instance_id = %s AND id = %s AND status = 'pending'",
        (invitation, job.instance_id, row["id"]),
    )


def record_failure(conn, instance_id, request_id, code, job_status):
    conn.execute(
        "UPDATE mint.signup_requests SET last_error = %s, status = %s"
        " WHERE instance_id = %s AND id = %s AND status = 'pending'",
        (code, "failed" if job_status == "failed" else "pending", instance_id, request_id),
    )

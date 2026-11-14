"""작업 ``config_secret_scan``: LiteLLM 설정 파일에 평문으로 적힌 비밀을 경보로 알린다.

LiteLLM의 DB는 읽지 않고, 프록시가 읽는 설정 파일만 본다. 평문 비밀이 있으면 경보
``config_plaintext_secret``을 열고(항목 경로만 담는다, 값은 담지 않는다), 없으면 닫는다. 설정 파일이
이 프로세스에서 보이지 않으면 아무것도 하지 않는다. 로그 파일의 비밀은 보지 못한다.
"""

from mint_litellm.control import alerts, litellm_config
from mint_litellm.types.events import AlertKind
from mint_litellm.types.plaintext_secrets import plaintext_secret_paths

KIND = AlertKind.CONFIG_PLAINTEXT_SECRET.value
SUBJECT_PATHS = 20


def run(job) -> None:
    path = getattr(job.settings, "litellm_config", None)
    if path is None or not path.is_file():
        return
    paths = plaintext_secret_paths(litellm_config.load_effective(path))
    with job.conn.transaction():
        if paths:
            alerts.raise_alert(
                job.conn,
                job.instance_id,
                kind=KIND,
                severity="medium",
                dedup_key=KIND,
                subject={"count": len(paths), "paths": paths[:SUBJECT_PATHS]},
            )
        else:
            alerts.resolve(job.conn, job.instance_id, KIND)

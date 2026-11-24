# 신청 소스 검사기(코드 Semgrep·비밀 Gitleaks·취약점/설정/라이선스 Trivy). 정책 집행·작업 실행기와 파일시스템을
# 나누려고 따로 둔다. 빌드 때 도구가 실행되는지 확인해, 깨진 도구가 검사 실패로 숨지 않게 한다.
FROM zricethezav/gitleaks:v8.30.1 AS secrets
FROM python:3.12-slim
COPY --from=secrets /usr/bin/gitleaks /usr/local/bin/gitleaks
ARG TRIVY_VERSION=0.74.0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SEMGREP_SEND_METRICS=off TRIVY_CACHE_DIR=/trivy-cache
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
       | tar -xz -C /usr/local/bin trivy \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "semgrep==1.172.0" \
    && semgrep --version >/dev/null && gitleaks version >/dev/null && trivy --version >/dev/null
# 작업 실행기와 같은 사용자(65532)라야 공유 볼륨의 요청 폴더에 결과를 쓸 수 있다.
# 취약점 DB 캐시 볼륨(scancache)도 같은 사용자가 쓴다.
RUN mkdir -p /scan /packs /trivy-cache && chown 65532:65532 /scan /trivy-cache
COPY scan.py /opt/mint/scan.py
COPY semgrep-mcp.yml gitleaks.toml /opt/mint/rules/
ENV HOME=/tmp XDG_CACHE_HOME=/tmp
USER 65532:65532
CMD ["python", "/opt/mint/scan.py"]

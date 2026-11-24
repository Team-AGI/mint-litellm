# 신청 소스 검사기(코드 검사 Semgrep·비밀 검사 Gitleaks). 정책 집행·작업 실행기와 파일시스템을
# 나누려고 따로 둔다. 빌드 때 두 도구가 실행되는지 확인해, 깨진 도구가 검사 실패로 숨지 않게 한다.
FROM zricethezav/gitleaks:v8.30.1 AS secrets
FROM python:3.12-slim
COPY --from=secrets /usr/bin/gitleaks /usr/local/bin/gitleaks
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SEMGREP_SEND_METRICS=off
RUN pip install --no-cache-dir "semgrep==1.172.0" \
    && semgrep --version >/dev/null && gitleaks version >/dev/null
# 작업 실행기와 같은 사용자(65532)라야 공유 볼륨의 요청 폴더에 결과를 쓸 수 있다.
RUN mkdir -p /scan /packs && chown 65532:65532 /scan
COPY scan.py /opt/mint/scan.py
COPY semgrep-mcp.yml gitleaks.toml /opt/mint/rules/
ENV HOME=/tmp XDG_CACHE_HOME=/tmp
USER 65532:65532
CMD ["python", "/opt/mint/scan.py"]

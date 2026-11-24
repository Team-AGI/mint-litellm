#!/bin/sh
# 하루가 지났거나 콘솔의 「지금 백업」 요청이 마지막 백업보다 새로우면 두 데이터베이스를
# backups/<시각>/에 덤프하고, 최신 BACKUP_KEEP개만 남긴다. 1분마다 확인한다.
# 하나라도 비면 그 폴더를 지우고 한 시간 뒤 다시 시도한다.
root="${BACKUP_DIR:-/backups}"
keep="${BACKUP_KEEP:-7}"
retry_at=0
requested() {
    psql -h postgres -U postgres -d mint -tAc \
        "SELECT coalesce(extract(epoch FROM max(marked_at))::bigint, 0) FROM mint.setup_marks WHERE mark = 'backup_requested'" \
        2>/dev/null || echo 0
}
while :; do
    newest=$(ls -1d "$root"/[0-9]*T*Z 2>/dev/null | sort | tail -n 1)
    last=0
    [ -n "$newest" ] && last=$(stat -c %Y "$newest")
    now=$(date +%s)
    asked=$(requested)
    if [ "$asked" -gt "$last" ] && [ "$asked" -gt "$retry_at" ] \
        || { [ $((now - last)) -ge 86400 ] && [ "$now" -ge "$retry_at" ]; }; then
        dir="$root/$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "$dir"
        ok=1
        for db in mint litellm; do
            pg_dump -h postgres -U postgres -d "$db" > "$dir/$db.sql" && [ -s "$dir/$db.sql" ] || ok=0
        done
        if [ "$ok" = 1 ]; then
            ls -1d "$root"/[0-9]*T*Z | sort | head -n "-$keep" | xargs -r rm -rf
        else
            rm -rf "$dir"
            retry_at=$((now + 3600))
            echo "백업에 실패했습니다. 한 시간 뒤 다시 시도합니다." >&2
        fi
    fi
    sleep 60 || exit 0
done

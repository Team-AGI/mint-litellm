#!/bin/sh
# 하루가 지났으면 두 데이터베이스를 backups/<시각>/에 덤프하고, 최신 BACKUP_KEEP개만 남긴다.
# 하나라도 비면 그 폴더를 지우고 한 시간 뒤 다시 시도한다.
root="${BACKUP_DIR:-/backups}"
keep="${BACKUP_KEEP:-7}"
while :; do
    wait=3600
    if [ -z "$(find "$root" -maxdepth 1 -name '[0-9]*T*Z' -mmin -1440 2>/dev/null)" ]; then
        dir="$root/$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "$dir"
        ok=1
        for db in mint litellm; do
            pg_dump -h postgres -U postgres -d "$db" > "$dir/$db.sql" && [ -s "$dir/$db.sql" ] || ok=0
        done
        if [ "$ok" = 1 ]; then
            wait=86400
            ls -1d "$root"/[0-9]*T*Z | sort | head -n "-$keep" | xargs -r rm -rf
        else
            rm -rf "$dir"
            echo "백업에 실패했습니다. 한 시간 뒤 다시 시도합니다." >&2
        fi
    fi
    sleep "$wait" || exit 0
done

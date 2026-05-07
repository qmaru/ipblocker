#!/bin/bash

LOGS_PATH="/var/log/nginx"
ACCESS_LOG="${LOGS_PATH}/access.log"
ARCHIVE_DIR="${LOGS_PATH}/archive_access"

mkdir -p "$ARCHIVE_DIR"

if [[ -f "$ACCESS_LOG" ]]; then
	yesterday=$(date +"%F" -d "-1 days")
	ARCHIVE_FILE="${ARCHIVE_DIR}/access-${yesterday}.log.gz"
	gzip -c "$ACCESS_LOG" >"$ARCHIVE_FILE"
	: >"$ACCESS_LOG"
	/usr/local/nginx/sbin/nginx -s reload
fi

find "$ARCHIVE_DIR" -name "access-*.log.gz" -mtime +30 -delete

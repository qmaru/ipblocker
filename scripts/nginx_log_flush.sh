#!/bin/bash

LOGS_PATH="/var/log/nginx"
ACCESS_LOG="${LOGS_PATH}/access.log"

if [[ -f "$ACCESS_LOG" ]]; then
    yesterday=$(date +"%F" -d "-1 days")
    mv "$ACCESS_LOG" "${LOGS_PATH}/access-${yesterday}.log"
    gzip "${LOGS_PATH}/access-${yesterday}.log"
    /usr/local/nginx/sbin/nginx -s reload
fi

find "$LOGS_PATH" -name "access-*.log.gz" -mtime +30 -delete

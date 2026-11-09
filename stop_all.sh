#!/usr/bin/env bash
# Останавливает все сервисы.
cd "$(dirname "$0")"
for f in logs/*.pid; do
  [ -e "$f" ] || continue
  pid=$(cat "$f")
  if kill "$pid" 2>/dev/null; then
    echo "остановлен $(basename "$f" .pid) (pid $pid)"
  fi
  rm -f "$f"
done

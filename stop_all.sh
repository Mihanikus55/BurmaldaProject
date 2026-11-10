#!/usr/bin/env bash
# Останавливает все сервисы проекта.
#
# Сначала по pid-файлам, которые оставил run_all.sh. Потом на всякий случай
# подчищает порты: если запускали вручную или pid-файлы потерялись, процессы
# всё равно останутся висеть и в следующий раз порт будет занят.

cd "$(dirname "$0")"
PORTS="8001 8002 8003 8004 8005 ${UI_PORT:-8090}"

# 1. по pid-файлам
for f in logs/*.pid; do
  [ -e "$f" ] || continue
  pid=$(cat "$f")
  if kill "$pid" 2>/dev/null; then
    echo "остановлен $(basename "$f" .pid) (pid $pid)"
  fi
  rm -f "$f"
done

sleep 0.4

# 2. подчистка по портам
if command -v lsof > /dev/null 2>&1; then
  for p in $PORTS; do
    pids=$(lsof -ti tcp:"$p" 2>/dev/null)
    for pid in $pids; do
      kill -9 "$pid" 2>/dev/null && echo "добит процесс на порту $p (pid $pid)"
    done
  done
elif command -v fuser > /dev/null 2>&1; then
  for p in $PORTS; do
    fuser -k "$p"/tcp > /dev/null 2>&1 && echo "освобождён порт $p"
  done
fi

# 3. что осталось
busy=""
for p in $PORTS; do
  if command -v lsof > /dev/null 2>&1 && lsof -ti tcp:"$p" > /dev/null 2>&1; then
    busy="$busy $p"
  fi
done

if [ -n "$busy" ]; then
  echo "Внимание: порты всё ещё заняты:$busy"
else
  echo "Все порты свободны."
fi

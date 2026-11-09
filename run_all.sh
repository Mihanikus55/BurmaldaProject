#!/usr/bin/env bash
# Поднимает все сервисы. Каждый — отдельный процесс со своей базой.
#
#   8001  client_app   телефон клиента
#   8002  burmalda     центр Бурмалда
#   8003  bookmaker    БК Альфа
#   8005  bookmaker    БК Бета   (тот же файл, другой BOOKMAKER_ID и своя база)
#   8004  regulator    регулятор
#
# Логи каждого сервиса — в logs/<имя>.log

set -e
cd "$(dirname "$0")"
mkdir -p logs data

start() {  # start <имя> <модуль> <порт> [env...]
  local name=$1 module=$2 port=$3; shift 3
  env "$@" python3 -m uvicorn "$module:app" --host 127.0.0.1 --port "$port" \
    > "logs/$name.log" 2>&1 &
  echo "$!" > "logs/$name.pid"
  printf '  %-12s :%s  pid %s\n' "$name" "$port" "$(cat logs/$name.pid)"
}

echo "Поднимаю сервисы:"
start regulator  services.regulator  8004
start burmalda   services.burmalda   8002
start bk_alpha   services.bookmaker  8003 BOOKMAKER_ID=bk_alpha
start bk_beta    services.bookmaker  8005 BOOKMAKER_ID=bk_beta
start client     services.client_app 8001

# интерфейс — обычная статика, никакой логики в нём нет
python3 -m http.server 8090 --directory ui --bind 127.0.0.1 > logs/ui.log 2>&1 &
echo "$!" > logs/ui.pid
printf '  %-12s :%s  pid %s\n' "ui" 8090 "$(cat logs/ui.pid)"

echo
echo "Ждём, пока поднимутся..."
for port in 8001 8002 8003 8004 8005; do
  for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:$port/" > /dev/null 2>&1; then
      echo "  :$port готов"; break
    fi
    sleep 0.25
  done
done

echo
echo "Интерфейс:                 http://127.0.0.1:8090"
echo "Сквозной прогон в консоли: python3 demo.py"
echo "Остановить:                ./stop_all.sh"

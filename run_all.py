"""
Поднимает все сервисы проекта. Работает и на Windows, и на macOS, и на Linux.

    python run_all.py               поднять всё
    python run_all.py --ui-port 9100   если 8090 занят
    python run_all.py --fresh       сначала удалить базы, начать с чистого листа

Останавливать:  python stop_all.py

Что поднимается:
    8001  client_app   телефон клиента
    8002  burmalda     центр Бурмалда
    8003  bookmaker    БК Альфа
    8005  bookmaker    БК Бета
    8004  regulator    регулятор
    8090  интерфейс    статическая страница

Логи каждого процесса — в logs/<имя>.log. Если что-то не поднялось,
смотреть туда: там будет видно, занят ли порт и не упал ли импорт.
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOGS = ROOT / "logs"


def port_busy(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def start(name: str, args: list[str], env_extra: dict | None = None):
    LOGS.mkdir(exist_ok=True)
    log = open(LOGS / f"{name}.log", "w", encoding="utf-8")
    env = {**os.environ, **(env_extra or {})}
    p = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, env=env)
    (LOGS / f"{name}.pid").write_text(str(p.pid))
    return p


def uvicorn(module: str, port: int) -> list[str]:
    return [sys.executable, "-m", "uvicorn", f"{module}:app",
            "--host", "127.0.0.1", "--port", str(port)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ui-port", type=int, default=int(os.getenv("UI_PORT", "8090")))
    ap.add_argument("--fresh", action="store_true", help="удалить базы перед запуском")
    a = ap.parse_args()

    if a.fresh:
        shutil.rmtree(ROOT / "data", ignore_errors=True)
        print("Базы удалены, начинаем с чистого листа.\n")

    services = [
        ("regulator", uvicorn("services.regulator", 8004), None, 8004),
        ("burmalda",  uvicorn("services.burmalda", 8002), None, 8002),
        ("bk_alpha",  uvicorn("services.bookmaker", 8003), {"BOOKMAKER_ID": "bk_alpha"}, 8003),
        ("bk_beta",   uvicorn("services.bookmaker", 8005), {"BOOKMAKER_ID": "bk_beta"}, 8005),
        ("client",    uvicorn("services.client_app", 8001), None, 8001),
    ]

    # проверяем порты заранее, иначе процесс упадёт молча
    taken = [p for _, _, _, p in services if port_busy(p)]
    if port_busy(a.ui_port):
        taken.append(a.ui_port)
    if taken:
        print(f"Порты уже заняты: {', '.join(map(str, taken))}")
        print("Сначала:  python stop_all.py")
        if a.ui_port in taken:
            print(f"Если {a.ui_port} держит чужая программа:  python run_all.py --ui-port 9100")
        sys.exit(1)

    print("Поднимаю сервисы:")
    for name, args, env, port in services:
        p = start(name, args, env)
        print(f"  {name:<12} :{port}  pid {p.pid}")

    ui = start("ui", [sys.executable, "-m", "http.server", str(a.ui_port),
                      "--directory", "ui", "--bind", "127.0.0.1"])
    print(f"  {'ui':<12} :{a.ui_port}  pid {ui.pid}")

    print("\nЖдём, пока поднимутся...")
    ok = True
    for name, _, _, port in services:
        for _ in range(60):
            if port_busy(port):
                print(f"  :{port} готов")
                break
            time.sleep(0.25)
        else:
            print(f"  :{port} НЕ ПОДНЯЛСЯ — смотри logs/{name}.log")
            ok = False

    print()
    print(f"Интерфейс (защита):    http://127.0.0.1:{a.ui_port}")
    print(f"Интерфейс (подробный): http://127.0.0.1:{a.ui_port}/detail.html")
    print("Прогон в консоли:      python demo.py")
    print("Остановить:            python stop_all.py")
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()

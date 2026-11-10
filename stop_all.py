"""
Останавливает все сервисы проекта. Работает и на Windows, и на macOS, и на Linux.

    python stop_all.py              остановить сервисы
    python stop_all.py --clean      остановить и удалить базы (папку data)

Сначала гасит процессы по pid-файлам, которые оставил run_all.sh. Потом
проверяет порты и добивает всё, что на них ещё висит, — это нужно, когда
сервисы запускали вручную в отдельных окнах и pid-файлов нет.
"""

import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PORTS = [8001, 8002, 8003, 8004, 8005, int(os.getenv("UI_PORT", "8090"))]
WINDOWS = platform.system() == "Windows"


def port_busy(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def kill(pid: int) -> bool:
    """Убить процесс по его номеру."""
    try:
        if WINDOWS:
            r = subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"],
                               capture_output=True, text=True)
            return r.returncode == 0
        os.kill(pid, 15)
        time.sleep(0.3)
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
        return True
    except Exception:
        return False


def pids_on_port(port: int) -> list[int]:
    """Кто занимает порт. На Windows — через netstat, иначе — через lsof."""
    found = set()
    try:
        if WINDOWS:
            out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
            for line in out.splitlines():
                if f":{port} " in line and "LISTENING" in line.upper():
                    m = re.search(r"(\d+)\s*$", line.strip())
                    if m:
                        found.add(int(m.group(1)))
        else:
            out = subprocess.run(["lsof", "-ti", f"tcp:{port}"],
                                 capture_output=True, text=True).stdout
            found.update(int(x) for x in out.split())
    except FileNotFoundError:
        pass
    return sorted(found)


def main():
    stopped = 0

    # 1. по pid-файлам
    logs = ROOT / "logs"
    if logs.is_dir():
        for f in sorted(logs.glob("*.pid")):
            try:
                pid = int(f.read_text().strip())
            except ValueError:
                f.unlink(missing_ok=True)
                continue
            if kill(pid):
                print(f"  остановлен {f.stem} (pid {pid})")
                stopped += 1
            f.unlink(missing_ok=True)

    time.sleep(0.5)

    # 2. добиваем всё, что ещё держит порты
    for port in PORTS:
        for pid in pids_on_port(port):
            if kill(pid):
                print(f"  добит процесс на порту {port} (pid {pid})")
                stopped += 1

    time.sleep(0.5)

    # 3. что осталось
    busy = [p for p in PORTS if port_busy(p)]
    if busy:
        print(f"\nПорты всё ещё заняты: {', '.join(map(str, busy))}")
        print("Если это чужая программа (например, Tomcat на 8080) — так и должно быть.")
    else:
        print("\nВсе порты свободны." if stopped else "\nНечего останавливать, всё уже выключено.")

    # 4. по просьбе — снести базы
    if "--clean" in sys.argv:
        data = ROOT / "data"
        if data.is_dir():
            shutil.rmtree(data, ignore_errors=True)
            print("Базы удалены: папка data снесена, создастся заново при запуске.")
        else:
            print("Папки data нет, удалять нечего.")


if __name__ == "__main__":
    main()

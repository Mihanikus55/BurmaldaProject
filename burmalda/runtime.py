import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from .crypto import load_keys, public_keys

ROLES = ("cupis", "wallet", "arbiter", "bookmaker_alpha", "bookmaker_beta", "recipient", "disclosure")


class DemoCluster:
    def __init__(self, root, service_base=5101):
        self.root = Path(root).resolve()
        self.service_base = service_base
        self.processes, self.logs = [], []
        self.registry = {}

    def start(self):
        self.root.mkdir(parents=True, exist_ok=True)
        for index, role in enumerate(("observer", *ROLES)):
            signing, encryption = load_keys(self.root / role)
            self.registry[role] = {**public_keys(signing, encryption), "url": f"http://127.0.0.1:{self.service_base + index - 1}" if role != "observer" else "local-observer"}
        (self.root / "public_registry.json").write_text(json.dumps(self.registry, indent=2), encoding="utf-8")
        try:
            for role in ROLES:
                log = (self.root / role / "service.log").open("a", encoding="utf-8")
                self.logs.append(log)
                self.processes.append(subprocess.Popen([sys.executable, "-m", "burmalda.service", "--role", role, "--runtime", str(self.root)], cwd=Path(__file__).resolve().parents[1], stdout=log, stderr=log, env={**os.environ, "PYTHONUNBUFFERED": "1"}))
            deadline = time.monotonic() + 30
            for role in ROLES:
                while True:
                    if any(process.poll() is not None for process in self.processes):
                        raise RuntimeError("A role service failed to start; check the per-role service.log")
                    try:
                        with urllib.request.urlopen(self.registry[role]["url"] + "/health", timeout=1) as response:
                            if json.load(response)["role"] != role:
                                raise RuntimeError("Port occupied by another role")
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Role service startup timed out")
                        time.sleep(0.1)
            return self
        except Exception:
            self.stop()
            raise

    def stop(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in self.logs:
            log.close()

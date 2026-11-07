import json
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from burmalda.crypto import load_keys, sign
from burmalda.runtime import DemoCluster, ROLES
from burmalda.transport import ProtocolError, Transport


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    root = tmp_path_factory.mktemp("burmalda")
    sockets = []
    for port in range(18101, 18108):
        sock = socket.socket()
        sock.bind(("127.0.0.1", port))
        sockets.append(sock)
    for sock in sockets:
        sock.close()
    running = DemoCluster(root, 18101).start()
    try:
        yield running
    finally:
        running.stop()


def transport(cluster, role="observer"):
    signing, encryption = load_keys(cluster.root / role)
    return Transport(role, cluster.registry, signing, encryption)


def enroll(t, cid="test-client", name="Синтетический Клиент"):
    return t.call("wallet", "enroll", {"client_id": cid, "full_name": name, "passport": "DEMO-0000", "age": 25})


def request_disclosure(t, cid="test-client", fields=None):
    return t.call("cupis", "create_request", {"client_id": cid, "bookmaker": "bookmaker_alpha", "fields": fields or ["full_name"], "reason": "Демонстрационная проверка", "operation_id": uuid.uuid4().hex})["request_id"]


def test_complete_flow_and_role_boundaries(cluster):
    t = transport(cluster)
    enroll(t)
    enroll(t, "other-client", "Другой Синтетический")
    cupis = t.call("cupis", "state")
    assert len(cupis["clients"]) == 2
    assert "Синтетический Клиент" not in json.dumps(cupis, ensure_ascii=False)
    assert "DEMO-0000" not in json.dumps(cupis)
    aliases = cupis["clients"][0]["aliases"]
    assert aliases["bookmaker_alpha"] != aliases["bookmaker_beta"]
    probe = t.call("cupis", "probe", {"client_id": "test-client"})
    assert probe["decrypted"] is False
    with pytest.raises(ProtocolError, match="FORBIDDEN"):
        transport(cluster, "bookmaker_alpha").call("cupis", "state")
    with pytest.raises(ProtocolError, match="INVALID_AMOUNT"):
        t.call("wallet", "bet", {"client_id": "test-client", "bookmaker": "bookmaker_alpha", "event_id": "cup-final", "selection": "HOME_WIN", "stake": -100, "operation_id": "bad"})
    data = {"client_id": "test-client", "bookmaker": "bookmaker_alpha", "event_id": "cup-final", "selection": "HOME_WIN", "stake": 10000, "operation_id": "bet-one"}
    receipt = t.call("wallet", "bet", data)
    assert receipt == t.call("wallet", "bet", data)
    t.call("wallet", "bet", {**data, "event_id": "league-match", "operation_id": "bet-two"})
    result = t.call("bookmaker_alpha", "settle", {"event_id": "cup-final", "outcome": "HOME_WIN"})
    assert result["settled"] == 1
    states = t.call("bookmaker_alpha", "state")
    assert [b["status"] for b in states["bets"]] == ["WON", "ACCEPTED"]
    assert "client_id" not in json.dumps(states)
    before = t.call("recipient", "state")
    assert before["joined"][0]["identity"] is None
    rid = request_disclosure(t)
    result = t.call("wallet", "approve", {"request_id": rid})
    assert result == {"status": "COMPLETED", "version": 2, "old_key_rejected": True}
    recipient = t.call("recipient", "state")
    assert recipient["joined"][0]["identity"] == {"full_name": "Синтетический Клиент"}
    assert "DEMO-0000" not in json.dumps(recipient)
    state = t.call("cupis", "state")
    assert [c["archive"]["version"] for c in state["clients"]] == [2, 1]
    for role in ("cupis", "wallet", "arbiter"):
        shares = [s for s in t.call(role, "state")["shares"] if s["client_id"] == "test-client"]
        assert len(shares) == 1 and shares[0]["version"] == 2
    # A textual dump of CUPIS must not contain clear identity, foreign shares, or a full DEK.
    with sqlite3.connect(cluster.root / "cupis" / "store.sqlite3") as db:
        dump = "\n".join(db.iterdump())
    assert "Синтетический Клиент" not in dump and "DEMO-0000" not in dump
    assert '"value"' in dump  # only its own current share is present
    assert '"owner": "wallet"' not in dump and '"owner": "arbiter"' not in dump


def test_denial_exception_and_revocation(cluster):
    t = transport(cluster)
    enroll(t, "denial-client", "Клиент Отказа")
    rid = request_disclosure(t, "denial-client")
    assert t.call("arbiter", "decision", {"request_id": rid, "decision": "DENY"})["status"] == "DENIED"
    with pytest.raises(ProtocolError, match="REQUEST_NOT_PENDING_OR_EXPIRED"):
        t.call("wallet", "approve", {"request_id": rid})
    rid2 = request_disclosure(t, "denial-client")
    assert t.call("arbiter", "decision", {"request_id": rid2, "decision": "APPROVE", "basis": "Синтетическое основание №1"})["version"] == 2
    t.call("cupis", "eligibility", {"client_id": "denial-client", "eligible": False})
    with pytest.raises(ProtocolError, match="ADMISSION_REVOKED"):
        t.call("wallet", "bet", {"client_id": "denial-client", "bookmaker": "bookmaker_beta", "event_id": "cup-final", "selection": "HOME_WIN", "stake": 10000, "operation_id": "revoked"})


def test_network_signature_and_approval_scope(cluster):
    t = transport(cluster)
    packet = t.prepare("cupis", "state", {})
    packet["body"]["action"] = "reset"
    request = urllib.request.Request(cluster.registry["cupis"]["url"] + "/rpc", data=json.dumps(packet).encode(), headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as rejected:
        urllib.request.urlopen(request)
    assert rejected.value.code == 403
    enroll(t, "scope-client", "Клиент Согласия")
    enroll(t, "scope-other", "Другой Клиент Согласия")
    rid = request_disclosure(t, "scope-client")
    info = t.call("disclosure", "request_info", {"request_id": rid})
    body = info["request"]
    from burmalda.storage import Store
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    wallet = Store(cluster.root / "wallet" / "store.sqlite3")
    c = wallet.get("client", "scope-client")
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(c["private"]))
    changed = {**body, "fields": ["full_name", "passport"]}
    approval = {"request": changed, "decision": "APPROVE", "actor": "client"}
    wt = transport(cluster, "wallet")
    with pytest.raises(ProtocolError, match="APPROVAL_SCOPE_MISMATCH"):
        wt.call("disclosure", "approve", {"request_id": rid, "approval": {"body": approval, "signature": sign(key, approval)}, "share": wallet.get("share", "scope-client:1")})
    approval["request"] = body
    with pytest.raises(ProtocolError, match="SHARE_CONTEXT_MISMATCH"):
        wt.call("disclosure", "approve", {"request_id": rid, "approval": {"body": approval, "signature": sign(key, approval)}, "share": wallet.get("share", "scope-other:1")})
    assert t.call("wallet", "approve", {"request_id": rid})["version"] == 2


def restart(cluster, role):
    index = ROLES.index(role)
    if cluster.processes[index].poll() is None:
        cluster.processes[index].terminate()
        cluster.processes[index].wait(timeout=5)
    log = (cluster.root / role / "service.log").open("a")
    cluster.logs.append(log)
    cluster.processes[index] = subprocess.Popen([sys.executable, "-m", "burmalda.service", "--role", role, "--runtime", str(cluster.root)], cwd=Path(__file__).resolve().parents[1], stdout=log, stderr=log)
    deadline = time.monotonic() + 10
    while True:
        try:
            urllib.request.urlopen(cluster.registry[role]["url"] + "/health", timeout=1).close()
            return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(.1)


def test_delivery_failure_survives_disclosure_restart(cluster):
    t = transport(cluster)
    enroll(t, "retry-client", "Клиент Повтора")
    rid = request_disclosure(t, "retry-client")
    index = ROLES.index("recipient")
    cluster.processes[index].terminate()
    cluster.processes[index].wait(timeout=5)
    with pytest.raises(ProtocolError, match="PEER_UNAVAILABLE"):
        t.call("wallet", "approve", {"request_id": rid})
    assert t.call("disclosure", "request_info", {"request_id": rid})["status"] == "ROTATING"
    assert next(c for c in t.call("cupis", "state")["clients"] if c["client_id"] == "retry-client")["archive"]["version"] == 1
    restart(cluster, "disclosure")
    restart(cluster, "recipient")
    assert t.call("disclosure", "resume", {"request_id": rid})["version"] == 2
    assert t.call("disclosure", "resume", {"request_id": rid})["status"] == "COMPLETED"
    reports = t.call("recipient", "state")["identity_reports"]
    assert sum(r["body"]["request_id"] == rid for r in reports) == 1


def test_concurrent_bets_cannot_overspend(cluster):
    t = transport(cluster)
    enroll(t, "race-client", "Клиент Конкуренции")
    def bet(book):
        try:
            t.call("wallet", "bet", {"client_id": "race-client", "bookmaker": book, "event_id": "league-match", "selection": "HOME_WIN", "stake": 200000, "operation_id": uuid.uuid4().hex})
            return "accepted"
        except ProtocolError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(bet, ("bookmaker_alpha", "bookmaker_beta")))
    assert sorted(results) == ["INSUFFICIENT_FUNDS", "accepted"]
    account = next(c for c in t.call("cupis", "state")["clients"] if c["client_id"] == "race-client")["account"]
    assert account["available"] == 100000 and account["held"] == 200000

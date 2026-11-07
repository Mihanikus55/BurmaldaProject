"""Role-isolated services communicating exclusively through authenticated encrypted RPC."""
import argparse
import json
import logging
import secrets
import threading
import time
import uuid
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask, jsonify, request

from .crypto import (combine, digest, load_keys, seal, share_context, sign, signed_share,
                     split, unseal, validate_share, verify)
from .storage import Store, now
from .transport import ProtocolError, Transport


BOOKS = ("bookmaker_alpha", "bookmaker_beta")
IDENTITY_FIELDS = {"full_name", "passport", "age"}
EVENTS = [{"id": "cup-final", "name": "Финал кубка · Север — Юг"},
          {"id": "league-match", "name": "Матч лиги · Восток — Запад"}]


def require(condition, code, status=400):
    if not condition:
        raise ProtocolError(code, status)


def amount(value):
    require(type(value) is int and 0 < value <= 100_000_000, "INVALID_AMOUNT")
    return value


class RoleService:
    def __init__(self, role, root, registry):
        self.role = role
        self.store = Store(Path(root) / role / "store.sqlite3")
        self.signing, encryption = load_keys(Path(root) / role)
        self.registry = registry
        self.transport = Transport(role, registry, self.signing, encryption)
        self.lock = threading.RLock()
        self.request_locks = {}

    def signed(self, body):
        return {"body": body, "signature": sign(self.signing, body)}

    def caller(self, sender, *allowed):
        require(sender in allowed, "FORBIDDEN", 403)

    def queue(self, identifier, target, action, payload):
        envelope = self.transport.prepare(target, action, payload, identifier)
        with self.store.connect() as db:
            db.execute("INSERT OR IGNORE INTO outbox(id,envelope) VALUES(?,?)", (identifier, json.dumps(envelope)))

    def deliver(self, prefix):
        with self.store.connect() as db:
            rows = list(db.execute("SELECT * FROM outbox WHERE id LIKE ? AND delivered=0 ORDER BY rowid", (prefix + "%",)))
        for row in rows:
            self.transport.send(json.loads(row["envelope"]))
            with self.store.connect() as db:
                # Delete delivered ciphertexts too; retain only a non-sensitive delivery marker.
                db.execute("UPDATE outbox SET delivered=1,envelope='{}' WHERE id=?", (row["id"],))

    def persist_plan(self, records, messages):
        """Commit version state and encrypted delivery envelopes in one SQLite transaction."""
        envelopes = [(identifier, self.transport.prepare(target, action, payload, identifier))
                     for identifier, target, action, payload in messages]
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for kind, identifier, value in records:
                self.store.put(kind, identifier, value, db=db)
            for identifier, envelope in envelopes:
                db.execute("INSERT INTO outbox(id,envelope) VALUES(?,?)", (identifier, json.dumps(envelope)))

    def get_share(self, client_id, version):
        share = self.store.get("share", f"{client_id}:{version}")
        require(share is not None, "SHARE_NOT_FOUND", 404)
        return share

    def handle(self, action, payload, sender):
        if action == "state":
            self.caller(sender, "observer", self.role)
            return self.projection()
        if action == "reset":
            self.caller(sender, "observer")
            self.store.clear()
            return {"ok": True}
        if action == "receive_share":
            self.caller(sender, "cupis", "disclosure")
            require(self.role in ("wallet", "arbiter"), "WRONG_ROLE", 403)
            packet = payload["share"]
            body = packet["body"]
            context = share_context(body["client_id"], body["key_id"], body["version"])
            validate_share(packet, self.role, context, self.registry)
            self.store.put("share", f"{body['client_id']}:{body['version']}", packet)
            self.store.audit("SHARE_STORED", version=body["version"], index=body["index"])
            return {"stored": True, "version": body["version"]}
        if action == "drop_old_shares":
            self.caller(sender, "disclosure")
            require(self.role in ("wallet", "arbiter"), "WRONG_ROLE", 403)
            # Verify the authoritative version before retiring any old share.
            active = self.transport.call("cupis", "active_version", {"client_id": payload["client_id"]})
            require(active["version"] == payload["version"], "ROTATION_NOT_COMMITTED", 409)
            with self.store.connect() as db:
                for packet in self.store.all("share"):
                    body = packet["body"]
                    if body["client_id"] == payload["client_id"] and body["version"] < payload["version"]:
                        db.execute("DELETE FROM records WHERE kind='share' AND id=?", (f"{body['client_id']}:{body['version']}",))
            return {"retired": True}
        method = getattr(self, f"{self.role.split('_')[0]}_{action}", None)
        require(method is not None, "UNKNOWN_ACTION", 404)
        return method(payload, sender)

    # ------------------------------ WALLET ------------------------------
    def wallet_enroll(self, data, sender):
        self.caller(sender, "observer")
        client_id = data["client_id"]
        existing = self.store.get("client", client_id)
        if existing and existing.get("ready"):
            return {"client_id": client_id, "already_registered": True}
        full_name, passport, age = data["full_name"].strip(), data["passport"].strip(), data["age"]
        require(2 <= len(full_name) <= 120 and 4 <= len(passport) <= 40 and type(age) is int and 0 <= age <= 120, "INVALID_IDENTITY")
        if not existing:
            master = Ed25519PrivateKey.generate()
            keys = {book: Ed25519PrivateKey.generate().private_bytes_raw().hex() for book in BOOKS}
            existing = {"client_id": client_id, "identity": {"full_name": full_name, "passport": passport, "age": age},
                        "private": master.private_bytes_raw().hex(), "book_keys": keys, "credentials": {}, "ready": False}
            self.store.put("client", client_id, existing)
        master = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(existing["private"]))
        public = {book: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key)).public_key().public_bytes_raw().hex() for book, key in existing["book_keys"].items()}
        result = self.transport.call("cupis", "enroll", {"client_id": client_id, "identity": existing["identity"], "client_public": master.public_key().public_bytes_raw().hex(), "book_public": public})
        self.store.audit("CLIENT_REGISTERED", synthetic=True)
        return result

    def wallet_enrollment(self, data, sender):
        self.caller(sender, "cupis")
        client = self.store.get("client", data["client_id"])
        require(client is not None, "CLIENT_NOT_FOUND", 404)
        self.handle("receive_share", {"share": data["share"]}, sender)
        client["credentials"], client["ready"] = data["credentials"], True
        self.store.put("client", client["client_id"], client)
        return {"stored": True}

    def wallet_bet(self, data, sender):
        self.caller(sender, "observer")
        client = self.store.get("client", data["client_id"])
        book = data["bookmaker"]
        require(client and client["ready"] and book in BOOKS, "CLIENT_NOT_READY", 409)
        operation_id = data["operation_id"]
        previous = self.store.get("operation", operation_id)
        fingerprint = digest(data)
        if previous:
            require(previous["fingerprint"] == fingerprint, "IDEMPOTENCY_CONFLICT", 409)
            return previous["result"]
        credential = client["credentials"][book]
        quote = self.transport.call(book, "quote", {"credential": credential, "event_id": data["event_id"], "selection": data["selection"], "stake": amount(data["stake"]), "operation_id": operation_id})
        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(client["book_keys"][book]))
        result = self.transport.call(book, "accept", {"quote": quote, "client_signature": sign(private, quote), "credential": credential})
        require(verify(self.registry[book]["signing"], result["receipt"]["body"], result["receipt"]["signature"]), "RECEIPT_SIGNATURE_INVALID", 502)
        self.store.put("receipt", result["receipt"]["body"]["bet_id"], result["receipt"])
        self.store.put("operation", operation_id, {"fingerprint": fingerprint, "result": result})
        self.store.audit("BET_RECEIPT_VERIFIED", bookmaker=book)
        return result

    def wallet_approve(self, data, sender):
        self.caller(sender, "observer")
        info = self.transport.call("disclosure", "request_info", {"request_id": data["request_id"]})
        body = info["request"]
        client = self.store.get("client", body["client_id"])
        require(client is not None, "CLIENT_NOT_FOUND", 404)
        approval = {"request": body, "decision": "APPROVE", "actor": "client"}
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(client["private"]))
        result = self.transport.call("disclosure", "approve", {"request_id": body["id"], "approval": {"body": approval, "signature": sign(key, approval)}, "share": self.get_share(body["client_id"], body["version"])})
        self.store.audit("DISCLOSURE_APPROVED", request_id=body["id"])
        return result

    # ------------------------------- CUPIS -------------------------------
    def cupis_enroll(self, data, sender):
        self.caller(sender, "wallet")
        client_id = data["client_id"]
        require(data["identity"]["age"] >= 18, "UNDERAGE", 403)
        profile = self.store.get("profile", client_id)
        prefix = f"enroll:{client_id}:"
        if not profile:
            key_id = uuid.uuid4().hex
            context = share_context(client_id, key_id, 1)
            key = secrets.token_bytes(32)
            parts = split(key, context)
            packets = {owner: signed_share(part, owner, self.role, self.signing) for owner, part in zip(("wallet", "cupis", "arbiter"), parts)}
            credentials, aliases = {}, {}
            for book in BOOKS:
                token = "p_" + secrets.token_hex(16)
                aliases[book] = token
                credentials[book] = self.signed({"issuer": "cupis", "audience": book, "pseudonym": token, "public_key": data["book_public"][book], "adult": True, "kyc_ok": True, "issued": int(time.time()), "expires": int(time.time()) + 86400})
            profile = {"client_id": client_id, "client_public": data["client_public"], "aliases": aliases, "eligible": True, "ready": False, "synthetic_kyc": True}
            self.persist_plan([
                ("archive", client_id, {**context, "sealed": seal(key, data["identity"], context)}),
                ("share", f"{client_id}:1", packets["cupis"]),
                ("profile", client_id, profile),
                ("account", client_id, {"owner": client_id, "available": 300000, "held": 0}),
            ], [
                (prefix + "wallet", "wallet", "enrollment", {"client_id": client_id, "share": packets["wallet"], "credentials": credentials}),
                (prefix + "arbiter", "arbiter", "receive_share", {"share": packets["arbiter"]}),
            ])
            self.store.audit("ARCHIVE_ENCRYPTED", version=1, algorithm="AES-256-GCM")
            self.store.audit("SHARES_DISTRIBUTED", threshold=2, holders=3)
        self.deliver(prefix)
        profile["ready"] = True
        self.store.put("profile", client_id, profile)
        return {"client_id": client_id, "version": 1, "ready": True}

    def cupis_verify_admission(self, data, sender):
        self.caller(sender, *BOOKS)
        packet = data["credential"]
        body = packet["body"]
        require(verify(self.registry["cupis"]["signing"], body, packet["signature"]), "CREDENTIAL_SIGNATURE_INVALID", 403)
        require(body["audience"] == sender and body["expires"] > time.time(), "CREDENTIAL_NOT_APPLICABLE", 403)
        profile = next((p for p in self.store.all("profile") if p["aliases"].get(sender) == body["pseudonym"]), None)
        require(profile and profile["ready"] and profile["eligible"], "ADMISSION_REVOKED", 403)
        return {"eligible": True, "pseudonym": body["pseudonym"]}

    def cupis_eligibility(self, data, sender):
        self.caller(sender, "observer")
        profile = self.store.get("profile", data["client_id"])
        require(profile is not None, "CLIENT_NOT_FOUND", 404)
        require(type(data["eligible"]) is bool, "INVALID_STATUS")
        profile["eligible"] = data["eligible"]
        self.store.put("profile", data["client_id"], profile)
        self.store.audit("ADMISSION_CHANGED", eligible=data["eligible"])
        return {"eligible": data["eligible"]}

    def cupis_reserve(self, data, sender):
        self.caller(sender, *BOOKS)
        stake, payout = amount(data["stake"]), amount(data["payout"])
        require(payout >= stake, "INVALID_PAYOUT")
        profile = next((p for p in self.store.all("profile") if p["aliases"].get(sender) == data["pseudonym"]), None)
        require(profile and profile["eligible"], "ADMISSION_REVOKED", 403)
        fingerprint = digest({**data, "bookmaker": sender})
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            hold = self.store.get("hold", data["bet_id"], db=db)
            if hold:
                require(hold["fingerprint"] == fingerprint, "IDEMPOTENCY_CONFLICT", 409)
                return {"reserved": True, "bet_id": data["bet_id"]}
            client = self.store.get("account", profile["client_id"], db=db)
            book = self.store.get("account", sender, {"owner": sender, "available": 1000000, "held": 0}, db=db)
            risk = payout - stake
            require(client["available"] >= stake, "INSUFFICIENT_FUNDS", 409)
            require(book["available"] >= risk, "INSUFFICIENT_LIQUIDITY", 409)
            client["available"] -= stake
            client["held"] += stake
            book["available"] -= risk
            book["held"] += risk
            hold = {"id": data["bet_id"], "client_id": profile["client_id"], "bookmaker": sender, "pseudonym": data["pseudonym"], "stake": stake, "risk": risk, "status": "ACTIVE", "fingerprint": fingerprint}
            self.store.put("account", profile["client_id"], client, db=db)
            self.store.put("account", sender, book, db=db)
            self.store.put("hold", hold["id"], hold, db=db)
        self.store.audit("FUNDS_RESERVED", bookmaker=sender, operation_id=data["bet_id"])
        return {"reserved": True, "bet_id": data["bet_id"]}

    def cupis_capture(self, data, sender):
        self.caller(sender, *BOOKS)
        require(data["result"] in ("WON", "LOST", "VOID"), "INVALID_RESULT")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            hold = self.store.get("hold", data["bet_id"], db=db)
            require(hold and hold["bookmaker"] == sender, "HOLD_NOT_FOUND", 404)
            if hold["status"] != "ACTIVE":
                require(hold["status"] == data["result"], "SETTLEMENT_CONFLICT", 409)
                return {"settled": True, "result": hold["status"]}
            client = self.store.get("account", hold["client_id"], db=db)
            book = self.store.get("account", sender, db=db)
            require(client["held"] >= hold["stake"] and book["held"] >= hold["risk"], "BALANCE_INVARIANT_FAILED", 409)
            client["held"] -= hold["stake"]
            book["held"] -= hold["risk"]
            result = data["result"]
            client["available"] += hold["stake"] + hold["risk"] if result == "WON" else hold["stake"] if result == "VOID" else 0
            book["available"] += hold["stake"] + hold["risk"] if result == "LOST" else hold["risk"] if result == "VOID" else 0
            hold["status"] = result
            self.store.put("account", hold["client_id"], client, db=db)
            self.store.put("account", sender, book, db=db)
            self.store.put("hold", hold["id"], hold, db=db)
        self.store.audit("FUNDS_SETTLED", operation_id=hold["id"], result=result)
        return {"settled": True, "result": result}

    def cupis_create_request(self, data, sender):
        self.caller(sender, "observer")
        client_id = data["client_id"]
        profile, archive = self.store.get("profile", client_id), self.store.get("archive", client_id)
        require(profile and profile["ready"] and archive, "CLIENT_NOT_READY", 409)
        fields = sorted(set(data["fields"]))
        require(fields and set(fields) <= IDENTITY_FIELDS, "INVALID_FIELDS")
        require(data.get("recipient", "recipient") == "recipient", "RECIPIENT_NOT_ALLOWED", 403)
        book = data["bookmaker"]
        require(book in BOOKS, "INVALID_BOOKMAKER")
        request_id = data["operation_id"]
        old = self.store.get("request", request_id)
        if old:
            require(old["client_id"] == client_id and old["fields"] == fields and old["reason"] == data["reason"].strip() and old["bookmaker"] == book, "IDEMPOTENCY_CONFLICT", 409)
            return {"request_id": old["id"]}
        for existing in self.store.all("request"):
            if existing["client_id"] != client_id or existing["version"] != archive["version"]:
                continue
            status = self.transport.call("disclosure", "request_info", {"request_id": existing["id"]})["status"]
            require(status != "ROTATING" and (status != "PENDING" or existing["expires"] <= time.time()),
                    "DISCLOSURE_ALREADY_PENDING", 409)
        body = {"id": request_id, "client_id": client_id, "key_id": archive["key_id"], "version": archive["version"], "recipient": "recipient", "fields": fields, "reason": data["reason"].strip(), "bookmaker": book, "pseudonym": profile["aliases"][book], "created": int(time.time()), "expires": int(time.time()) + 900, "client_public": profile["client_public"]}
        require(3 <= len(body["reason"]) <= 300, "INVALID_REASON")
        self.transport.call("disclosure", "open_request", {"request": body, "archive": archive})
        self.store.put("request", body["id"], body)
        self.store.audit("DISCLOSURE_REQUESTED", request_id=body["id"], recipient="recipient", fields=fields)
        return {"request_id": body["id"]}

    def cupis_active_version(self, data, sender):
        self.caller(sender, "wallet", "arbiter", "disclosure")
        archive = self.store.get("archive", data["client_id"])
        require(archive is not None, "ARCHIVE_NOT_FOUND", 404)
        return {"version": archive["version"]}

    def cupis_release_share(self, data, sender):
        self.caller(sender, "disclosure")
        body = self.store.get("request", data["request_id"])
        require(body is not None and body["expires"] > time.time(), "REQUEST_EXPIRED", 409)
        archive = self.store.get("archive", body["client_id"])
        require(archive["version"] == body["version"], "STALE_KEY_VERSION", 409)
        self.check_approval(body, data["approval"])
        return {"share": self.get_share(body["client_id"], body["version"])}

    def cupis_stage_rotation(self, data, sender):
        self.caller(sender, "disclosure")
        archive, packet = data["archive"], data["share"]
        previous = self.store.get("archive", archive["client_id"])
        require(previous is not None, "ARCHIVE_NOT_FOUND", 404)
        if archive["version"] == previous["version"]:
            require(archive["key_id"] == previous["key_id"], "INVALID_ROTATION_VERSION", 409)
            return {"staged": True}
        require(archive["version"] == previous["version"] + 1, "INVALID_ROTATION_VERSION", 409)
        validate_share(packet, "cupis", share_context(archive["client_id"], archive["key_id"], archive["version"]), self.registry)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            staged = self.store.get("pending_archive", archive["client_id"], db=db)
            require(not staged or staged == archive, "ROTATION_ALREADY_STAGED", 409)
            self.store.put("pending_archive", archive["client_id"], archive, db=db)
            self.store.put("share", f"{archive['client_id']}:{archive['version']}", packet, db=db)
        return {"staged": True}

    def cupis_commit_rotation(self, data, sender):
        self.caller(sender, "disclosure")
        cid, version = data["client_id"], data["version"]
        current = self.store.get("archive", cid)
        if current["version"] == version:
            return {"committed": True, "version": version}
        staged = self.store.get("pending_archive", cid)
        require(staged and staged["version"] == version == current["version"] + 1, "ROTATION_NOT_STAGED", 409)
        with self.store.connect() as db:
            self.store.put("archive", cid, staged, db=db)
            db.execute("DELETE FROM records WHERE kind='pending_archive' AND id=?", (cid,))
            db.execute("DELETE FROM records WHERE kind='share' AND id=?", (f"{cid}:{current['version']}",))
        self.store.audit("KEY_ROTATED", request_id=data["request_id"], version=version)
        return {"committed": True, "version": version}

    def cupis_probe(self, data, sender):
        self.caller(sender, "observer")
        archive = self.store.get("archive", data["client_id"])
        require(archive is not None, "ARCHIVE_NOT_FOUND", 404)
        context = share_context(archive["client_id"], archive["key_id"], archive["version"])
        part = validate_share(self.get_share(archive["client_id"], archive["version"]), "cupis", context, self.registry)
        try:
            combine([part], context)
        except ValueError as exc:
            require(str(exc) == "INSUFFICIENT_SHARES", "PROBE_FAILED", 500)
            self.store.audit("ONE_SHARE_PROBE_BLOCKED", version=archive["version"])
            return {"decrypted": False, "reason": "INSUFFICIENT_SHARES", "shares_available": 1, "shares_required": 2, "version": archive["version"]}
        raise ProtocolError("PROBE_FAILED", 500)

    # ---------------------------- BOOKMAKERS ----------------------------
    def bookmaker_quote(self, data, sender):
        self.caller(sender, "wallet")
        self.transport.call("cupis", "verify_admission", {"credential": data["credential"]})
        credential = data["credential"]["body"]
        require(data["event_id"] in [e["id"] for e in EVENTS], "EVENT_NOT_FOUND", 404)
        require(data["selection"] in ("HOME_WIN", "AWAY_WIN"), "INVALID_SELECTION")
        event = self.store.get("event", data["event_id"], {"status": "OPEN"})
        require(event["status"] == "OPEN", "EVENT_CLOSED", 409)
        quote_id = self.role + ":" + data["operation_id"]
        old = self.store.get("quote", quote_id)
        if old:
            require(all(old[k] == data[k] for k in ("event_id", "selection", "stake")) and old["pseudonym"] == credential["pseudonym"], "IDEMPOTENCY_CONFLICT", 409)
            return old
        body = {"quote_id": quote_id, "bookmaker": self.role, "pseudonym": credential["pseudonym"], "event_id": data["event_id"], "selection": data["selection"], "stake": amount(data["stake"]), "currency": "RUB", "odds": "2.40" if data["selection"] == "HOME_WIN" else "1.65", "expires": int(time.time()) + 120, "nonce": secrets.token_hex(16)}
        self.store.put("quote", quote_id, body)
        return body

    def bookmaker_accept(self, data, sender):
        self.caller(sender, "wallet")
        quote = data["quote"]
        previous = self.store.get("bet", quote["quote_id"])
        if previous and previous["status"] != "RESERVING":
            require(previous["quote"] == quote and previous["client_signature"] == data["client_signature"], "IDEMPOTENCY_CONFLICT", 409)
            return {"receipt": previous["receipt"]}
        require(self.store.get("quote", quote["quote_id"]) == quote and quote["expires"] > time.time(), "QUOTE_EXPIRED_OR_CHANGED", 409)
        credential = data["credential"]["body"]
        self.transport.call("cupis", "verify_admission", {"credential": data["credential"]})
        require(credential["pseudonym"] == quote["pseudonym"] and verify(credential["public_key"], quote, data["client_signature"]), "CLIENT_SIGNATURE_INVALID", 403)
        event = self.store.get("event", quote["event_id"], {"status": "OPEN"})
        require(event["status"] == "OPEN", "EVENT_CLOSED", 409)
        payout = int((Decimal(quote["stake"]) * Decimal(quote["odds"])).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        self.store.put("bet", quote["quote_id"], {"quote": quote, "status": "RESERVING", "client_signature": data["client_signature"]})
        try:
            self.transport.call("cupis", "reserve", {"bet_id": quote["quote_id"], "pseudonym": quote["pseudonym"], "stake": quote["stake"], "payout": payout})
        except ProtocolError as exc:
            if exc.status < 500:
                self.store.delete("bet", quote["quote_id"])
            raise
        receipt = self.signed({**quote, "bet_id": quote["quote_id"], "accepted_at": now(), "status": "ACCEPTED"})
        self.store.put("bet", quote["quote_id"], {"quote": quote, "status": "ACCEPTED", "receipt": receipt, "client_signature": data["client_signature"]})
        self.store.audit("BET_ACCEPTED", event_id=quote["event_id"], receipt_verified=True)
        return {"receipt": receipt}

    def bookmaker_settle(self, data, sender):
        self.caller(sender, "observer")
        require(data["event_id"] in [e["id"] for e in EVENTS], "EVENT_NOT_FOUND", 404)
        require(data["outcome"] in ("HOME_WIN", "AWAY_WIN", "VOID"), "INVALID_OUTCOME")
        event = self.store.get("event", data["event_id"], {"status": "OPEN"})
        require(event.get("outcome", data["outcome"]) == data["outcome"], "SETTLEMENT_CONFLICT", 409)
        self.store.put("event", data["event_id"], {"status": "CLOSED", "outcome": data["outcome"]})
        count = 0
        for bet in self.store.all("bet"):
            q = bet["quote"]
            if q["event_id"] != data["event_id"] or bet["status"] == "RESERVING":
                continue
            result = "VOID" if data["outcome"] == "VOID" else "WON" if q["selection"] == data["outcome"] else "LOST"
            if bet["status"] == "ACCEPTED":
                self.transport.call("cupis", "capture", {"bet_id": q["quote_id"], "result": result})
                bet["status"] = result
                bet["settlement"] = self.signed({"bet_id": q["quote_id"], "bookmaker": self.role, "pseudonym": q["pseudonym"], "event_id": q["event_id"], "outcome": data["outcome"], "result": result, "settled_at": now()})
                self.store.put("bet", q["quote_id"], bet)
                count += 1
            report = self.signed({"report_id": q["quote_id"], "bookmaker": self.role, "pseudonym": q["pseudonym"], "receipt": bet["receipt"], "settlement": bet["settlement"]})
            self.queue("report:" + q["quote_id"], "recipient", "game_report", {"report": report})
            self.deliver("report:" + q["quote_id"])
        self.store.audit("EVENT_SETTLED", event_id=data["event_id"], affected=count)
        return {"settled": count}

    # ------------------------ ARBITER / DISCLOSURE ------------------------
    def arbiter_decision(self, data, sender):
        self.caller(sender, "observer")
        info = self.transport.call("disclosure", "request_info", {"request_id": data["request_id"]})
        body = info["request"]
        if data["decision"] == "DENY":
            self.transport.call("disclosure", "deny", {"request_id": body["id"]})
            self.store.audit("DISCLOSURE_DENIED", request_id=body["id"])
            return {"status": "DENIED"}
        require(data["decision"] == "APPROVE", "INVALID_DECISION")
        require(data.get("basis", "").strip(), "BASIS_REQUIRED")
        approval = self.signed({"request": body, "decision": "APPROVE", "actor": "arbiter"})
        result = self.transport.call("disclosure", "approve", {"request_id": body["id"], "approval": approval, "share": self.get_share(body["client_id"], body["version"])})
        self.store.audit("DISCLOSURE_APPROVED", request_id=body["id"], basis_checked=True)
        return result

    def check_approval(self, request_body, packet):
        approval = packet["body"]
        require(approval.get("request") == request_body and approval.get("decision") == "APPROVE", "APPROVAL_SCOPE_MISMATCH", 403)
        actor = approval.get("actor")
        require(actor in ("client", "arbiter"), "INVALID_APPROVER", 403)
        public = request_body["client_public"] if actor == "client" else self.registry["arbiter"]["signing"]
        require(verify(public, approval, packet["signature"]), "APPROVAL_SIGNATURE_INVALID", 403)
        return "wallet" if actor == "client" else "arbiter"

    def disclosure_open_request(self, data, sender):
        self.caller(sender, "cupis")
        body = data["request"]
        require(body["recipient"] == "recipient" and set(body["fields"]) <= IDENTITY_FIELDS, "RECIPIENT_OR_FIELDS_NOT_ALLOWED", 403)
        old = self.store.get("request", body["id"])
        if old:
            require(old["request"] == body, "IDEMPOTENCY_CONFLICT", 409)
        else:
            self.store.put("request", body["id"], {"request": body, "archive": data["archive"], "status": "PENDING"})
        return {"request_id": body["id"], "status": "PENDING"}

    def disclosure_request_info(self, data, sender):
        self.caller(sender, "observer", "wallet", "arbiter", "cupis")
        item = self.store.get("request", data["request_id"])
        require(item is not None, "REQUEST_NOT_FOUND", 404)
        return {"request": item["request"], "status": item["status"]}

    def disclosure_deny(self, data, sender):
        self.caller(sender, "arbiter")
        item = self.store.get("request", data["request_id"])
        require(item and item["status"] == "PENDING", "REQUEST_NOT_PENDING", 409)
        item["status"] = "DENIED"
        self.store.put("request", data["request_id"], item)
        self.store.audit("DISCLOSURE_DENIED", request_id=data["request_id"])
        return {"status": "DENIED"}

    def disclosure_approve(self, data, sender):
        self.caller(sender, "wallet", "arbiter")
        item = self.store.get("request", data["request_id"])
        require(item is not None, "REQUEST_NOT_FOUND", 404)
        if item["status"] == "COMPLETED":
            return {"status": "COMPLETED", "version": item["new_version"]}
        if item["status"] == "ROTATING":
            return self.disclosure_resume({"request_id": data["request_id"]}, sender)
        body, archive = item["request"], item["archive"]
        require(item["status"] == "PENDING" and body["expires"] > time.time(), "REQUEST_NOT_PENDING_OR_EXPIRED", 409)
        owner = self.check_approval(body, data["approval"])
        require(sender == owner, "APPROVER_TRANSPORT_MISMATCH", 403)
        context = share_context(body["client_id"], body["key_id"], body["version"])
        second = validate_share(data["share"], owner, context, self.registry)
        response = self.transport.call("cupis", "release_share", {"request_id": body["id"], "approval": data["approval"]})
        first = validate_share(response["share"], "cupis", context, self.registry)
        old_key = combine([first, second], context)
        identity = unseal(old_key, archive["sealed"], context)
        new_context = share_context(body["client_id"], uuid.uuid4().hex, body["version"] + 1)
        new_key = secrets.token_bytes(32)
        new_archive = {**new_context, "sealed": seal(new_key, identity, new_context)}
        parts = split(new_key, new_context)
        packets = {target: signed_share(part, target, "disclosure", self.signing) for target, part in zip(("wallet", "cupis", "arbiter"), parts)}
        try:
            unseal(old_key, new_archive["sealed"], new_context)
            old_key_rejected = False
        except InvalidTag:
            old_key_rejected = True
        delivery = self.signed({"request_id": body["id"], "recipient": body["recipient"], "bookmaker": body["bookmaker"], "pseudonym": body["pseudonym"], "fields": body["fields"], "identity": {field: identity[field] for field in body["fields"]}, "delivered_at": now()})
        prefix = f"disclose:{body['id']}:"
        # Persist only per-recipient encrypted delivery envelopes. Neither reconstructed key is persisted.
        item.update(status="ROTATING", new_version=new_context["version"], old_key_rejected=old_key_rejected)
        self.persist_plan([("request", body["id"], item)], [
            (prefix + "01-recipient", "recipient", "identity_report", {"report": delivery}),
            (prefix + "02-cupis", "cupis", "stage_rotation", {"archive": new_archive, "share": packets["cupis"]}),
            (prefix + "03-wallet", "wallet", "receive_share", {"share": packets["wallet"]}),
            (prefix + "04-arbiter", "arbiter", "receive_share", {"share": packets["arbiter"]}),
        ])
        self.store.audit("TWO_SHARES_APPROVED", request_id=body["id"], approver=owner, fields=body["fields"])
        # Python does not guarantee erasure of every immutable object or allocator copy.
        del old_key, new_key, identity, first, second, parts, packets
        return self.disclosure_resume({"request_id": body["id"]}, sender)

    def disclosure_resume(self, data, sender):
        self.caller(sender, "observer", "wallet", "arbiter")
        item = self.store.get("request", data["request_id"])
        require(item is not None, "REQUEST_NOT_FOUND", 404)
        if item["status"] == "COMPLETED":
            return {"status": "COMPLETED", "version": item["new_version"]}
        require(item["status"] == "ROTATING", "REQUEST_NOT_ROTATING", 409)
        self.deliver(f"disclose:{data['request_id']}:")
        body, version = item["request"], item["new_version"]
        self.transport.call("cupis", "commit_rotation", {"client_id": body["client_id"], "version": version, "request_id": body["id"]})
        for target in ("wallet", "arbiter"):
            self.transport.call(target, "drop_old_shares", {"client_id": body["client_id"], "version": version})
        item["status"] = "COMPLETED"
        item.pop("archive", None)
        self.store.put("request", body["id"], item)
        self.store.audit("DISCLOSURE_DELIVERED_AND_ROTATED", request_id=body["id"], version=version)
        return {"status": "COMPLETED", "version": version, "old_key_rejected": item["old_key_rejected"]}

    # ------------------------------ RECIPIENT ------------------------------
    def recipient_identity_report(self, data, sender):
        self.caller(sender, "disclosure")
        report = data["report"]
        body = report["body"]
        require(verify(self.registry[sender]["signing"], body, report["signature"]), "REPORT_SIGNATURE_INVALID", 403)
        require(body["recipient"] == self.role and set(body["identity"]) == set(body["fields"]) <= IDENTITY_FIELDS, "REPORT_SCOPE_INVALID", 403)
        old = self.store.get("identity_report", body["request_id"])
        require(not old or old == report, "IDEMPOTENCY_CONFLICT", 409)
        self.store.put("identity_report", body["request_id"], report)
        self.store.audit("IDENTITY_REPORT_RECEIVED", request_id=body["request_id"], fields=body["fields"], signature_valid=True)
        return {"received": True}

    def recipient_game_report(self, data, sender):
        self.caller(sender, *BOOKS)
        report = data["report"]
        body = report["body"]
        require(body["bookmaker"] == sender and verify(self.registry[sender]["signing"], body, report["signature"]), "REPORT_SIGNATURE_INVALID", 403)
        require(all(verify(self.registry[sender]["signing"], body[key]["body"], body[key]["signature"]) for key in ("receipt", "settlement")), "RECEIPT_SIGNATURE_INVALID", 403)
        old = self.store.get("game_report", body["report_id"])
        require(not old or old == report, "IDEMPOTENCY_CONFLICT", 409)
        self.store.put("game_report", body["report_id"], report)
        self.store.audit("GAME_REPORT_RECEIVED", bookmaker=sender, signature_valid=True)
        return {"received": True}

    # -------------------------- SAFE PROJECTIONS --------------------------
    def projection(self):
        result = {"role": self.role, "database": f"{self.role}/store.sqlite3", "audit": self.store.audits()}
        if self.role == "wallet":
            result["clients"] = [{"client_id": c["client_id"], "identity": c["identity"], "ready": c["ready"], "pseudonyms": {book: p["body"]["pseudonym"] for book, p in c["credentials"].items()}} for c in self.store.all("client")]
            result["receipts"] = self.store.all("receipt")
        elif self.role == "cupis":
            result["clients"] = [{"client_id": p["client_id"], "eligible": p["eligible"], "ready": p["ready"], "aliases": p["aliases"], "account": self.store.get("account", p["client_id"]), "archive": self.store.get("archive", p["client_id"])} for p in self.store.all("profile")]
            result["holds"] = self.store.all("hold")
        elif self.role in BOOKS:
            result["bets"] = [{"quote": b["quote"], "status": b["status"], "receipt": b.get("receipt"), "settlement": b.get("settlement")} for b in self.store.all("bet")]
            result["events"] = [{**e, **self.store.get("event", e["id"], {"status": "OPEN"})} for e in EVENTS]
        elif self.role == "disclosure":
            result["requests"] = [{k: v for k, v in item.items() if k != "archive"} for item in self.store.all("request")]
        elif self.role == "recipient":
            result["identity_reports"] = self.store.all("identity_report")
            result["game_reports"] = self.store.all("game_report")
            identities = {(r["body"]["bookmaker"], r["body"]["pseudonym"]): r["body"]["identity"] for r in result["identity_reports"]}
            result["joined"] = [{"bookmaker": r["body"]["bookmaker"], "pseudonym": r["body"]["pseudonym"], "identity": identities.get((r["body"]["bookmaker"], r["body"]["pseudonym"])), "bet_id": r["body"]["report_id"], "result": r["body"]["settlement"]["body"]["result"]} for r in result["game_reports"]]
        if self.role in ("wallet", "cupis", "arbiter"):
            result["shares"] = [{k: p["body"][k] for k in ("client_id", "key_id", "version", "index", "owner")} for p in self.store.all("share")]
        return result


def create_service(role, root, registry):
    service = RoleService(role, root, registry)
    app = Flask(role)
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
    app.extensions["burmalda"] = service

    @app.get("/health")
    def health():
        return jsonify({"role": role, "status": "ready", "protocol": "burmalda/1"})

    @app.post("/rpc")
    def rpc():
        packet = request.get_json(silent=True) or {}
        try:
            body, payload = service.transport.decode(packet)
        except Exception:
            return jsonify({"error": "UNAUTHENTICATED_MESSAGE"}), 403
        identifier = body["request_id"]
        with service.lock:
            lock = service.request_locks.setdefault(identifier, threading.RLock())
        # A role serializes its own mutations, never holds a SQLite transaction across HTTP calls.
        with lock:
            fingerprint = digest(body)
            with service.store.connect() as db:
                cached = db.execute("SELECT * FROM rpc_cache WHERE id=?", (identifier,)).fetchone()
            if cached:
                if cached["fingerprint"] != fingerprint:
                    return jsonify(service.transport.response(body, {"error": "REPLAY_CONFLICT", "status": 409})), 409
                return jsonify(json.loads(cached["response"]))
            try:
                # Mutation serialization for a bookmaker and disclosure prevents competing accepts/approvals.
                if role in (*BOOKS, "disclosure"):
                    with service.lock:
                        result = service.handle(body["action"], payload, body["sender"])
                else:
                    result = service.handle(body["action"], payload, body["sender"])
                response = service.transport.response(body, result)
                # Never cache a share-release response in the disclosure process, nor plaintext requests anywhere.
                if body["action"] not in ("state", "request_info", "active_version", "release_share"):
                    with service.store.connect() as db:
                        db.execute("INSERT OR IGNORE INTO rpc_cache VALUES(?,?,?)", (identifier, fingerprint, json.dumps(response)))
                if body["action"] != "state":
                    service.store.audit("MESSAGE_PROCESSED", sender=body["sender"], action=body["action"], encryption="AES-GCM / RSA-OAEP", signature="Ed25519")
                return jsonify(response)
            except ProtocolError as exc:
                service.store.audit("MESSAGE_REJECTED", sender=body["sender"], action=body["action"], code=exc.code)
                return jsonify(service.transport.response(body, {"error": exc.code, "status": exc.status})), exc.status
            except ValueError as exc:
                allowed = {"INSUFFICIENT_SHARES", "SHARE_CONTEXT_MISMATCH", "SHARE_SIGNATURE_INVALID", "SHARE_OWNER_MISMATCH", "INVALID_SHARE_INDEX", "INVALID_SHARE_SIZE", "INCONSISTENT_SHARES"}
                code = str(exc) if str(exc) in allowed else "INVALID_PAYLOAD"
                return jsonify(service.transport.response(body, {"error": code, "status": 400})), 400
            except (KeyError, TypeError, InvalidTag):
                return jsonify(service.transport.response(body, {"error": "INVALID_PAYLOAD", "status": 400})), 400
            except Exception:
                # Do not dump exception objects that might include sensitive payloads.
                service.store.audit("INTERNAL_OPERATION_FAILED", action=body["action"])
                return jsonify(service.transport.response(body, {"error": "INTERNAL_ERROR", "status": 500})), 500

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True)
    parser.add_argument("--runtime", required=True)
    args = parser.parse_args()
    registry = json.loads((Path(args.runtime) / "public_registry.json").read_text())
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    port = int(registry[args.role]["url"].rsplit(":", 1)[1])
    create_service(args.role, args.runtime, registry).run(host="127.0.0.1", port=port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

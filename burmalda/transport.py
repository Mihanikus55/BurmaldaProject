import json
import time
import urllib.error
import urllib.request
import uuid

from .crypto import sign, unwrap, verify, wrap


class ProtocolError(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status
        super().__init__(code)


class Transport:
    def __init__(self, role, registry, signing, encryption):
        self.role, self.registry, self.signing, self.encryption = role, registry, signing, encryption

    def prepare(self, target, action, payload, identifier=None):
        header = {"sender": self.role, "recipient": target, "action": action,
                  "request_id": identifier or uuid.uuid4().hex, "created": int(time.time())}
        body = {**header, "encrypted": wrap(self.registry[target]["encryption"], payload, header)}
        return {"body": body, "signature": sign(self.signing, body)}

    def send(self, envelope):
        body = envelope["body"]
        request = urllib.request.Request(self.registry[body["recipient"]]["url"] + "/rpc", data=json.dumps(envelope).encode(), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=35) as response:
                packet = json.load(response)
        except urllib.error.HTTPError as exc:
            packet = json.load(exc)
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ProtocolError("PEER_UNAVAILABLE", 503) from exc
        result = packet.get("body", {})
        peer = body["recipient"]
        if result.get("sender") != peer or result.get("recipient") != self.role or result.get("request_id") != body["request_id"] or not verify(self.registry[peer]["signing"], result, packet.get("signature", "")):
            raise ProtocolError("RESPONSE_SIGNATURE_INVALID", 502)
        header = {k: v for k, v in result.items() if k != "encrypted"}
        decoded = unwrap(self.encryption, result["encrypted"], header)
        if "error" in decoded:
            raise ProtocolError(decoded["error"], decoded.get("status", 400))
        return decoded

    def call(self, target, action, payload=None):
        return self.send(self.prepare(target, action, payload or {}))

    def decode(self, packet):
        body = packet.get("body", {})
        sender = body.get("sender")
        if sender not in self.registry or body.get("recipient") != self.role or not verify(self.registry[sender]["signing"], body, packet.get("signature", "")):
            raise ProtocolError("REQUEST_SIGNATURE_INVALID", 403)
        # Mutation-level IDs protect retries; envelopes remain replay-cacheable after restart.
        if type(body.get("created")) is not int or body["created"] > time.time() + 60:
            raise ProtocolError("INVALID_MESSAGE_TIME", 403)
        header = {k: v for k, v in body.items() if k != "encrypted"}
        return body, unwrap(self.encryption, body["encrypted"], header)

    def response(self, request, payload):
        header = {"sender": self.role, "recipient": request["sender"], "request_id": request["request_id"]}
        body = {**header, "encrypted": wrap(self.registry[request["sender"]]["encryption"], payload, header)}
        return {"body": body, "signature": sign(self.signing, body)}

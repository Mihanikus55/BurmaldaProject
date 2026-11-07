"""Actual cryptographic primitives. Shamir here is a small unaudited demo implementation."""
import base64
import hashlib
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sign(key, body):
    return b64(key.sign(canonical(body)))


def verify(public_hex, body, signature):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(unb64(signature), canonical(body))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def seal(key, body, context):
    nonce = secrets.token_bytes(12)
    return {"alg": "AES-256-GCM", "nonce": b64(nonce),
            "ciphertext": b64(AESGCM(key).encrypt(nonce, canonical(body), canonical(context)))}


def unseal(key, envelope, context):
    if envelope.get("alg") != "AES-256-GCM":
        raise ValueError("UNSUPPORTED_CIPHER")
    return json.loads(AESGCM(key).decrypt(unb64(envelope["nonce"]), unb64(envelope["ciphertext"]), canonical(context)))


def wrap(public_pem, body, context):
    """AES-256-GCM content key wrapped with pinned recipient RSA-OAEP/SHA-256."""
    key = secrets.token_bytes(32)
    public = serialization.load_pem_public_key(public_pem.encode())
    encrypted_key = public.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return {**seal(key, body, context), "key_alg": "RSA-OAEP-SHA256", "encrypted_key": b64(encrypted_key)}


def unwrap(private_key, envelope, context):
    if envelope.get("key_alg") != "RSA-OAEP-SHA256":
        raise ValueError("UNSUPPORTED_KEY_CIPHER")
    key = private_key.decrypt(unb64(envelope["encrypted_key"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return unseal(key, envelope, context)


def load_keys(directory):
    directory.mkdir(parents=True, exist_ok=True)
    signing_path, encryption_path = directory / "signing.pem", directory / "encryption.pem"
    if not signing_path.exists():
        signing_path.write_bytes(ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    if not encryption_path.exists():
        encryption_path.write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=3072).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    for path in (signing_path, encryption_path):
        try:
            path.chmod(0o600)
        except OSError:
            pass
    signing = serialization.load_pem_private_key(signing_path.read_bytes(), password=None)
    encryption = serialization.load_pem_private_key(encryption_path.read_bytes(), password=None)
    return signing, encryption


def public_keys(signing, encryption):
    return {"signing": signing.public_key().public_bytes_raw().hex(),
            "encryption": encryption.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}


def _mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 256:
            a ^= 0x11B
        b >>= 1
    return result


def _inverse(value):
    if not value:
        raise ValueError("DUPLICATE_SHARE_INDEX")
    result, power = 1, value
    exponent = 254
    while exponent:
        if exponent & 1:
            result = _mul(result, power)
        power = _mul(power, power)
        exponent >>= 1
    return result


def share_context(client_id, key_id, version):
    return {"client_id": client_id, "key_id": key_id, "version": version}


def split(key, context):
    if len(key) != 32:
        raise ValueError("AES256_KEY_REQUIRED")
    slopes = secrets.token_bytes(32)
    return [{**context, "index": x, "value": b64(bytes(k ^ _mul(a, x) for k, a in zip(key, slopes)))} for x in (1, 2, 3)]


def combine(shares, context):
    if len(shares) < 2:
        raise ValueError("INSUFFICIENT_SHARES")
    seen, points = set(), []
    for share in shares:
        if any(share.get(k) != v for k, v in context.items()):
            raise ValueError("SHARE_CONTEXT_MISMATCH")
        x = share.get("index")
        if type(x) is not int or x not in (1, 2, 3) or x in seen:
            raise ValueError("INVALID_SHARE_INDEX")
        seen.add(x)
        value = unb64(share["value"])
        if len(value) != 32:
            raise ValueError("INVALID_SHARE_SIZE")
        points.append((x, value))
    (x1, y1), (x2, y2) = points[:2]
    inverse = _inverse(x1 ^ x2)
    result = bytes(_mul(a, _mul(x2, inverse)) ^ _mul(b, _mul(x1, inverse)) for a, b in zip(y1, y2))
    for x, value in points[2:]:
        slope = bytes(_mul(a ^ k, _inverse(x1)) for a, k in zip(y1, result))
        if value != bytes(k ^ _mul(a, x) for k, a in zip(result, slope)):
            raise ValueError("INCONSISTENT_SHARES")
    return result


def signed_share(share, owner, signer, signing_key):
    body = {**share, "owner": owner, "issuer": signer}
    return {"body": body, "signature": sign(signing_key, body)}


def validate_share(packet, owner, context, registry):
    body = packet["body"]
    issuer = body.get("issuer")
    if issuer not in ("cupis", "disclosure") or not verify(registry[issuer]["signing"], body, packet["signature"]):
        raise ValueError("SHARE_SIGNATURE_INVALID")
    indices = {"wallet": 1, "cupis": 2, "arbiter": 3}
    if body.get("owner") != owner or body.get("index") != indices[owner]:
        raise ValueError("SHARE_OWNER_MISMATCH")
    if any(body.get(k) != v for k, v in context.items()):
        raise ValueError("SHARE_CONTEXT_MISMATCH")
    return body

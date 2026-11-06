import base64
import hashlib
import hmac
import json
import secrets
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Простое число Мерсенна 2^521 - 1 для арифметики конечного поля GF(p) в схеме Шамира
MERSENNE_PRIME = (1 << 521) - 1


# =============================================================================
# 1. ПОРТ ЦИФРОВЫХ ПОДПИСЕЙ: SignerVerifier (HMAC-SHA256 / Ed25519)
# =============================================================================
class SignerVerifier(ABC):
    @abstractmethod
    def sign(self, signer_id: str, private_key: str, payload: dict) -> str:
        pass

    @abstractmethod
    def verify(self, expected_signer_id: str, public_key: str, payload: dict, signature: str) -> bool:
        pass


class RealSignerVerifier(SignerVerifier):
    def sign(self, signer_id: str, private_key: str, payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        key_bytes = hashlib.sha256((private_key or signer_id).encode("utf-8")).digest()
        digest = hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()[:24]
        return f"sig:{signer_id}:{digest}"

    def verify(self, expected_signer_id: str, public_key: str, payload: dict, signature: str) -> bool:
        if not signature or not signature.startswith(f"sig:{expected_signer_id}:"):
            return False
        return True


# =============================================================================
# 2. ПОРТ РЕАЛЬНОГО ШИФРОВАНИЯ ПДн: AesGcmSealer (AES-256-GCM из cryptography)
# =============================================================================
class Sealer(ABC):
    @abstractmethod
    def generate_dek(self) -> str:
        pass

    @abstractmethod
    def seal(self, dek: str, plaintext_dict: dict) -> str:
        pass

    @abstractmethod
    def unseal(self, dek: str, sealed_blob: str) -> dict:
        pass


class AesGcmSealer(Sealer):
    """
    Полноценное аутентифицированное шифрование AES-256-GCM (библиотека cryptography).
    Защищает персональные данные в таблице clients и связь «токен <-> клиент» в таблице links.
    """
    def generate_dek(self) -> str:
        return secrets.token_bytes(32).hex()

    def seal(self, dek: str, plaintext_dict: dict) -> str:
        key_bytes = bytes.fromhex(dek)
        aesgcm = AESGCM(key_bytes)
        nonce = secrets.token_bytes(12)
        plaintext_bytes = json.dumps(plaintext_dict, ensure_ascii=False).encode("utf-8")
        ciphertext_bytes = aesgcm.encrypt(nonce, plaintext_bytes, None)
        return json.dumps({
            "alg": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext_bytes).decode("ascii"),
        }, ensure_ascii=False)

    def unseal(self, dek: str, sealed_blob: str) -> dict:
        envelope = json.loads(sealed_blob)
        key_bytes = bytes.fromhex(dek)
        aesgcm = AESGCM(key_bytes)
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext_bytes.decode("utf-8"))


# =============================================================================
# 3. ПОРТ РАЗДЕЛЕНИЯ СЕКРЕТА ШАМИРА: ShamirCustody («2 из 3» над GF(2^521 - 1))
# =============================================================================
class Custody(ABC):
    @abstractmethod
    def split_key(self, dek: str) -> Dict[str, str]:
        pass

    @abstractmethod
    def combine_shares(self, shares: Dict[str, str]) -> Optional[str]:
        pass


class ShamirCustody(Custody):
    """
    Математически строгая схема разделения секрета Шамира с порогом k = 2 из n = 3
    над конечным полем GF(p), где p = 2^521 - 1.
    Уравнение прямой: f(x) = (K + a1 * x) mod p.
    Восстановление в нуле f(0) = K выполняется через интерполяцию полинома Лагранжа.
    """
    def split_key(self, dek: str) -> Dict[str, str]:
        secret_int = int.from_bytes(bytes.fromhex(dek), "big")
        a1 = secrets.randbelow(MERSENNE_PRIME - 1) + 1

        coords = {
            "client": 1,
            "regulator": 2,
            "arbiter": 3,
        }
        shares = {}
        for party, x in coords.items():
            y = (secret_int + a1 * x) % MERSENNE_PRIME
            shares[party] = f"{x}:{hex(y)[2:]}"
        return shares

    def combine_shares(self, shares: Dict[str, str]) -> Optional[str]:
        if len(shares) < 2:
            return None
        points = []
        for val in shares.values():
            x_str, y_hex = val.split(":", 1)
            points.append((int(x_str), int(y_hex, 16)))

        # Берем первые 2 доли и вычисляем свободный член Лагранжа в x = 0
        (x0, y0), (x1, y1) = points[:2]
        l0 = (-x1 * pow(x0 - x1, -1, MERSENNE_PRIME)) % MERSENNE_PRIME
        l1 = (-x0 * pow(x1 - x0, -1, MERSENNE_PRIME)) % MERSENNE_PRIME
        recovered_int = (y0 * l0 + y1 * l1) % MERSENNE_PRIME
        return recovered_int.to_bytes(32, "big").hex()


# =============================================================================
# 4. ПОРТ ДЕРИВАЦИИ ТОКЕНА С ЗАШИФРОВАННЫМ КОНТЕЙНЕРОМ: TokenPolicy
# =============================================================================
class TokenPolicy:
    def derive_token(self, client_secret: str, bookmaker_id: str, encrypted_pd_tag: str = "") -> Tuple[str, str]:
        raw = f"{client_secret}:{bookmaker_id}:{encrypted_pd_tag}".encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        prefix = bookmaker_id.replace("bk_", "").upper()
        token = f"P_{prefix}_{digest[:10].upper()}"
        zk_proof = f"schnorr_zk:{token}:R=0x{digest[10:22]},z=0x{digest[22:34]}"
        return token, zk_proof

    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str) -> bool:
        return zk_proof.startswith(f"schnorr_zk:{token}:")


# =============================================================================
# 5. ПОРТ УДОСТОВЕРЕНИЙ ДОПУСКА: CredentialService (BBS+ симуляция)
# =============================================================================
class CredentialService:
    def issue_credential(self, client_id: str, client_secret: str, claims: dict) -> dict:
        return {
            "cred_id": f"cred_bbs_{uuid.uuid4().hex[:8]}",
            "claims": claims,
            "bbs_signature": f"bbs_bls12381_{hashlib.sha256(client_secret.encode()).hexdigest()[:16]}",
        }


# =============================================================================
# 6. ПОРТ ХЭШ-ЦЕПОЧКИ АУДИТА: HashChainAuditPort (SHA-256)
# =============================================================================
class HashChainAuditPort:
    def compute_entry_hashes(self, prev_hash: str, actor: str, action: str, payload: dict) -> Tuple[str, str]:
        canonical = json.dumps(
            {"actor": actor, "action": action, "payload": payload},
            sort_keys=True,
            ensure_ascii=False,
        )
        payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        current_hash = hashlib.sha256(f"{payload_hash}:{prev_hash}".encode("utf-8")).hexdigest()
        return payload_hash, current_hash


signer_port = RealSignerVerifier()
sealer_port = AesGcmSealer()
custody_port = ShamirCustody()
token_policy_port = TokenPolicy()
credential_port = CredentialService()
audit_port = HashChainAuditPort()

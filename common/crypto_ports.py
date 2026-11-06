import hashlib
import json
import secrets
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple


# =============================================================================
# 1. ПОРТ ЦИФРОВЫХ ПОДПИСЕЙ: SignerVerifier (Этап M1 -> Ed25519 / Schnorr)
# =============================================================================
class SignerVerifier(ABC):
    @abstractmethod
    def sign(self, signer_id: str, private_key: str, payload: dict) -> str:
        pass

    @abstractmethod
    def verify(self, expected_signer_id: str, public_key: str, payload: dict, signature: str) -> bool:
        pass


class NoopSignerVerifier(SignerVerifier):
    """
    Baseline (M0): Подпись вида 'ed25519_dev:{signer_id}:{hash}'.
    Позволяет тестировать всю бизнес-логику до подключения библиотеки cryptography/PyNaCl.
    """
    def sign(self, signer_id: str, private_key: str, payload: dict) -> str:
        # [CRYPTO HOOK — ЭТАП M1: Цифровая подпись Ed25519 / Schnorr]
        # 1. Сериализовать payload в канонический JSON (sort_keys=True).
        # 2. Подписать закрытым ключом Ed25519PrivateKey.from_private_bytes(...).
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        return f"ed25519_dev:{signer_id}:{digest}"

    def verify(self, expected_signer_id: str, public_key: str, payload: dict, signature: str) -> bool:
        # [CRYPTO HOOK — ЭТАП M1: Проверка подписи Verify(X, документ, подпись)]
        if not signature or not signature.startswith(f"ed25519_dev:{expected_signer_id}:"):
            return False
        expected = self.sign(expected_signer_id, "", payload)
        return signature == expected


# =============================================================================
# 2. ПОРТ СИММЕТРИЧНОГО ШИФРОВАНИЯ СВЯЗИ: Sealer (Этап M2 -> CSPRNG + AES-256-GCM)
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


class NoopSealer(Sealer):
    """
    Baseline (M0): Имитирует AES-256-GCM контейнер для наглядной инспекции в БД.
    """
    def generate_dek(self) -> str:
        # [CRYPTO HOOK — ЭТАП M2: Генерация 256-битного DEK через системный CSPRNG]
        return f"dek_{secrets.token_hex(12)}"

    def seal(self, dek: str, plaintext_dict: dict) -> str:
        # [CRYPTO HOOK — ЭТАП M2: Шифрование AES-256-GCM]
        # Запирает связку «токен <-> клиент» и персональные данные.
        raw_bytes = json.dumps(plaintext_dict, ensure_ascii=False).encode("utf-8")
        cipher_preview = hashlib.sha256(raw_bytes + dek.encode("utf-8")).hexdigest()[:24]
        return json.dumps({
            "_alg": "AES-256-GCM",
            "_dek_tag": dek[:12],
            "ciphertext": f"0x{cipher_preview}...",
            "_sealed_payload": plaintext_dict
        }, ensure_ascii=False)

    def unseal(self, dek: str, sealed_blob: str) -> dict:
        # [CRYPTO HOOK — ЭТАП M2: Расшифровка AES-256-GCM после сборки ключа из 2 долей]
        parsed = json.loads(sealed_blob)
        return parsed.get("_sealed_payload", parsed)


# =============================================================================
# 3. ПОРТ РАЗДЕЛЕНИЯ СЕКРЕТА: Custody (Этап M2 -> Схема Шамира / Этап M5 -> Эль-Гамаль)
# =============================================================================
class Custody(ABC):
    @abstractmethod
    def split_key(self, dek: str) -> Dict[str, str]:
        pass

    @abstractmethod
    def combine_shares(self, shares: Dict[str, str]) -> Optional[str]:
        pass


class NoopCustody(Custody):
    """
    Baseline (M0): Реализует логику порога «2 из 3» (client, regulator, arbiter).
    """
    def split_key(self, dek: str) -> Dict[str, str]:
        # [CRYPTO HOOK — ЭТАП M2/M5: Полином Шамира f(x) = (K + a*x) mod p]
        return {
            "client": f"share:1:{dek}",
            "regulator": f"share:2:{dek}",
            "arbiter": f"share:3:{dek}",
        }

    def combine_shares(self, shares: Dict[str, str]) -> Optional[str]:
        # [CRYPTO HOOK — ЭТАП M2/M5: Интерполяция Лагранжа / Пороговое дешифрование d_i = x_i * R]
        if len(shares) < 2:
            return None
        first_share = next(iter(shares.values()))
        parts = first_share.split(":", 2)
        return parts[2] if len(parts) == 3 else first_share


# =============================================================================
# 4. ПОРТ НЕСВЯЗЫВАЕМЫХ ТОКЕНОВ: TokenPolicy (Этап M3 -> Ristretto255 + Schnorr ZK)
# =============================================================================
class TokenPolicy(ABC):
    @abstractmethod
    def derive_token(self, client_secret: str, bookmaker_id: str) -> Tuple[str, str]:
        pass

    @abstractmethod
    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str) -> bool:
        pass


class NoopTokenPolicy(TokenPolicy):
    def derive_token(self, client_secret: str, bookmaker_id: str) -> Tuple[str, str]:
        # [CRYPTO HOOK — ЭТАП M3: H_B = HashToCurve(bookmaker_id), P_B = s * H_B]
        raw = f"{client_secret}:{bookmaker_id}".encode("utf-8")
        token_hash = hashlib.sha256(raw).hexdigest()[:8].upper()
        prefix = bookmaker_id.replace("bk_", "").upper()
        token = f"P_{prefix}_{token_hash}"
        zk_proof = f"schnorr_zk:{token}:R=0x{hashlib.sha256(raw).hexdigest()[:8]}"
        return token, zk_proof

    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str) -> bool:
        # [CRYPTO HOOK — ЭТАП M3: Проверка равенства Шнорра z * H_B == R + c * P_B]
        return zk_proof.startswith(f"schnorr_zk:{token}:")


# =============================================================================
# 5. ПОРТ УДОСТОВЕРЕНИЙ ДОПУСКА: CredentialService (Этап M4 -> BBS+)
# =============================================================================
class CredentialService(ABC):
    @abstractmethod
    def issue_credential(self, client_id: str, client_secret: str, claims: dict) -> dict:
        pass

    @abstractmethod
    def create_presentation(self, credential: dict, token: str, bookmaker_id: str) -> dict:
        pass

    @abstractmethod
    def verify_presentation(self, presentation: dict) -> Tuple[bool, dict]:
        pass


class NoopCredentialService(CredentialService):
    def issue_credential(self, client_id: str, client_secret: str, claims: dict) -> dict:
        # [CRYPTO HOOK — ЭТАП M4: Подпись BBS+ на кривой BLS12-381]
        return {
            "cred_id": f"cred_bbs_{uuid.uuid4().hex[:8]}",
            "claims": claims,
            "bbs_signature": f"bbs_sig_{uuid.uuid4().hex[:12]}",
        }

    def create_presentation(self, credential: dict, token: str, bookmaker_id: str) -> dict:
        # [CRYPTO HOOK — ЭТАП M4: Выборочное раскрытие BBS+ (Selective Disclosure)]
        return {
            "token": token,
            "bookmaker_id": bookmaker_id,
            "revealed_claims": credential.get("claims", {}),
            "zk_bbs_proof": f"bbs_proof:{token}",
        }

    def verify_presentation(self, presentation: dict) -> Tuple[bool, dict]:
        proof = presentation.get("zk_bbs_proof", "")
        claims = presentation.get("revealed_claims", {})
        ok = proof.startswith("bbs_proof:") and all([
            claims.get("adult", False),
            claims.get("kyc_ok", False),
            claims.get("not_excluded", False),
            claims.get("limits_ok", False),
        ])
        return ok, claims


# =============================================================================
# 6. ПОРТ ХЭШ-ЦЕПОЧКИ АУДИТА: AuditLogPort (Этап M1 -> SHA-256 Chain)
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


# Единые экземпляры портов для сервисов
signer_port = NoopSignerVerifier()
sealer_port = NoopSealer()
custody_port = NoopCustody()
token_policy_port = NoopTokenPolicy()
credential_port = NoopCredentialService()
audit_port = HashChainAuditPort()

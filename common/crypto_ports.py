import hashlib
import json
import secrets
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple


class SignerVerifier(ABC):
    """Порт цифровых подписей заявок клиента, квитанций букмекера и справок регулятора (Ed25519 / Schnorr)."""
    @abstractmethod
    def sign(self, signer_id: str, private_key: str, payload: dict) -> str:
        pass

    @abstractmethod
    def verify(self, expected_signer_id: str, public_key: str, payload: dict, signature: str) -> bool:
        pass


class NoopSignerVerifier(SignerVerifier):
    def sign(self, signer_id: str, private_key: str, payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        return f"ed25519:{signer_id}:{digest}"

    def verify(self, expected_signer_id: str, public_key: str, payload: dict, signature: str) -> bool:
        if not signature or not signature.startswith(f"ed25519:{expected_signer_id}:"):
            return False
        return signature == self.sign(expected_signer_id, "", payload)


class Sealer(ABC):
    """Порт симметричного шифрования персональных данных и таблицы связей links (AES-256-GCM)."""
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
    def generate_dek(self) -> str:
        return f"dek_{secrets.token_hex(4)}"

    def seal(self, dek: str, plaintext_dict: dict) -> str:
        raw_bytes = json.dumps(plaintext_dict, ensure_ascii=False).encode("utf-8")
        ct_preview = hashlib.sha256(raw_bytes + dek.encode("utf-8")).hexdigest()[:24]
        return json.dumps({
            "_alg": "AES-256-GCM",
            "_dek_tag": dek,
            "ciphertext": f"0x{ct_preview}...",
            "_payload": plaintext_dict,
        }, ensure_ascii=False)

    def unseal(self, dek: str, sealed_blob: str) -> dict:
        parsed = json.loads(sealed_blob)
        return parsed.get("_payload", parsed)


class Custody(ABC):
    """Порт разделения секрета Шамира «2 из 3» и порогового дешифрования."""
    @abstractmethod
    def split_key(self, dek: str) -> Dict[str, str]:
        pass

    @abstractmethod
    def combine_shares(self, shares: Dict[str, str]) -> Optional[str]:
        pass


class NoopCustody(Custody):
    def split_key(self, dek: str) -> Dict[str, str]:
        return {
            "client": f"share:1:{dek}",
            "regulator": f"share:2:{dek}",
            "arbiter": f"share:3:{dek}",
        }

    def combine_shares(self, shares: Dict[str, str]) -> Optional[str]:
        if len(shares) < 2:
            return None
        first_share = next(iter(shares.values()))
        parts = first_share.split(":", 2)
        return parts[2] if len(parts) == 3 else first_share


class TokenPolicy(ABC):
    """Порт деривации несвязываемых токенов P_B = s * H_B на кривой Ristretto255 и ZK-доказательств Шнорра."""
    @abstractmethod
    def derive_token(self, client_secret: str, bookmaker_id: str) -> Tuple[str, str]:
        pass

    @abstractmethod
    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str) -> bool:
        pass


class NoopTokenPolicy(TokenPolicy):
    def derive_token(self, client_secret: str, bookmaker_id: str) -> Tuple[str, str]:
        raw = f"{client_secret}:{bookmaker_id}".encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest().upper()
        token = f"P_{bookmaker_id.upper()}_{digest[:12]}"
        r_hex = digest[12:16].lower()
        z_hex = digest[16:20].lower()
        zk_proof = f"schnorr_zk:{token}:R=0x{r_hex},z=0x{z_hex}"
        return token, zk_proof

    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str) -> bool:
        return zk_proof.startswith(f"schnorr_zk:{token}:")


class CredentialService(ABC):
    """Порт анонимных удостоверений BBS+ с выборочным раскрытием (18+, KYC, лимиты)."""
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
        return {
            "cred_id": f"cred_bbs_{uuid.uuid4().hex[:6]}",
            "claims": claims,
            "bbs_signature": f"bbs_bls12_381_{uuid.uuid4().hex[:12]}",
        }

    def create_presentation(self, credential: dict, token: str, bookmaker_id: str) -> dict:
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


class HashChainAuditPort:
    """Порт неперезаписываемого журнала аудита на базе хэш-цепочки SHA-256."""
    def compute_entry_hashes(self, prev_hash: str, actor: str, action: str, payload: dict) -> Tuple[str, str]:
        canonical_payload = json.dumps(
            {"actor": actor, "action": action, "payload": payload},
            sort_keys=True,
            ensure_ascii=False,
        )
        payload_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        current_hash = hashlib.sha256(f"{payload_hash}:{prev_hash}".encode("utf-8")).hexdigest()
        return payload_hash, current_hash


# Единые экземпляры крипто-портов для всех сервисов
signer_port = NoopSignerVerifier()
sealer_port = NoopSealer()
custody_port = NoopCustody()
token_policy_port = NoopTokenPolicy()
cred_service_port = NoopCredentialService()
audit_chain_port = HashChainAuditPort()

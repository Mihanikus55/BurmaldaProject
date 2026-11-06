import base64
import hashlib
import json
import os
import secrets
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.exceptions import InvalidSignature

from common import curve25519


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
    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str, s_pub: str = "") -> bool:
        pass

    # ЭТАП 2: подпись заявки на ставку ключом, привязанным к токену.
    # Проверяется по самому токену, поэтому букмекер убеждается в подлинности
    # заявки, не получая ни S_pub, ни client_id.
    @abstractmethod
    def sign_as_token(self, client_secret: str, bookmaker_id: str, payload: dict) -> str:
        pass

    @abstractmethod
    def verify_token_signature(self, token: str, bookmaker_id: str, payload: dict, signature: str) -> bool:
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

    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str, s_pub: str = "") -> bool:
        return zk_proof.startswith(f"schnorr_zk:{token}:")

    def sign_as_token(self, client_secret: str, bookmaker_id: str, payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return "schnorr-sig:noop:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]

    def verify_token_signature(self, token: str, bookmaker_id: str, payload: dict, signature: str) -> bool:
        return signature.startswith("schnorr-sig:noop:")


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
        canonical_payload = self.canonical(actor, action, payload)
        payload_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        current_hash = hashlib.sha256(f"{payload_hash}:{prev_hash}".encode("utf-8")).hexdigest()
        return payload_hash, current_hash

    def canonical(self, actor: str, action: str, payload: dict) -> str:
        return json.dumps(
            {"actor": actor, "action": action, "payload": payload},
            sort_keys=True,
            ensure_ascii=False,
        )

    # =========================================================================
    # ЭТАП 3 (РАСЧЁТ)
    # =========================================================================
    def verify_chain(self, rows) -> dict:
        """
        Пересчитывает журнал с самого начала и ищет первое расхождение.

        Проверяются три вещи на каждой записи:
          1. хэш содержимого совпадает с пересчитанным по сохранённому payload;
          2. prev_hash записи равен current_hash предыдущей;
          3. current_hash = SHA-256(payload_hash : prev_hash).

        Поэтому подделать одну старую запись нельзя: придётся пересчитать
        всю цепочку до конца, а её последний корень уже опубликован
        и подписан (см. audit_anchors).
        """
        prev_hash = "0" * 64
        for row in rows:
            payload = json.loads(row.payload_json) if row.payload_json else {}
            expected_payload_hash, expected_current = self.compute_entry_hashes(
                prev_hash, row.actor, row.action, payload
            )
            if row.payload_hash != expected_payload_hash:
                return {"valid": False, "broken_at": row.seq, "reason": "PAYLOAD_TAMPERED"}
            if row.prev_hash != prev_hash:
                return {"valid": False, "broken_at": row.seq, "reason": "CHAIN_BROKEN"}
            if row.current_hash != expected_current:
                return {"valid": False, "broken_at": row.seq, "reason": "HASH_MISMATCH"}
            prev_hash = row.current_hash
        return {"valid": True, "broken_at": None, "reason": None, "root": prev_hash, "entries": len(rows)}


class OutcomeOracle:
    """
    ЭТАП 3: источник исходов событий.

    Исход — это внешний факт, и регулятор не должен иметь возможности
    объявить его сам: иначе он мог бы «назначить» нужный результат и
    перераспределить деньги. Поэтому исход приходит подписанным.

    В демо оракул живёт в том же процессе и подписывается своим ключом из
    KeyVault. На проде это отдельная организация (или несколько, с
    согласованием) и свой ключ, которого у регулятора нет.
    """

    ORACLE_ID = "results_oracle"

    def publish(self, event_id: str, outcome: str) -> dict:
        statement = {
            "event_id": event_id,
            "outcome": outcome,
            "published_at": datetime.utcnow().isoformat(timespec="seconds"),
        }
        return {"statement": statement, "signature": signer_port.sign(self.ORACLE_ID, "", statement)}

    def verify(self, signed: dict) -> bool:
        return signer_port.verify(
            self.ORACLE_ID, "", signed.get("statement", {}), signed.get("signature", "")
        )


# =============================================================================
# ЭТАП 1 (РЕГИСТРАЦИЯ) — РЕАЛЬНЫЕ АЛГОРИТМЫ
#
# Ниже — боевые реализации тех же портов. Классы Noop* выше НЕ удалены:
# они остаются как baseline, и к ним можно вернуться одной строкой в самом
# низу файла. Заменены только те порты, что нужны этапу регистрации;
# TokenPolicy (деривация токенов и ZK) остаётся заглушкой — это этап 2.
# =============================================================================

_VAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance_keys.json")


class KeyVault:
    """
    Заглушка KMS/HSM: долгоживущие ключи сервисов в одном файле.

    Хранит:
      * пары Ed25519 для подписей (регулятор, букмекеры);
      * операционный ключ регулятора для таблицы links.

    На проде это место заменяется на KMS или HSM: ключи не покидают модуль,
    а сервис дергает его по API. Файл нужен, чтобы подписи и шифротексты
    переживали перезапуск процесса.
    """

    def __init__(self, path: str = _VAULT_PATH):
        self.path = path
        self._data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return {"ed25519": {}, "symmetric": {}}

    def _save(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2)

    def signing_key(self, owner_id: str) -> Ed25519PrivateKey:
        """Приватный ключ подписи владельца. Создаётся при первом обращении."""
        stored = self._data["ed25519"].get(owner_id)
        if not stored:
            key = Ed25519PrivateKey.generate()
            stored = key.private_bytes_raw().hex()
            self._data["ed25519"][owner_id] = stored
            self._save()
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(stored))

    def verifying_key_hex(self, owner_id: str) -> str:
        """Публичный ключ владельца в hex — его можно публиковать где угодно."""
        return self.signing_key(owner_id).public_key().public_bytes_raw().hex()

    def symmetric_key(self, name: str) -> bytes:
        """Симметричный ключ сервиса (AES-256). Создаётся при первом обращении."""
        stored = self._data["symmetric"].get(name)
        if not stored:
            stored = secrets.token_bytes(32).hex()
            self._data["symmetric"][name] = stored
            self._save()
        return bytes.fromhex(stored)


key_vault = KeyVault()


def operational_link_key() -> str:
    """
    Операционный ключ регулятора для таблицы links (token -> client_id).

    ВАЖНО, и это осознанное архитектурное решение, а не упрощение:
    регулятор обязан знать, какому клиенту принадлежит токен, иначе он не
    спишет деньги с нужного счёта при расчёте ставки. Поэтому таблица links
    шифруется ключом, который регулятор может открыть сам (защита от выгрузки
    базы, но не от самого регулятора).

    А вот персональные данные (ClientModel.pd_blob) заперты ДРУГИМ ключом,
    который разрезан Шамиром на три доли — его в одиночку не открыть.
    """
    return key_vault.symmetric_key("regulator_links").hex()


class AesGcmSealer(Sealer):
    """
    AES-256-GCM — симметричное шифрование записей.

    GCM, а не просто CBC/CTR: он даёт не только секретность, но и
    аутентификацию. Если кто-то поменяет в базе хотя бы один байт
    шифротекста, расшифровка упадёт с ошибкой, а не вернёт тихо испорченные
    данные. Nonce (12 байт) генерируется заново на каждое шифрование —
    повторно использовать его с тем же ключом нельзя ни в коем случае.
    """

    def generate_dek(self) -> str:
        return secrets.token_bytes(32).hex()

    def seal(self, dek: str, plaintext_dict: dict) -> str:
        key = bytes.fromhex(dek)
        nonce = secrets.token_bytes(12)
        raw = json.dumps(plaintext_dict, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, raw, None)
        return json.dumps({
            "alg": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ct": base64.b64encode(ciphertext).decode("ascii"),
        }, ensure_ascii=False)

    def unseal(self, dek: str, sealed_blob: str) -> dict:
        envelope = json.loads(sealed_blob)
        key = bytes.fromhex(dek)
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ct"])
        raw = AESGCM(key).decrypt(nonce, ciphertext, None)
        return json.loads(raw.decode("utf-8"))


class ShamirCustody(Custody):
    """
    Разделение секрета по схеме Шамира «2 из 3», побайтно в поле GF(2^8).

    Как это работает на одном байте секрета:
        строим прямую  f(x) = секретный_байт + a*x,  где a случайно
        доля №1 = f(1),  доля №2 = f(2),  доля №3 = f(3)
        сам секретный байт стирается

    Одна доля — это одна точка. Через одну точку проходит бесконечно много
    прямых, и каждая даёт своё значение в нуле, поэтому про секрет не
    известно РОВНО НИЧЕГО (не «трудно подобрать», а нет информации вообще).
    Две точки задают прямую однозначно -> f(0) восстанавливается.

    Арифметика идёт не в обычных числах, а в конечном поле GF(2^8) (то же
    поле, что внутри AES) — иначе доли «протекали» бы через размер чисел.
    """

    _EXP = [0] * 512
    _LOG = [0] * 256

    def __init__(self):
        x = 1
        for i in range(255):
            self._EXP[i] = x
            self._LOG[x] = i
            # умножение на 3: x*3 = x*2 XOR x. Именно 3 — генератор этого поля,
            # двойка порождает лишь подгруппу из 51 элемента.
            x ^= (x << 1)
            if x & 0x100:
                x ^= 0x11B                      # неприводимый многочлен AES
        for i in range(255, 512):
            self._EXP[i] = self._EXP[i - 255]

    def _mul(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return self._EXP[self._LOG[a] + self._LOG[b]]

    def _div(self, a: int, b: int) -> int:
        if a == 0:
            return 0
        return self._EXP[(self._LOG[a] - self._LOG[b]) % 255]

    def split_key(self, dek: str) -> Dict[str, str]:
        secret = bytes.fromhex(dek)
        parties = ["client", "regulator", "arbiter"]
        buckets = {idx: bytearray() for idx in (1, 2, 3)}

        for byte in secret:
            a = secrets.randbelow(256)          # случайный наклон прямой
            for idx in (1, 2, 3):
                buckets[idx].append(byte ^ self._mul(a, idx))

        return {
            party: f"shamir-gf256:{idx}:{bytes(buckets[idx]).hex()}"
            for idx, party in zip((1, 2, 3), parties)
        }

    def combine_shares(self, shares: Dict[str, str]) -> Optional[str]:
        points = []
        for payload in shares.values():
            if not payload or not payload.startswith("shamir-gf256:"):
                continue
            _, idx_str, hex_body = payload.split(":", 2)
            points.append((int(idx_str), bytes.fromhex(hex_body)))

        if len(points) < 2:                     # порога нет — не восстанавливаем ничего
            return None

        points = points[:2]
        length = len(points[0][1])
        recovered = bytearray()

        # интерполяция Лагранжа в точке x = 0
        for pos in range(length):
            acc = 0
            for i, (xi, body_i) in enumerate(points):
                num, den = 1, 1
                for j, (xj, _) in enumerate(points):
                    if i == j:
                        continue
                    num = self._mul(num, xj)
                    den = self._mul(den, xi ^ xj)
                acc ^= self._mul(body_i[pos], self._div(num, den))
            recovered.append(acc)

        return bytes(recovered).hex()


class Ed25519SignerVerifier(SignerVerifier):
    """
    Ed25519 — подписи заявок клиента, квитанций букмекера и справок регулятора.

    Ключи берутся из KeyVault по signer_id, поэтому старые вызовы вида
    sign("bk_alpha", "", payload) продолжают работать без изменений.
    Подписывается канонический JSON (sort_keys=True) — иначе одна и та же
    структура с другим порядком полей дала бы другую подпись.
    """

    def _canonical(self, payload: dict) -> bytes:
        return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")

    def sign(self, signer_id: str, private_key: str, payload: dict) -> str:
        key = key_vault.signing_key(signer_id)
        signature = key.sign(self._canonical(payload))
        return f"ed25519:{signer_id}:{signature.hex()}"

    def verify(self, expected_signer_id: str, public_key: str, payload: dict, signature: str) -> bool:
        prefix = f"ed25519:{expected_signer_id}:"
        if not signature or not signature.startswith(prefix):
            return False
        try:
            raw_sig = bytes.fromhex(signature[len(prefix):])
            pub_hex = public_key or key_vault.verifying_key_hex(expected_signer_id)
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            pub.verify(raw_sig, self._canonical(payload))
            return True
        except (InvalidSignature, ValueError):
            return False


class SchnorrIdentity:
    """
    Публичная анкета клиента S_pub = s*G и доказательство владения ею.

    Зачем это вообще нужно:
      * регулятор НЕ ДОЛЖЕН знать секрет s — иначе он сам вычислит все токены
        клиента у всех букмекеров, и вся схема обессмысливается;
      * но ему нужно к чему-то привязать KYC и что-то подписать в справке.
        Этим «чем-то» и становится точка S_pub;
      * доказательство Шнорра не даёт зарегистрировать чужую точку: без
        знания s построить его невозможно.

    Сам протокол и арифметика кривой — в common/curve25519.py.
    """

    def generate_secret(self) -> str:
        return f"{curve25519.random_scalar():064x}"

    def public_point(self, secret_hex: str) -> str:
        s = int(secret_hex, 16)
        return curve25519.encode_point(curve25519.scalar_mult(s, curve25519.G))

    def prove(self, secret_hex: str, context: str) -> str:
        return curve25519.prove_knowledge(int(secret_hex, 16), context)

    def verify(self, s_pub_hex: str, proof: str, context: str) -> bool:
        return curve25519.verify_knowledge(s_pub_hex, proof, context)


class Ed25519CredentialService(CredentialService):
    """
    Справка регулятора: 18+, KYC пройден, самоограничения нет, срок действия.

    Подписывается Ed25519 над S_pub клиента, а НЕ над его именем — поэтому
    справку можно показать букмекеру, не раскрывая личность.

    Это baseline-вариант. Его ограничение: подпись приходится отдавать
    целиком, а она уникальна, то есть служит опознавательным знаком и
    связывает визиты клиента между собой. Лечится переходом на BBS+
    (этап M5), где предъявляется не подпись, а доказательство владения ею
    с раскрытием только нужных полей. Порт при этом не меняется.
    """

    ISSUER_ID = "regulator"
    TTL_HOURS = 24

    def issue_credential(self, client_id: str, client_secret: str, claims: dict) -> dict:
        issued_at = datetime.utcnow()
        body = {
            "s_pub": claims.get("s_pub", ""),
            "adult": bool(claims.get("adult")),
            "kyc_ok": bool(claims.get("kyc_ok")),
            "not_excluded": bool(claims.get("not_excluded")),
            "limits_ok": bool(claims.get("limits_ok")),
            "issued_at": issued_at.isoformat(timespec="seconds"),
            "expires_at": (issued_at + timedelta(hours=self.TTL_HOURS)).isoformat(timespec="seconds"),
        }
        signature = signer_port.sign(self.ISSUER_ID, "", body)
        return {
            "cred_id": f"cred_{uuid.uuid4().hex[:8]}",
            "claims": body,
            "issuer_pub": key_vault.verifying_key_hex(self.ISSUER_ID),
            "signature": signature,
        }

    def create_presentation(self, credential: dict, token: str, bookmaker_id: str) -> dict:
        # ЭТАП 2: здесь появится выборочное раскрытие на BBS+.
        return {
            "token": token,
            "bookmaker_id": bookmaker_id,
            "revealed_claims": credential.get("claims", {}),
            "signature": credential.get("signature", ""),
            "issuer_pub": credential.get("issuer_pub", ""),
        }

    def verify_presentation(self, presentation: dict) -> Tuple[bool, dict]:
        claims = presentation.get("revealed_claims", {})
        sig_ok = signer_port.verify(
            self.ISSUER_ID,
            presentation.get("issuer_pub", ""),
            claims,
            presentation.get("signature", ""),
        )
        not_expired = claims.get("expires_at", "") > datetime.utcnow().isoformat(timespec="seconds")
        ok = sig_ok and not_expired and all([
            claims.get("adult", False),
            claims.get("kyc_ok", False),
            claims.get("not_excluded", False),
            claims.get("limits_ok", False),
        ])
        return ok, claims


class Curve25519TokenPolicy(TokenPolicy):
    """
    =========================================================================
    ЭТАП 2 (СТАВКА) — ядро всего проекта.

    Токен вычисляет САМ КЛИЕНТ на своём устройстве:

        H_B   = hash_to_curve(идентификатор_конторы)     одинаково у всех
        P_B   = s * H_B                                  это и есть токен

    Что отсюда следует:
      * у одной конторы токен всегда один и тот же — букмекер спокойно
        копит по нему историю и считает коэффициент;
      * у разных контор токены разные и вычислительно не связываются:
        чтобы увидеть за ними общий s, надо решить задачу Диффи-Хеллмана;
      * обратно из токена секрет не достаётся.

    Чтобы клиент не завёл себе второй токен у той же конторы из левого
    секрета, к токену прикладывается доказательство Шаума-Педерсена:
    «за S_pub и за P_B стоит ОДИН И ТОТ ЖЕ s». Проверяет его регулятор,
    у которого хранится S_pub — см. /api/regulator/tokens/verify.

    На проде это место переезжает на Ristretto255 из libsodium: меняется
    представление точек, формулы и смысл остаются теми же.
    =========================================================================
    """

    CONTEXT = "burmalda:token-binding:v1"

    def _h(self, bookmaker_id: str):
        return curve25519.hash_to_curve(bookmaker_id)

    def derive_token(self, client_secret: str, bookmaker_id: str) -> Tuple[str, str]:
        s = int(client_secret, 16)
        h_point = self._h(bookmaker_id)
        token = curve25519.encode_point(curve25519.scalar_mult(s, h_point))
        proof = curve25519.prove_dleq(s, h_point, f"{self.CONTEXT}:{bookmaker_id}")
        return token, proof

    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str, s_pub: str = "") -> bool:
        if not s_pub:
            # Без публичной анкеты проверять нечего: именно сравнение с S_pub
            # и отличает настоящий токен от выдуманного.
            return False
        return curve25519.verify_dleq(
            s_pub, token, self._h(bookmaker_id), zk_proof, f"{self.CONTEXT}:{bookmaker_id}"
        )

    def sign_as_token(self, client_secret: str, bookmaker_id: str, payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return curve25519.sign_with_base(int(client_secret, 16), self._h(bookmaker_id), canonical)

    def verify_token_signature(self, token: str, bookmaker_id: str, payload: dict, signature: str) -> bool:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return curve25519.verify_with_base(token, self._h(bookmaker_id), canonical, signature)


class OddsCommitment:
    """
    ЭТАП 2: обязательство букмекера на коэффициент.

    Букмекер публикует хэш коэффициента ДО исхода события, а сам
    коэффициент вместе со случайной солью раскрывает ПОСЛЕ. Соль
    обязательна: без неё коэффициентов мало, и хэш подбирается перебором
    за секунду, то есть обязательство ничего не скрывает.
    """

    def commit(self, payload: dict) -> Tuple[str, str]:
        salt = secrets.token_hex(16)
        return self._digest(salt, payload), salt

    def verify(self, commitment: str, salt: str, payload: dict) -> bool:
        return secrets.compare_digest(commitment, self._digest(salt, payload))

    def _digest(self, salt: str, payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(f"{salt}:{canonical}".encode("utf-8")).hexdigest()


# =============================================================================
# Единые экземпляры крипто-портов для всех сервисов.
# Чтобы вернуться к baseline без криптографии — замените реальный класс
# на соответствующий Noop* в строке ниже. Больше ничего менять не нужно.
# =============================================================================
signer_port = Ed25519SignerVerifier()        # было NoopSignerVerifier
sealer_port = AesGcmSealer()                 # было NoopSealer
custody_port = ShamirCustody()               # было NoopCustody
token_policy_port = Curve25519TokenPolicy()  # было NoopTokenPolicy
cred_service_port = Ed25519CredentialService()   # было NoopCredentialService
audit_chain_port = HashChainAuditPort()
schnorr_port = SchnorrIdentity()             # ЭТАП 1: новый порт, S_pub и доказательство
odds_commitment_port = OddsCommitment()      # ЭТАП 2: новый порт, обязательство на коэффициент
outcome_oracle_port = OutcomeOracle()        # ЭТАП 3: новый порт, подписанные исходы событий

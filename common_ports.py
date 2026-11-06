# common_ports.py
import hashlib
import json
import secrets
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Tuple


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
    Baseline (M0): Подпись формируется как строка 'dev:{signer_id}:{hash}',
    проверка выполняется по префиксу и контрольной сумме.
    """
    def sign(self, signer_id: str, private_key: str, payload: dict) -> str:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M1: Цифровая подпись Ed25519 / Schnorr]
        # Зачем нужна:
        #   1. Клиент подписывает ставку (client_sig) ключом, привязанным к секрету s,
        #      чтобы букмекер не мог списать средства с чужого токена.
        #   2. Букмекер подписывает квитанцию (bookmaker_sig) и делает обязательство
        #      (commitment) на коэффициент до исхода матча.
        # Как правильно встроить:
        #   1. Сериализовать payload в канонический вид:
        #      msg = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        #   2. Использовать библиотеку cryptography.hazmat.primitives.asymmetric.ed25519
        #      или PyNaCl (SigningKey):
        #      sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
        #      return sk.sign(msg).hex()
        # ---------------------------------------------------------------------
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        return f"dev:{signer_id}:{digest}"

    def verify(self, expected_signer_id: str, public_key: str, payload: dict, signature: str) -> bool:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M1: Проверка подписи Verify(X, документ, подпись)]
        # Как правильно встроить:
        #   1. Восстановить открытый ключ X = x * G из public_key:
        #      pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        #   2. Вызвать pk.verify(bytes.fromhex(signature), msg). При ошибке
        #      InvalidSignature вернуть False.
        # ---------------------------------------------------------------------
        if not signature or not signature.startswith(f"dev:{expected_signer_id}:"):
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
    Baseline (M0): Хранит персональные данные и связь «токен -> клиент»
    в открытом JSON-формате для отладки взаимодействия сервисов.
    """
    def generate_dek(self) -> str:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M2: Генерация ключа шифрования данных (DEK)]
        # Как правильно встроить:
        #   Использовать системный криптографический генератор случайных чисел
        #   CSPRNG (/dev/urandom через os.urandom(32) или secrets.token_bytes(32))
        #   для получения 256-битного случайного ключа DEK.
        # ---------------------------------------------------------------------
        return f"dek_{secrets.token_hex(16)}"

    def seal(self, dek: str, plaintext_dict: dict) -> str:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M2: Симметричное шифрование AES-256-GCM]
        # Где применяется:
        #   1. Шифрование поля pd_blob в таблице clients.
        #   2. Шифрование поля client_ref_sealed ("секрет s / токен принадлежит Иванову")
        #      в таблице links регулятора.
        # Как правильно встроить:
        #   1. Использовать cryptography.hazmat.primitives.ciphers.aead.AESGCM:
        #      aesgcm = AESGCM(bytes.fromhex(dek))
        #      nonce = os.urandom(12)  # 96-битный уникальный вектор инициализации
        #      ct = aesgcm.encrypt(nonce, json.dumps(plaintext_dict).encode('utf-8'), associated_data=None)
        #   2. Стереть открытый DEK и s из оперативной памяти после разделения DEK на доли.
        #   3. Вернуть base64/hex от (nonce + ct), где GCM-тег гарантирует защиту от подмены байтов в БД.
        # ---------------------------------------------------------------------
        return json.dumps({"_sealed_with": dek[:12], "data": plaintext_dict}, ensure_ascii=False)

    def unseal(self, dek: str, sealed_blob: str) -> dict:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M2: Расшифровка AES-256-GCM]
        # Как правильно встроить:
        #   После восстановления DEK (или точки x*R) вызвать:
        #   plaintext = aesgcm.decrypt(nonce, ct, associated_data=None)
        #   При повреждении хотя бы одного байта в БД AES-GCM выбросит InvalidTag.
        # ---------------------------------------------------------------------
        parsed = json.loads(sealed_blob)
        return parsed.get("data", parsed)


# =============================================================================
# 3. ПОРТ РАЗДЕЛЕНИЯ СЕКРЕТА И ПОРОГОВОГО РАСКРЫТИЯ: Custody (Этапы M2 -> M5)
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
    Baseline (M0): Имитирует схему «2 из 3» (client, regulator, arbiter).
    Отдаёт ключ DEK, если собрано минимум 2 доли из 3.
    """
    def split_key(self, dek: str) -> Dict[str, str]:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M2 (Схема Шамира) И ЭТАП M5 (Пороговый Эль-Гамаль)]
        # Способ 1 (Этап M2 — Схема разделения секрета Шамира «2 из 3»):
        #   1. Представить 256-битный DEK как элемент конечного поля K в GF(p).
        #   2. Выбрать случайный коэффициент a через CSPRNG и задать прямую:
        #      f(x) = (K + a * x) mod p.
        #   3. Вычислить 3 точки для участников:
        #      - client (x=1):    share_1 = f(1)
        #      - regulator (x=2): share_2 = f(2)
        #      - arbiter (x=3):   share_3 = f(3)
        #   4. Удалить исходный DEK (K) и коэффициент a из памяти.
        #
        # Способ 2 (Этап M5 — Пороговый Эль-Гамаль без сборки ключа на кривой Ristretto255):
        #   1. Секретный ключ системы x разделен на доли x_1, x_2, x_3 (или создан через DKG),
        #      публичный ключ системы X = x * G.
        #   2. При шифровании DEK берется случайное число r, вычисляется R = r * G,
        #      а DEK маскируется точкой r * X. В БД сохраняется пара (R, masked_DEK).
        # ---------------------------------------------------------------------
        return {
            "client": f"share:1:{dek}",
            "regulator": f"share:2:{dek}",
            "arbiter": f"share:3:{dek}",
        }

    def combine_shares(self, shares: Dict[str, str]) -> Optional[str]:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M2 (Интерполяция Лагранжа) И ЭТАП M5 (Пороговое дешифрование)]
        # Способ 1 (Этап M2 — Сборка по Шамиру из 2 долей):
        #   По любым двум точкам (x_i, y_i) и (x_j, y_j) восстановить свободный член
        #   полинома Лагранжа в нуле: K = f(0) = (y_i * x_j / (x_j - x_i) + y_j * x_i / (x_i - x_j)) mod p.
        #
        # Способ 2 (Этап M5 — Расшифровка без сборки ключа + Доказательство Шаума-Педерсена):
        #   1. Каждая из двух сторон (например, регулятор и арбитр) берет точку R из БД
        #      и вычисляет частичное дешифрование своей долей: d_i = x_i * R.
        #   2. К каждому d_i прикладывается ZK-доказательство Шаума-Педерсена о том,
        #      что d_i посчитан именно с истинной долей x_i (защита от саботажа раскрытия).
        #   3. Регулятор складывает точки с публичными коэффициентами Лагранжа:
        #      lambda_1 * d_1 + lambda_2 * d_2 = (lambda_1 * x_1 + lambda_2 * x_2) * R = x * R = r * X.
        #   4. Секретный ключ x ни в один момент времени не собирается целиком в памяти!
        # ---------------------------------------------------------------------
        if len(shares) < 2:
            return None
        first_share = next(iter(shares.values()))
        parts = first_share.split(":", 2)
        return parts[2] if len(parts) == 3 else first_share


# =============================================================================
# 4. ПОРТ ГЕНЕРАЦИИ И ПРОВЕРКИ ТОКЕНОВ: TokenPolicy (Этап M3 -> Ristretto255 + Schnorr ZK)
# =============================================================================
class TokenPolicy(ABC):
    @abstractmethod
    def derive_token(self, client_secret: str, bookmaker_id: str) -> Tuple[str, str]:
        pass

    @abstractmethod
    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str) -> bool:
        pass


class NoopTokenPolicy(TokenPolicy):
    """
    Baseline (M0): Детерминированный псевдоним и заглушка ZK-доказательства.
    """
    def derive_token(self, client_secret: str, bookmaker_id: str) -> Tuple[str, str]:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M3: Hash-to-Curve (Ristretto255) + Протокол Шнорра (ZK)]
        # Где применяется:
        #   Выполняется локально на устройстве клиента при входе к букмекеру.
        # Как правильно встроить:
        #   1. Вычисление токена (односторонняя арифметика на эллиптической кривой Ristretto255):
        #      H_B = HashToCurve("bookmaker:" + bookmaker_id)  # базовая точка конторы Б
        #      P_B = s * H_B                                   # постоянный токен клиента у конторы Б
        #      Свойства:
        #        - у одной конторы токен всегда одинаковый (P_B);
        #        - у другой конторы точка H_C другая -> токен P_C = s * H_C не связывается с P_B;
        #        - вычислить секрет s из P_B невозможно (задача дискретного логарифма).
        #   2. Построение ZK-доказательства Шнорра (защита от мультиаккаунтов):
        #      Клиент доказывает: «Я знаю такой секрет s, что P_B = s * H_B, и именно этот s
        #      записан внутри моей справки BBS+ от регулятора», не раскрывая сам s:
        #        - Шаг 1 (Commitment): выбрать случайное k (CSPRNG), вычислить R = k * H_B.
        #        - Шаг 2 (Challenge):  c = SHA256(H_B || P_B || R) (преобразование Фиата-Шамира).
        #        - Шаг 3 (Response):   z = (k + c * s) mod l.
        #        - Доказательство zk_proof = (R, z).
        # ---------------------------------------------------------------------
        raw = f"{client_secret}:{bookmaker_id}".encode("utf-8")
        token_hash = hashlib.sha256(raw).hexdigest()[:12].upper()
        token = f"P_{bookmaker_id.upper()}_{token_hash}"
        zk_proof = f"schnorr_zk_noop:{token}:{hashlib.sha256(raw).hexdigest()[:8]}"
        return token, zk_proof

    def verify_token_proof(self, token: str, bookmaker_id: str, zk_proof: str) -> bool:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M3: Проверка ZK-доказательства Шнорра у букмекера]
        # Как правильно встроить:
        #   1. Распаковать zk_proof на точку R и скаляр z.
        #   2. Вычислить H_B = HashToCurve("bookmaker:" + bookmaker_id) и вызов c = SHA256(H_B || P_B || R).
        #   3. Проверить равенство на кривой Ristretto255:
        #      z * H_B == R + c * P_B
        #      (так как (k + c*s)*H_B = k*H_B + c*(s*H_B) = R + c*P_B).
        #   Проверка занимает ~1-2 мс и гарантирует, что один человек не может завести
        #   второй аккаунт у того же букмекера.
        # ---------------------------------------------------------------------
        return zk_proof.startswith(f"schnorr_zk_noop:{token}:")


# =============================================================================
# 5. ПОРТ АНОНИМНЫХ УДОСТОВЕРЕНИЙ ДОПУСКА: CredentialService (Этап M4 -> BBS+)
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
    """
    Baseline (M0): Выпускает JSON-удостоверение и формирует презентацию.
    На этапе M0 букмекер дополнительно проверяет статус через REST-эндпоинт регулятора.
    """
    def issue_credential(self, client_id: str, client_secret: str, claims: dict) -> dict:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M4: Выдача слепой/многоатрибутной подписи BBS+ на BLS12-381]
        # Где применяется:
        #   При прохождении KYC у регулятора (POST /v1/credentials/issue).
        # Как правильно встроить:
        #   Регулятор подписывает вектор атрибутов M = [s, adult=True, kyc_ok=True,
        #   not_excluded=True, expires_at] своим секретным ключом BBS+ на кривой BLS12-381:
        #   bbs_sig = BBSPlus.sign(regulator_sk, messages=M)
        #   Обычная подпись Ed25519 здесь не подходит, так как её нельзя показать по частям!
        # ---------------------------------------------------------------------
        return {
            "cred_id": f"cred_{uuid.uuid4().hex[:10]}",
            "claims": claims,
            "bbs_signature_placeholder": f"bbs_sig_reg_{uuid.uuid4().hex[:16]}",
        }

    def create_presentation(self, credential: dict, token: str, bookmaker_id: str) -> dict:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M4: Выборочное раскрытие BBS+ (Selective Disclosure ZK Proof)]
        # Где применяется:
        #   На стороне клиента перед отправкой ставки букмекеру.
        # Как правильно встроить:
        #   Клиент генерирует несвязываемое (unlinkable) ZK-доказательство владения
        #   подписью BBS+ регулятора, открывая ТОЛЬКО булевы флаги:
        #   revealed = {adult: True, kyc_ok: True, not_excluded: True, limits_ok: True},
        #   атрибут s остается скрытым (и связывается с токеном P_B = s*H_B через общий ZK-пруф),
        #   а сама уникальная подпись регулятора НЕ передается (чтобы конторы не склеили клиента).
        # ---------------------------------------------------------------------
        return {
            "token": token,
            "bookmaker_id": bookmaker_id,
            "revealed_claims": credential.get("claims", {}),
            "zk_bbs_proof": f"bbs_proof_noop:{token}",
        }

    def verify_presentation(self, presentation: dict) -> Tuple[bool, dict]:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M4: Офлайн-проверка доказательства BBS+ букмекером]
        # Как правильно встроить:
        #   На этапе M4 букмекер проверяет BBS+ доказательство локально за 5-15 мс
        #   с помощью публичного ключа регулятора БЕЗ синхронного REST-запроса к регулятору:
        #   is_valid = BBSPlus.verify_proof(regulator_pk, proof, revealed_claims)
        # ---------------------------------------------------------------------
        proof = presentation.get("zk_bbs_proof", "")
        claims = presentation.get("revealed_claims", {})
        ok = proof.startswith("bbs_proof_noop:") and all([
            claims.get("adult", False),
            claims.get("kyc_ok", False),
            claims.get("not_excluded", False),
            claims.get("limits_ok", False),
        ])
        return ok, claims


# =============================================================================
# 6. ПОРТ НЕПЕРЕЗАПИСЫВАЕМОГО ЖУРНАЛА АУДИТА: AuditLogPort (Этап M1 -> SHA-256 Chain)
# =============================================================================
class AuditLogPort(ABC):
    @abstractmethod
    def compute_entry_hashes(self, prev_hash: str, actor: str, action: str, payload: dict) -> Tuple[str, str]:
        pass


class HashChainAuditPort(AuditLogPort):
    """
    Вычисляет хэш полезной нагрузки и сцепляет запись с предыдущим хэшем (SHA-256).
    """
    def compute_entry_hashes(self, prev_hash: str, actor: str, action: str, payload: dict) -> Tuple[str, str]:
        # ---------------------------------------------------------------------
        # [CRYPTO HOOK — ЭТАП M1: Криптографическая хэш-цепочка (SHA-256 / ГОСТ Стрибог)]
        # Зачем нужна:
        #   Каждая запись журнала держит за руку предыдущую:
        #   hash_i = SHA256(payload_hash_i || prev_hash_{i-1}).
        #   Любая попытка изменить старую ставку, коэффициент или скрыть факт
        #   деанонимизации задним числом разрушит всю цепочку до опубликованного корня (/v1/audit/root).
        # ---------------------------------------------------------------------
        canonical_payload = json.dumps(
            {"actor": actor, "action": action, "payload": payload},
            sort_keys=True,
            ensure_ascii=False,
        )
        payload_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        chain_input = f"{payload_hash}:{prev_hash}".encode("utf-8")
        current_hash = hashlib.sha256(chain_input).hexdigest()
        return payload_hash, current_hash


# =============================================================================
# 7. ПОРТ ИСТОЧНИКА ИСХОДОВ СОБЫТИЙ: OutcomeSource
# =============================================================================
class OutcomeSource(ABC):
    @abstractmethod
    def verify_outcome(self, event_id: str, outcome: str, source: str) -> bool:
        pass


class ManualOutcomeSource(OutcomeSource):
    """
    Baseline (M0): Ручной ввод результата с проверкой формата.
    В боевом режиме заменяется на проверку подписи оракула / официального спортивного фида.
    """
    def verify_outcome(self, event_id: str, outcome: str, source: str) -> bool:
        return bool(event_id and outcome and source)
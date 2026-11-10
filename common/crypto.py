"""
Вся криптография проекта в одном файле — её немного, и так её видно целиком.

  AES-256-GCM   шифрование персональных данных. Делается ТОЛЬКО на телефоне
                клиента. Ни Бурмалда, ни букмекер, ни регулятор открытого
                текста не видят.

  XOR           разделение ключа AES на две доли, схема «2 из 2».
                Доля А уходит в Бурмалду и дальше регулятору.
                Доля Б остаётся на телефоне и уезжает букмекеру в момент
                подтверждения ставки.

Подписей в схеме нет: мы договорились, что если приложение разблокировано,
клиент считается доверенным, и букмекеру проверять нечего.
"""

import json
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canon(obj) -> bytes:
    """Каноническая форма: ключи отсортированы, пробелов нет.

    Нужна затем, чтобы один и тот же объект, собранный в разных сервисах,
    давал байт в байт одинаковый результат.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# AES-256-GCM
#
# GCM не только шифрует, но и заверяет: если в шифротексте поменяли хотя бы
# один бит, расшифрование падает с ошибкой, а не выдаёт мусор. Поэтому
# подделать архив незаметно нельзя.
#
# Nonce (12 случайных байт) новый на каждое шифрование и хранится рядом с
# шифротекстом — он не секретный. Повторное использование nonce с тем же
# ключом ломает GCM полностью, поэтому он всегда случайный.
# ---------------------------------------------------------------------------


def new_aes_key() -> bytes:
    """32 байта из CSPRNG — криптографически стойкого генератора ОС."""
    return secrets.token_bytes(32)


def aes_encrypt(key: bytes, obj) -> str:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, canon(obj), None)
    return (nonce + ct).hex()


def aes_decrypt(key: bytes, blob_hex: str):
    raw = bytes.fromhex(blob_hex)
    return json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], None).decode("utf-8"))


# ---------------------------------------------------------------------------
# XOR-разделение ключа, «2 из 2»
#
# Доля А — это просто 32 случайных байта.
# Доля Б — это ключ, побитово сложенный с долей А.
#
# Любая ОДНА доля является равномерным случайным мусором: по ней о ключе
# нельзя сказать ничего — ровно ничего, а не «мало». Для каждого
# предполагаемого ключа существует ровно одна подходящая вторая доля,
# поэтому все ключи остаются равновероятными.
#
# Две доли вместе дают ключ обратно, потому что (k XOR a) XOR a == k.
# ---------------------------------------------------------------------------


def xor_split(key: bytes) -> tuple[str, str]:
    share_a = secrets.token_bytes(len(key))
    share_b = bytes(x ^ y for x, y in zip(key, share_a))
    return share_a.hex(), share_b.hex()


def xor_combine(share_a_hex: str, share_b_hex: str) -> bytes:
    a, b = bytes.fromhex(share_a_hex), bytes.fromhex(share_b_hex)
    if len(a) != len(b):
        raise ValueError("доли разной длины")
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Мелочи
# ---------------------------------------------------------------------------


def random_id(prefix: str = "", nbytes: int = 8) -> str:
    return f"{prefix}{secrets.token_hex(nbytes)}"


def sha256_hex(obj) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(canon(obj))
    return h.finalize().hex()

"""
=============================================================================
ЭТАП 1 (РЕГИСТРАЦИЯ) — НОВЫЙ ФАЙЛ
Арифметика эллиптической кривой Edwards25519 на чистом Python.

Нужен ровно для одной вещи: вычислить публичную точку клиента S_pub = s*G
и построить/проверить доказательство Шнорра «я знаю s, стоящий за S_pub».

Почему своя реализация, а не библиотека: нам нужно именно скалярное
умножение точки (s*G), а библиотека `cryptography` наружу его не отдаёт —
она даёт только готовые подписи. Код ниже — стандартная референсная
арифметика Ed25519, без оптимизаций: читаемость важнее скорости,
одно умножение занимает порядка 2-3 мс, этого достаточно.

На проде это место заменяется на Ristretto255 из libsodium (pynacl).
Математика та же, меняется только представление точек.
=============================================================================
"""

import hashlib
import secrets
from typing import Tuple

# --- параметры кривой Edwards25519 (RFC 8032) --------------------------------
P = 2 ** 255 - 19                                                   # модуль поля
L = 2 ** 252 + 27742317777372353535851937790883648493               # порядок базовой точки
D = (-121665 * pow(121666, P - 2, P)) % P                           # коэффициент кривой
I = pow(2, (P - 1) // 4, P)                                         # sqrt(-1) mod P

Point = Tuple[int, int]
IDENTITY: Point = (0, 1)


def _recover_x(y: int, sign: int) -> int:
    """Восстанавливает x по y из уравнения кривой -x^2 + y^2 = 1 + d*x^2*y^2."""
    yy = (y * y) % P
    u = (yy - 1) % P
    v = (D * yy + 1) % P
    # каноническая формула: x = u * v^3 * (u * v^7)^((p-5)/8)
    v3 = (v * v % P) * v % P
    v7 = (v3 * v3 % P) * v % P
    x = (u * v3) % P * pow((u * v7) % P, (P - 5) // 8, P) % P
    vxx = (v * x % P) * x % P
    if (vxx - u) % P != 0:
        if (vxx + u) % P == 0:
            x = x * I % P
        else:
            raise ValueError("точка не лежит на кривой")
    if x % 2 != sign:
        x = (P - x) % P
    return x


_D2 = (2 * D) % P


def _to_ext(point: Point):
    """Афинная точка (x, y) -> расширенные координаты (X, Y, Z, T)."""
    x, y = point
    return (x, y, 1, x * y % P)


def _to_affine(ext) -> Point:
    """Обратно в (x, y). Одно обращение по модулю на всё умножение, а не на каждый шаг."""
    x, y, z, _ = ext
    inv_z = pow(z, P - 2, P)
    return (x * inv_z % P, y * inv_z % P)


def _ext_add(p1, p2):
    """Сложение в расширенных координатах (add-2008-hwcd-3) — без деления."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * _D2 % P * t2 % P
    d = z1 * 2 * z2 % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_add(p1: Point, p2: Point) -> Point:
    """Сложение точек на скрученной кривой Эдвардса (a = -1). Афинный API."""
    return _to_affine(_ext_add(_to_ext(p1), _to_ext(p2)))


def scalar_mult(k: int, point: Point) -> Point:
    """Умножение точки на число методом удвоения-сложения. Это и есть s*G."""
    result = _to_ext(IDENTITY)
    addend = _to_ext(point)
    k = k % L
    while k > 0:
        if k & 1:
            result = _ext_add(result, addend)
        addend = _ext_add(addend, addend)
        k >>= 1
    return _to_affine(result)


# базовая точка G
_BY = 4 * pow(5, P - 2, P) % P
G: Point = (_recover_x(_BY, 0), _BY)


def encode_point(point: Point) -> str:
    """Точка -> 32 байта (сжатая форма: y + знаковый бит x) -> hex-строка."""
    x, y = point
    buf = bytearray(y.to_bytes(32, "little"))
    buf[31] |= (x & 1) << 7
    return bytes(buf).hex()


def decode_point(hex_str: str) -> Point:
    """hex-строка -> точка."""
    raw = bytearray(bytes.fromhex(hex_str))
    sign = raw[31] >> 7
    raw[31] &= 0x7F
    y = int.from_bytes(bytes(raw), "little")
    return (_recover_x(y, sign), y)


def random_scalar() -> int:
    """CSPRNG: случайное число в [1, L-1]."""
    return secrets.randbelow(L - 1) + 1


# --- доказательство Шнорра (неинтерактивное, преобразование Фиата-Шамира) ----

def prove_knowledge(secret: int, context: str) -> str:
    """
    Доказывает знание s, не раскрывая s.
        1. берём случайное k, считаем R = k*G        (обязательство)
        2. c = SHA-512(R || S_pub || context) mod L  (вызов, считаем сами)
        3. z = k + c*s mod L                         (ответ)
    Наружу уходит только (R, z).
    """
    s_pub = scalar_mult(secret, G)
    k = random_scalar()
    r_point = scalar_mult(k, G)
    c = _challenge(r_point, s_pub, context)
    z = (k + c * secret) % L
    return f"schnorr-ed25519:R={encode_point(r_point)}:z={z:064x}"


def verify_knowledge(s_pub_hex: str, proof: str, context: str) -> bool:
    """
    Проверяет равенство z*G == R + c*S_pub.
    Если равенство сошлось — доказывающий знает s. Сам s при этом не раскрыт.
    """
    try:
        if not proof.startswith("schnorr-ed25519:"):
            return False
        _, r_part, z_part = proof.split(":", 2)
        r_point = decode_point(r_part[2:])
        z = int(z_part[2:], 16)
        s_pub = decode_point(s_pub_hex)

        c = _challenge(r_point, s_pub, context)
        left = scalar_mult(z, G)
        right = point_add(r_point, scalar_mult(c, s_pub))
        return left == right
    except Exception:
        return False


def _challenge(r_point: Point, s_pub: Point, context: str) -> int:
    material = (encode_point(r_point) + encode_point(s_pub) + context).encode("utf-8")
    return int.from_bytes(hashlib.sha512(material).digest(), "little") % L


# =============================================================================
# ЭТАП 2 (СТАВКА)
# =============================================================================

def hash_to_curve(label: str) -> Point:
    """
    Превращает строку (идентификатор букмекера) в точку кривой H_B.

    Метод «пробуй и увеличивай счётчик»: хэшируем метку, пробуем прочитать
    результат как координату y, и если такая точка на кривой существует —
    берём её. Иначе увеличиваем счётчик и пробуем снова.

    В конце умножаем на 8 (кофактор кривой), чтобы точка гарантированно
    попала в подгруппу простого порядка. Без этого шага появляются атаки
    малых подгрупп.

    Важно: H_B получается ДЕТЕРМИНИРОВАННО и одинаково у всех сторон,
    при этом никто не знает такого числа t, что H_B = t*G. Это и даёт
    несвязываемость токенов между букмекерами.
    """
    cached = _H2C_CACHE.get(label)
    if cached is not None:
        return cached

    for counter in range(256):
        digest = hashlib.sha512(f"burmalda-hash-to-curve-v1:{label}".encode("utf-8")
                                + bytes([counter])).digest()[:32]
        buf = bytearray(digest)
        sign = buf[31] >> 7
        buf[31] &= 0x7F
        y = int.from_bytes(bytes(buf), "little")
        if y >= P:
            continue
        try:
            point = (_recover_x(y, sign), y)
        except ValueError:
            continue
        point = scalar_mult(8, point)           # очистка кофактора
        if point == IDENTITY:
            continue
        _H2C_CACHE[label] = point
        return point

    raise ValueError(f"не удалось отобразить метку {label!r} в точку кривой")


_H2C_CACHE: dict = {}


# --- доказательство Шаума-Педерсена (равенство дискретных логарифмов) --------

def prove_dleq(secret: int, h_point: Point, context: str) -> str:
    """
    Доказывает, что ОДИН И ТОТ ЖЕ секрет s стоит сразу за двумя точками:
        S_pub = s*G        (публичная анкета, её подписал регулятор)
        P_B   = s*H_B      (токен у конкретного букмекера)
    При этом сам s не раскрывается.

    Именно это и закрывает мультиаккаунт: второй токен у того же букмекера
    пришлось бы считать из другого s, а для него доказательство не сойдётся,
    потому что S_pub в анкете остался прежним.

    Схема та же, что у Шнорра, только обязательство берётся сразу по двум
    основаниям — G и H_B — с одним и тем же случайным k.
    """
    s_pub = scalar_mult(secret, G)
    p_token = scalar_mult(secret, h_point)
    k = random_scalar()
    r1 = scalar_mult(k, G)
    r2 = scalar_mult(k, h_point)
    c = _dleq_challenge(r1, r2, s_pub, p_token, h_point, context)
    z = (k + c * secret) % L
    return f"dleq-ed25519:R1={encode_point(r1)}:R2={encode_point(r2)}:z={z:064x}"


def verify_dleq(s_pub_hex: str, token_hex: str, h_point: Point, proof: str, context: str) -> bool:
    """
    Проверяет сразу два равенства:
        z*G   == R1 + c*S_pub
        z*H_B == R2 + c*P_B
    Сходятся оба — значит за S_pub и за токеном стоит один и тот же секрет.
    """
    try:
        if not proof.startswith("dleq-ed25519:"):
            return False
        _, r1_part, r2_part, z_part = proof.split(":", 3)
        r1 = decode_point(r1_part[3:])
        r2 = decode_point(r2_part[3:])
        z = int(z_part[2:], 16)
        s_pub = decode_point(s_pub_hex)
        p_token = decode_point(token_hex)

        c = _dleq_challenge(r1, r2, s_pub, p_token, h_point, context)
        first = scalar_mult(z, G) == point_add(r1, scalar_mult(c, s_pub))
        second = scalar_mult(z, h_point) == point_add(r2, scalar_mult(c, p_token))
        return first and second
    except Exception:
        return False


def _dleq_challenge(r1: Point, r2: Point, s_pub: Point, p_token: Point,
                    h_point: Point, context: str) -> int:
    material = "".join([
        encode_point(r1), encode_point(r2), encode_point(s_pub),
        encode_point(p_token), encode_point(h_point), context,
    ]).encode("utf-8")
    return int.from_bytes(hashlib.sha512(material).digest(), "little") % L


# --- подпись по произвольному основанию --------------------------------------

def sign_with_base(secret: int, base: Point, message: str) -> str:
    """
    Подпись Шнорра, но не по базовой точке G, а по H_B.

    Зачем так: проверяется такая подпись по токену P_B = s*H_B, который
    у букмекера уже есть. То есть букмекер убеждается, что заявку подписал
    владелец токена, и при этом не узнаёт ни S_pub, ни client_id —
    ничего, что связало бы клиента с его визитами к другим конторам.
    """
    pub = scalar_mult(secret, base)
    k = random_scalar()
    r_point = scalar_mult(k, base)
    c = _sig_challenge(r_point, pub, base, message)
    z = (k + c * secret) % L
    return f"schnorr-sig:R={encode_point(r_point)}:z={z:064x}"


def verify_with_base(pub_hex: str, base: Point, message: str, signature: str) -> bool:
    """Проверяет z*H_B == R + c*P_B."""
    try:
        if not signature.startswith("schnorr-sig:"):
            return False
        _, r_part, z_part = signature.split(":", 2)
        r_point = decode_point(r_part[2:])
        z = int(z_part[2:], 16)
        pub = decode_point(pub_hex)
        c = _sig_challenge(r_point, pub, base, message)
        return scalar_mult(z, base) == point_add(r_point, scalar_mult(c, pub))
    except Exception:
        return False


def _sig_challenge(r_point: Point, pub: Point, base: Point, message: str) -> int:
    material = (encode_point(r_point) + encode_point(pub)
                + encode_point(base) + message).encode("utf-8")
    return int.from_bytes(hashlib.sha512(material).digest(), "little") % L

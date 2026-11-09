"""
ПРИЛОЖЕНИЕ КЛИЕНТА — «телефон». Порт 8001.

Отдельный процесс со своей базой именно затем, чтобы ключи физически лежали
не у нас. Вся криптография происходит здесь и только здесь.

Что лежит на телефоне:
  ФИО и паспорт        свои собственные, прятать их от владельца смысла нет
  токен                свой на каждого букмекера
  доля Б               вторая половина ключа шифрования

Чего на телефоне НЕТ: самого ключа AES. Он существует несколько строк кода
внутри generate_tokens и стирается сразу после разделения на доли.
"""

from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.config import BOOKMAKERS, BURMALDA_URL, HTTP_TIMEOUT
from common.crypto import aes_encrypt, new_aes_key, random_id, xor_split
from common.db import make_db

engine, Base, SessionLocal = make_db("client_app")


class Profile(Base):
    __tablename__ = "profile"
    id = Column(Integer, primary_key=True)
    full_name = Column(String, nullable=False)
    passport = Column(String, nullable=False)
    birth_date = Column(String, nullable=False)
    unlocked = Column(Boolean, default=False)
    unlock_id = Column(String, nullable=True)


class TokenRow(Base):
    """Токен и доля Б — по одной строке на каждого букмекера.

    Ключи у разных букмекеров РАЗНЫЕ. Если бы ключ был один, доля,
    отданная одной конторе, открыла бы архив, привязанный к токену другой.
    """

    __tablename__ = "tokens"
    token = Column(String, primary_key=True)
    bookmaker_id = Column(String, nullable=False)
    share_b = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)

app = FastAPI(title="Приложение клиента")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


# ---------------------------------------------------------------------------
# ЭТАП 1. Регистрация
# ---------------------------------------------------------------------------


class KycRequest(BaseModel):
    full_name: str = "Иванова Анна Петровна"
    passport: str = "4509 123456"
    birth_date: str = "1998-04-12"


@app.post("/kyc")
def kyc(req: KycRequest):
    """Шаги 1-3. Клиент пришёл в центр, его проверили, приложение открылось.

    Данные уходят в Бурмалду один раз, для проверки. Обратно приходит
    только разрешение разблокировать приложение.
    """
    with httpx.Client(timeout=HTTP_TIMEOUT) as c:
        r = c.post(f"{BURMALDA_URL}/kyc/verify", json=req.model_dump())
    res = r.json()

    with SessionLocal() as s:
        prof = s.get(Profile, 1)
        if not prof:
            prof = Profile(id=1, full_name=req.full_name, passport=req.passport,
                           birth_date=req.birth_date)
            s.add(prof)
        prof.full_name, prof.passport, prof.birth_date = (
            req.full_name, req.passport, req.birth_date
        )
        prof.unlocked = bool(res.get("ok"))
        prof.unlock_id = res.get("unlock_id")
        s.commit()

    if not res.get("ok"):
        return {"unlocked": False, "reason": res.get("reason")}
    return {"unlocked": True, "unlock_id": res["unlock_id"]}


class GenerateRequest(BaseModel):
    bookmakers: list[str] = ["bk_alpha", "bk_beta"]


@app.post("/tokens/generate")
def generate_tokens(req: GenerateRequest):
    """Шаг 4 — здесь происходит вся криптография проекта.

    Для каждого букмекера по очереди:
        токен        -> случайная строка, ни из чего не выводится
        ключ AES-256 -> 32 байта из CSPRNG
        шифротекст   -> AES-GCM(ключ, {ФИО, паспорт, дата рождения})
        доли         -> ключ режется XOR на А и Б
        ключ         -> СТИРАЕТСЯ, больше не существует нигде
        доля А       -> уезжает в Бурмалду вместе с токеном и шифротекстом
        доля Б       -> остаётся здесь, на телефоне
    """
    with SessionLocal() as s:
        prof = s.get(Profile, 1)
        if not prof or not prof.unlocked:
            raise HTTPException(403, "приложение не разблокировано")
        personal = {
            "full_name": prof.full_name,
            "passport": prof.passport,
            "birth_date": prof.birth_date,
        }

    issued = []
    for bk in req.bookmakers:
        if bk not in BOOKMAKERS:
            raise HTTPException(400, f"неизвестный букмекер {bk}")

        token = random_id("p_", 8)
        key = new_aes_key()
        pd_blob = aes_encrypt(key, personal)
        share_a, share_b = xor_split(key)

        key_preview = key.hex()  # только для наглядности в интерфейсе
        del key                  # ключа больше нет

        with httpx.Client(timeout=HTTP_TIMEOUT) as c:
            r = c.post(f"{BURMALDA_URL}/register", json={
                "token": token, "bookmaker_id": bk,
                "pd_blob": pd_blob, "share_a": share_a,
            })
            r.raise_for_status()

        with SessionLocal() as s:
            s.add(TokenRow(token=token, bookmaker_id=bk, share_b=share_b))
            s.commit()

        issued.append({
            "bookmaker_id": bk,
            "token": token,
            "pd_blob": pd_blob,
            "share_a_sent": share_a,
            "share_b_kept": share_b,
            # Возвращаем ключ ТОЛЬКО чтобы интерфейс мог показать его на
            # секунду и перечеркнуть. В настоящем приложении он не
            # возвращается никуда и никогда.
            "key_wiped_demo_only": key_preview,
        })

    return {"issued": issued}


# ---------------------------------------------------------------------------
# ЭТАП 2. Ставка
# ---------------------------------------------------------------------------


@app.get("/events")
def events(bookmaker_id: str = "bk_alpha"):
    with httpx.Client(timeout=HTTP_TIMEOUT) as c:
        return c.get(f"{BOOKMAKERS[bookmaker_id]}/events").json()


class BetRequest(BaseModel):
    bookmaker_id: str = "bk_alpha"
    event_id: str = "ev_final"
    selection: str = "home"
    stake: int = 1000


@app.post("/bet")
def bet(req: BetRequest):
    """Шаг 6. Ставка и передача доли Б букмекеру.

    Доля Б уезжает именно в момент подтверждения ставки — это и есть
    техническое согласие клиента на будущее раскрытие личности.
    Если клиент не играет, его доля никуда не уходит, и личность
    не раскроет никто.
    """
    with SessionLocal() as s:
        row = (s.query(TokenRow)
               .filter_by(bookmaker_id=req.bookmaker_id)
               .first())
    if not row:
        raise HTTPException(404, f"нет токена для {req.bookmaker_id}")

    with httpx.Client(timeout=HTTP_TIMEOUT) as c:
        r = c.post(f"{BOOKMAKERS[req.bookmaker_id]}/bet", json={
            "token": row.token,
            "event_id": req.event_id,
            "selection": req.selection,
            "stake": req.stake,
            "share_b": row.share_b,
        })
        r.raise_for_status()
    return {"sent_token": row.token, "share_b_sent": True, **r.json()}


# ---------------------------------------------------------------------------
# Служебное
# ---------------------------------------------------------------------------


@app.get("/db")
def dump_db():
    with SessionLocal() as s:
        prof = s.get(Profile, 1)
        return {
            "service": "client_app",
            "role": "Телефон клиента",
            "profile": None if not prof else {
                "full_name": prof.full_name,
                "passport": prof.passport,
                "birth_date": prof.birth_date,
                "unlocked": prof.unlocked,
                "unlock_id": prof.unlock_id,
            },
            "tokens": [{
                "token": t.token,
                "bookmaker_id": t.bookmaker_id,
                "share_b": t.share_b,
                "created_at": t.created_at.isoformat() if t.created_at else None,
            } for t in s.query(TokenRow).all()],
            "aes_key_stored": None,
        }


@app.post("/reset")
def reset():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return {"reset": True}


@app.get("/")
def root():
    return {"service": "client_app", "port": 8001}

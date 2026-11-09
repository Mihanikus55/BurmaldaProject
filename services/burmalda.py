"""
ЦЕНТР БУРМАЛДА — это мы. Порт 8002.

Что мы делаем:
  1) проверяем клиента по реестру и разблокируем ему приложение;
  2) принимаем от телефона токен, шифротекст и долю А;
  3) пересылаем токен, шифротекст и долю А регулятору.

Что лежит у нас в базе: token -> шифротекст. И всё.

Чего у нас НЕТ и никогда не будет:
  - персональных данных: при проверке мы их видим, но не сохраняем;
  - доли Б: она идёт от клиента к букмекеру и от букмекера к регулятору,
    минуя нас. Поэтому мы физически не можем собрать ключ и прочитать
    архив, даже если захотим;
  - логов ставок: букмекер отправляет их прямо регулятору.
"""

from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, Text

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.config import HTTP_TIMEOUT, REGULATOR_URL
from common.crypto import random_id
from common.db import make_db

engine, Base, SessionLocal = make_db("burmalda")


# ---------------------------------------------------------------------------
# Модели
# ---------------------------------------------------------------------------


class ArchiveRow(Base):
    """Наша главная таблица: токен и зашифрованные персональные данные.

    pd_blob мы прочитать не можем — ключ был только на телефоне клиента и
    стёрт там сразу после шифрования.

    share_a здесь живёт недолго: приняли, переслали регулятору, обнулили.
    Это видно по полю forwarded_at.
    """

    __tablename__ = "archive"
    token = Column(String, primary_key=True)
    bookmaker_id = Column(String, nullable=False)
    pd_blob = Column(Text, nullable=False)
    share_a = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    forwarded_at = Column(DateTime, nullable=True)


class KycCheck(Base):
    """Журнал проверок.

    Намеренно пишем только замаскированный номер паспорта и вердикт.
    ФИО не пишем вообще: мы их видели в запросе и забыли.
    """

    __tablename__ = "kyc_checks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    passport_masked = Column(String, nullable=False)
    verdict = Column(String, nullable=False)
    reason = Column(String, nullable=True)
    unlock_id = Column(String, nullable=True)


Base.metadata.create_all(engine)


# ---------------------------------------------------------------------------
# Реестр — заглушка государственной базы, по которой мы сверяем клиента
# ---------------------------------------------------------------------------

REGISTRY = {
    "4509 123456": {"full_name": "Иванова Анна Петровна", "birth_date": "1998-04-12", "excluded": False},
    "4612 778899": {"full_name": "Петров Пётр Петрович", "birth_date": "2010-09-01", "excluded": False},
    "4455 010203": {"full_name": "Сидоров Иван Иванович", "birth_date": "1985-01-30", "excluded": True},
}


def _age(birth_date: str) -> int:
    born = datetime.strptime(birth_date, "%Y-%m-%d")
    today = datetime.now()
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))


def _mask(passport: str) -> str:
    return passport[:4] + " ****" + passport[-2:]


# ---------------------------------------------------------------------------
# Приложение
# ---------------------------------------------------------------------------

app = FastAPI(title="Центр Бурмалда")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


class KycRequest(BaseModel):
    full_name: str
    passport: str
    birth_date: str


@app.post("/kyc/verify")
def kyc_verify(req: KycRequest):
    """ЭТАП 1, шаг 1-2. Клиент пришёл в центр, мы его проверяем.

    Здесь мы ВИДИМ персональные данные — иначе проверить их нельзя.
    Но в базу не пишем ни ФИО, ни полный номер паспорта: в журнал идёт
    только маска и вердикт.
    """
    rec = REGISTRY.get(req.passport.strip())
    verdict, reason, unlock_id = "DENIED", None, None

    if rec is None:
        reason = "паспорт не найден в реестре"
    elif rec["full_name"].lower() != req.full_name.strip().lower():
        reason = "ФИО не совпадает с паспортом"
    elif rec["birth_date"] != req.birth_date.strip():
        reason = "дата рождения не совпадает"
    elif rec["excluded"]:
        reason = "клиент в списке самозапрета"
    elif _age(rec["birth_date"]) < 18:
        reason = f"клиенту {_age(rec['birth_date'])} лет, нужно 18"
    else:
        verdict, unlock_id = "APPROVED", random_id("unlock_", 8)

    with SessionLocal() as s:
        s.add(KycCheck(
            passport_masked=_mask(req.passport.strip()),
            verdict=verdict, reason=reason, unlock_id=unlock_id,
        ))
        s.commit()

    if verdict == "DENIED":
        return {"ok": False, "reason": reason}
    return {"ok": True, "unlock_id": unlock_id, "age": _age(rec["birth_date"])}


class RegisterRequest(BaseModel):
    token: str
    bookmaker_id: str
    pd_blob: str
    share_a: str


@app.post("/register")
def register(req: RegisterRequest):
    """ЭТАП 1, шаги 4-5.

    Телефон присылает токен, шифротекст и долю А.
    Мы кладём token -> шифротекст себе и тут же пересылаем всё регулятору,
    после чего долю А у себя обнуляем — она нам не нужна.
    """
    with SessionLocal() as s:
        if s.get(ArchiveRow, req.token):
            raise HTTPException(409, "токен уже зарегистрирован")
        s.add(ArchiveRow(
            token=req.token, bookmaker_id=req.bookmaker_id,
            pd_blob=req.pd_blob, share_a=req.share_a,
        ))
        s.commit()

    # пересылка регулятору: токен, шифротекст, доля А
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT) as c:
            r = c.post(f"{REGULATOR_URL}/registry", json={
                "token": req.token, "bookmaker_id": req.bookmaker_id,
                "pd_blob": req.pd_blob, "share_a": req.share_a,
            })
            r.raise_for_status()
    except Exception as e:
        raise HTTPException(502, f"регулятор недоступен: {e}")

    # доля А у нас больше не хранится
    with SessionLocal() as s:
        row = s.get(ArchiveRow, req.token)
        row.share_a = None
        row.forwarded_at = datetime.now(timezone.utc)
        s.commit()

    return {"stored": True, "forwarded_to_regulator": True, "share_a_kept": False}


@app.get("/try-read/{token}")
def try_read(token: str):
    """Кнопка «попробовать прочитать архив» для интерфейса.

    У нас есть шифротекст, но нет ни одной доли ключа: долю А мы отдали,
    доля Б через нас никогда не проходила. Читать нечем.
    """
    with SessionLocal() as s:
        row = s.get(ArchiveRow, token)
    if not row:
        return {"can_read": False, "reason": "токен не найден"}
    return {
        "can_read": False,
        "has_ciphertext": True,
        "has_share_a": row.share_a is not None,
        "has_share_b": False,
        "reason": "шифротекст есть, но ни одной доли ключа у нас нет — "
                  "долю А мы передали регулятору, доля Б через нас не проходит",
    }


@app.get("/db")
def dump_db():
    with SessionLocal() as s:
        return {
            "service": "burmalda",
            "role": "Центр Бурмалда",
            "archive": [{
                "token": r.token,
                "bookmaker_id": r.bookmaker_id,
                "pd_blob": r.pd_blob,
                "share_a": r.share_a,
                "forwarded": r.forwarded_at is not None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            } for r in s.query(ArchiveRow).all()],
            "kyc_checks": [{
                "ts": k.ts.isoformat() if k.ts else None,
                "passport_masked": k.passport_masked,
                "verdict": k.verdict,
                "reason": k.reason,
            } for k in s.query(KycCheck).order_by(KycCheck.id.desc()).all()],
            "personal_data_stored": 0,
            "bet_logs_stored": 0,
        }


@app.post("/reset")
def reset():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return {"reset": True}


@app.get("/")
def root():
    return {"service": "burmalda", "port": 8002, "registry_passports": list(REGISTRY)}

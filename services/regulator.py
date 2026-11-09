"""
РЕГУЛЯТОР. Порт 8004.

Получает данные из двух независимых источников:

  от Бурмалды (этап 1)    токен, шифротекст, доля А
  от букмекера (этап 3)   токен, логи ставок, доля Б

Пока пришла только первая таблица — архив нечитаем: одна доля XOR это
равномерный случайный мусор, по нему о ключе не известно ничего.

ЭТАП 4: регулятор соединяет две таблицы по токену, складывает доли,
получает ключ и расшифровывает личность. Раскрыть он может ТОЛЬКО тех,
кто реально играл: у неигравшего клиента доля Б осталась на телефоне.
"""

import json
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, Text

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.crypto import aes_decrypt, xor_combine
from common.db import make_db

engine, Base, SessionLocal = make_db("regulator")


class RegistryRow(Base):
    """Таблица 1 — от Бурмалды, приходит сразу при регистрации."""

    __tablename__ = "registry"
    token = Column(String, primary_key=True)
    bookmaker_id = Column(String, nullable=False)
    pd_blob = Column(Text, nullable=False)
    share_a = Column(Text, nullable=False)
    received_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ReportRow(Base):
    """Таблица 2 — от букмекера, приходит после расчёта события."""

    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String, nullable=False)
    bookmaker_id = Column(String, nullable=False)
    bets_json = Column(Text, nullable=False)
    share_b = Column(Text, nullable=False)
    received_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RevealRow(Base):
    """Результат этапа 4: личность, связанная со ставками."""

    __tablename__ = "revealed"
    token = Column(String, primary_key=True)
    bookmaker_id = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    passport = Column(String, nullable=False)
    birth_date = Column(String, nullable=False)
    bets_json = Column(Text, nullable=False)
    revealed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)

app = FastAPI(title="Регулятор")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


class RegistryPayload(BaseModel):
    token: str
    bookmaker_id: str
    pd_blob: str
    share_a: str


@app.post("/registry")
def receive_registry(p: RegistryPayload):
    """ЭТАП 1, шаг 5. Приём от Бурмалды. Открыть архив пока нельзя."""
    with SessionLocal() as s:
        if not s.get(RegistryRow, p.token):
            s.add(RegistryRow(**p.model_dump()))
            s.commit()
    return {"stored": True, "can_decrypt_now": False,
            "reason": "есть доля А, нет доли Б"}


class ReportPayload(BaseModel):
    token: str
    bookmaker_id: str
    bets: list[dict]
    share_b: str


@app.post("/report")
def receive_report(p: ReportPayload):
    """ЭТАП 3, завершение. Приём от букмекера напрямую."""
    with SessionLocal() as s:
        s.add(ReportRow(token=p.token, bookmaker_id=p.bookmaker_id,
                        bets_json=json.dumps(p.bets, ensure_ascii=False),
                        share_b=p.share_b))
        s.commit()
    return {"stored": True, "bets": len(p.bets)}


@app.post("/aggregate")
def aggregate():
    """ЭТАП 4. Соединяем две таблицы по токену и раскрываем личность.

    Сделано отдельным вызовом, а не автоматически при приёме отчёта,
    чтобы в интерфейсе это был явный, видимый шаг.
    """
    results = []
    with SessionLocal() as s:
        for reg in s.query(RegistryRow).all():
            rep = (s.query(ReportRow)
                   .filter_by(token=reg.token)
                   .order_by(ReportRow.id.desc())
                   .first())
            if not rep:
                results.append({"token": reg.token, "revealed": False,
                                "reason": "отчёта от букмекера нет — клиент не играл"})
                continue
            if s.get(RevealRow, reg.token):
                results.append({"token": reg.token, "revealed": True,
                                "reason": "уже раскрыт ранее"})
                continue

            # доля А XOR доля Б = ключ AES
            key = xor_combine(reg.share_a, rep.share_b)
            try:
                personal = aes_decrypt(key, reg.pd_blob)
            except Exception as e:
                results.append({"token": reg.token, "revealed": False,
                                "reason": f"расшифрование не удалось: {e}"})
                continue

            s.add(RevealRow(
                token=reg.token, bookmaker_id=reg.bookmaker_id,
                full_name=personal["full_name"], passport=personal["passport"],
                birth_date=personal["birth_date"], bets_json=rep.bets_json,
            ))
            results.append({
                "token": reg.token, "revealed": True,
                "bookmaker_id": reg.bookmaker_id,
                "full_name": personal["full_name"],
                "bets": len(json.loads(rep.bets_json)),
            })
        s.commit()
    return {"results": results}


@app.get("/try-read/{token}")
def try_read(token: str):
    """Кнопка «попробовать прочитать» для интерфейса."""
    with SessionLocal() as s:
        reg = s.get(RegistryRow, token)
        rep = s.query(ReportRow).filter_by(token=token).first()
    if not reg:
        return {"can_read": False, "reason": "токен не найден"}
    if not rep:
        return {"can_read": False, "has_ciphertext": True, "has_share_a": True,
                "has_share_b": False,
                "reason": "есть шифротекст и доля А, доли Б нет — "
                          "ключ не собрать, клиент не играл"}
    return {"can_read": True, "has_ciphertext": True, "has_share_a": True,
            "has_share_b": True, "reason": "обе доли на руках, ключ собирается"}


@app.get("/db")
def dump_db():
    with SessionLocal() as s:
        return {
            "service": "regulator",
            "role": "Регулятор",
            "registry": [{
                "token": r.token, "bookmaker_id": r.bookmaker_id,
                "pd_blob": r.pd_blob, "share_a": r.share_a,
            } for r in s.query(RegistryRow).all()],
            "reports": [{
                "token": r.token, "bookmaker_id": r.bookmaker_id,
                "share_b": r.share_b, "bets": json.loads(r.bets_json),
            } for r in s.query(ReportRow).all()],
            "revealed": [{
                "token": r.token, "bookmaker_id": r.bookmaker_id,
                "full_name": r.full_name, "passport": r.passport,
                "birth_date": r.birth_date, "bets": json.loads(r.bets_json),
                "revealed_at": r.revealed_at.isoformat() if r.revealed_at else None,
            } for r in s.query(RevealRow).all()],
        }


@app.post("/reset")
def reset():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return {"reset": True}


@app.get("/")
def root():
    return {"service": "regulator", "port": 8004}

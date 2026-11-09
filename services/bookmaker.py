"""
БУКМЕКЕР. Порт 8003 (bk_alpha) или 8005 (bk_beta) — один и тот же файл,
поднятый дважды с разным BOOKMAKER_ID и своей базой.

Что видит букмекер:
  токен             случайная строка, ни из чего не выводимая
  ставки по токену  событие, исход, сумма, коэффициент, результат
  доля Б            половина ключа шифрования

Чего он не видит: ФИО, паспорт, шифротекст. Доля Б для него бесполезна —
расшифровывать нечего, архив лежит у Бурмалды и у регулятора.

Проверок токена нет: мы договорились, что если Бурмалда разблокировала
приложение, клиент считается доверенным.

ЭТАП 3: расчёт делает букмекер, после чего отправляет логи ставок и долю Б
НАПРЯМУЮ регулятору, минуя Бурмалду.
"""

import json
import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Float, Integer, String, Text

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.config import HTTP_TIMEOUT, REGULATOR_URL
from common.db import make_db

BOOKMAKER_ID = os.getenv("BOOKMAKER_ID", "bk_alpha")
BOOKMAKER_NAME = {"bk_alpha": "БК Альфа", "bk_beta": "БК Бета"}.get(BOOKMAKER_ID, BOOKMAKER_ID)

engine, Base, SessionLocal = make_db(f"bookmaker_{BOOKMAKER_ID}")


class Event(Base):
    __tablename__ = "events"
    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    odds_json = Column(Text, nullable=False)
    status = Column(String, default="OPEN")
    outcome = Column(String, nullable=True)


class Bet(Base):
    __tablename__ = "bets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String, nullable=False)
    event_id = Column(String, nullable=False)
    selection = Column(String, nullable=False)
    stake = Column(Integer, nullable=False)
    odds = Column(Float, nullable=False)
    status = Column(String, default="ACCEPTED")
    result = Column(String, nullable=True)
    payout = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ShareRow(Base):
    """Доля Б, пришедшая от клиента вместе с подтверждением ставки.

    Лежит рядом с токеном. Прочитать с её помощью нечего: шифротекста
    у букмекера нет и не будет.
    """

    __tablename__ = "shares"
    token = Column(String, primary_key=True)
    share_b = Column(Text, nullable=False)
    received_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)


def seed_events():
    base = {
        "bk_alpha": {"home": 1.85, "draw": 3.40, "away": 4.20},
        "bk_beta": {"home": 1.92, "draw": 3.25, "away": 4.05},
    }.get(BOOKMAKER_ID, {"home": 1.9, "draw": 3.3, "away": 4.1})
    with SessionLocal() as s:
        if not s.query(Event).first():
            s.add(Event(id="ev_final", title="Финал: Спартак — Зенит",
                        odds_json=json.dumps(base)))
            s.add(Event(id="ev_semi", title="Полуфинал: ЦСКА — Динамо",
                        odds_json=json.dumps({"home": 2.10, "draw": 3.10, "away": 3.50})))
            s.commit()


seed_events()

app = FastAPI(title=f"Букмекер {BOOKMAKER_NAME}")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


@app.get("/events")
def events():
    with SessionLocal() as s:
        return [{
            "id": e.id, "title": e.title, "odds": json.loads(e.odds_json),
            "status": e.status, "outcome": e.outcome,
        } for e in s.query(Event).all()]


# ---------------------------------------------------------------------------
# ЭТАП 2. Приём ставки
# ---------------------------------------------------------------------------


class BetRequest(BaseModel):
    token: str
    event_id: str
    selection: str
    stake: int
    share_b: str


@app.post("/bet")
def accept_bet(req: BetRequest):
    """Принимаем ставку и вместе с ней долю Б.

    Доля пишется один раз на токен: при повторных ставках она та же.
    """
    with SessionLocal() as s:
        ev = s.get(Event, req.event_id)
        if not ev:
            raise HTTPException(404, "событие не найдено")
        if ev.status != "OPEN":
            raise HTTPException(409, "событие уже рассчитано")
        odds = json.loads(ev.odds_json).get(req.selection)
        if odds is None:
            raise HTTPException(400, f"нет такого исхода: {req.selection}")
        if req.stake <= 0:
            raise HTTPException(400, "сумма должна быть положительной")

        bet = Bet(token=req.token, event_id=req.event_id, selection=req.selection,
                  stake=req.stake, odds=odds)
        s.add(bet)
        if not s.get(ShareRow, req.token):
            s.add(ShareRow(token=req.token, share_b=req.share_b))
        s.commit()
        return {"bet_id": bet.id, "odds": odds, "status": "ACCEPTED"}


# ---------------------------------------------------------------------------
# ЭТАП 3. Расчёт
# ---------------------------------------------------------------------------


class SettleRequest(BaseModel):
    event_id: str = "ev_final"
    outcome: str = "home"


@app.post("/settle")
def settle(req: SettleRequest):
    """Расчёт события. Считает сам букмекер."""
    with SessionLocal() as s:
        ev = s.get(Event, req.event_id)
        if not ev:
            raise HTTPException(404, "событие не найдено")
        ev.status, ev.outcome = "SETTLED", req.outcome

        settled = 0
        for bet in s.query(Bet).filter_by(event_id=req.event_id, status="ACCEPTED").all():
            won = bet.selection == req.outcome
            bet.status = "SETTLED"
            bet.result = "WON" if won else "LOST"
            bet.payout = int(bet.stake * bet.odds) if won else 0
            settled += 1
        s.commit()
        return {"event_id": req.event_id, "outcome": req.outcome, "settled_bets": settled}


@app.post("/report")
def report_to_regulator():
    """ЭТАП 3, завершение: логи ставок и доля Б уходят ПРЯМО регулятору.

    Через Бурмалду это не идёт — и именно поэтому Бурмалда никогда не
    сможет собрать ключ: у неё есть шифротекст, но доля Б в её руки
    не попадает ни на одном шаге.
    """
    sent = []
    with SessionLocal() as s:
        tokens = [r.token for r in s.query(ShareRow).all()]
        for token in tokens:
            bets = s.query(Bet).filter_by(token=token, status="SETTLED").all()
            if not bets:
                continue
            share = s.get(ShareRow, token)
            payload = {
                "token": token,
                "bookmaker_id": BOOKMAKER_ID,
                "share_b": share.share_b,
                "bets": [{
                    "bet_id": b.id, "event_id": b.event_id, "selection": b.selection,
                    "stake": b.stake, "odds": b.odds, "result": b.result,
                    "payout": b.payout,
                    "created_at": b.created_at.isoformat() if b.created_at else None,
                } for b in bets],
            }
            with httpx.Client(timeout=HTTP_TIMEOUT) as c:
                r = c.post(f"{REGULATOR_URL}/report", json=payload)
                r.raise_for_status()
            sent.append({"token": token, "bets": len(payload["bets"])})
    return {"reported": sent, "sent_directly_to_regulator": True, "via_burmalda": False}


@app.get("/try-read/{token}")
def try_read(token: str):
    """Кнопка «попробовать прочитать» для интерфейса."""
    with SessionLocal() as s:
        share = s.get(ShareRow, token)
    return {
        "can_read": False,
        "has_ciphertext": False,
        "has_share_b": share is not None,
        "reason": "доля Б есть, но шифротекста у букмекера нет — "
                  "расшифровывать нечего",
    }


@app.get("/db")
def dump_db():
    with SessionLocal() as s:
        return {
            "service": "bookmaker",
            "bookmaker_id": BOOKMAKER_ID,
            "role": BOOKMAKER_NAME,
            "events": [{
                "id": e.id, "title": e.title, "odds": json.loads(e.odds_json),
                "status": e.status, "outcome": e.outcome,
            } for e in s.query(Event).all()],
            "bets": [{
                "id": b.id, "token": b.token, "event_id": b.event_id,
                "selection": b.selection, "stake": b.stake, "odds": b.odds,
                "status": b.status, "result": b.result, "payout": b.payout,
            } for b in s.query(Bet).order_by(Bet.id.desc()).all()],
            "shares": [{
                "token": r.token, "share_b": r.share_b,
            } for r in s.query(ShareRow).all()],
            "personal_data_stored": 0,
            "ciphertexts_stored": 0,
        }


@app.post("/reset")
def reset():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    seed_events()
    return {"reset": True}


@app.get("/")
def root():
    return {"service": "bookmaker", "bookmaker_id": BOOKMAKER_ID, "name": BOOKMAKER_NAME}

# bookmaker_service.py
import hashlib
import uuid
from datetime import datetime, timedelta
from decimal import Decimal

import requests
from flask import Flask, jsonify, request
from sqlalchemy import BigInteger, Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from common_ports import (
    CredentialService, NoopCredentialService, NoopSignerVerifier,
    NoopTokenPolicy, SignerVerifier, TokenPolicy
)

BookmakerBase = declarative_base()


# =============================================================================
# МОДЕЛИ БАЗЫ ДАННЫХ БУКМЕКЕРА (SQLAlchemy)
# Заметьте: здесь физически нет колонок для ФИО, паспорта или банковского счета!
# =============================================================================
class BmEventModel(BookmakerBase):
    __tablename__ = "bm_events"
    id = Column(String(64), primary_key=True)
    name = Column(String(256), nullable=False)
    base_odds_home = Column(String(16), nullable=False, default="2.40")
    base_odds_away = Column(String(16), nullable=False, default="1.65")


class BmTokenExposureModel(BookmakerBase):
    """Риск-профиль конкретного постоянного токена внутри данной конторы."""
    __tablename__ = "bm_token_exposure"
    token = Column(String(128), primary_key=True)
    bets_count = Column(Integer, nullable=False, default=0)
    total_staked = Column(BigInteger, nullable=False, default=0)
    won_count = Column(Integer, nullable=False, default=0)


class BmQuoteModel(BookmakerBase):
    __tablename__ = "bm_quotes"
    id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=False, index=True)
    event_id = Column(String(64), nullable=False)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    odds_commitment = Column(String(128), nullable=False)
    expires_at = Column(DateTime, nullable=False)


class BmBetModel(BookmakerBase):
    __tablename__ = "bm_bets"
    id = Column(String(64), primary_key=True)
    quote_id = Column(String(64), nullable=False)
    token = Column(String(128), nullable=False, index=True)
    event_id = Column(String(64), nullable=False)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)
    receipt_sig = Column(Text, nullable=False)


# =============================================================================
# КЛАСС СЕРВИСА БУКМЕКЕРА (Flask + SQLAlchemy)
# =============================================================================
class BookmakerService:
    def __init__(
        self,
        bookmaker_id: str,
        regulator_url: str,
        db_url: str = "sqlite:///bookmaker.db",
        signer: SignerVerifier = None,
        token_policy: TokenPolicy = None,
        cred_service: CredentialService = None,
    ):
        self.bookmaker_id = bookmaker_id
        self.regulator_url = regulator_url.rstrip("/")
        self.app = Flask(f"BookmakerService_{bookmaker_id}")
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

        self.signer = signer or NoopSignerVerifier()
        self.token_policy = token_policy or NoopTokenPolicy()
        self.cred_service = cred_service or NoopCredentialService()

        BookmakerBase.metadata.create_all(self.engine)

        self._seed_default_events()
        self._register_routes()

    def _seed_default_events(self):
        with self.SessionLocal() as session:
            if not session.query(BmEventModel).filter_by(id="ev_final_2026").first():
                session.add(BmEventModel(
                    id="ev_final_2026",
                    name="Финал Кубка: Команда А vs Команда Б",
                    base_odds_home="2.40",
                    base_odds_away="1.65",
                ))
                session.commit()

    def _calculate_pricing(self, session, token: str, event: BmEventModel, selection: str, stake: int) -> str:
        """
        Обычная бизнес-логика риск-менеджмента букмекера (криптографии здесь нет):
        рассчитывает коэффициент на основе базовой линии, размера ставки и истории токена.
        """
        base = Decimal(event.base_odds_home if selection == "HOME_WIN" else event.base_odds_away)
        exposure = session.query(BmTokenExposureModel).filter_by(token=token).first()
        if exposure and exposure.won_count >= 3:
            # Если токен часто выигрывает («шарп»), букмекер чуть снижает котировку
            base = max(Decimal("1.10"), base - Decimal("0.10"))
        if stake >= 500_000_00:  # При крупном прогрузе свыше 500 000 руб. сдвигаем кэф
            base = max(Decimal("1.10"), base - Decimal("0.05"))
        return f"{base:.2f}"

    def _register_routes(self):
        @self.app.route("/v1/events", methods=["GET"])
        def list_events():
            with self.SessionLocal() as session:
                evs = session.query(BmEventModel).all()
                return jsonify([{
                    "event_id": e.id, "name": e.name,
                    "markets": {"HOME_WIN": e.base_odds_home, "AWAY_WIN": e.base_odds_away}
                } for e in evs])

        # ПОПОЛНЕНИЕ ОБЕСПЕЧЕНИЯ (ЛИКВИДНОСТИ) БУКМЕКЕРА У РЕГУЛЯТОРА
        @self.app.route("/v1/liquidity/top-up", methods=["POST"])
        def top_up_liquidity():
            data = request.json or {}
            amount = int(data["amount"])
            resp = requests.post(
                f"{self.regulator_url}/v1/accounts/bookmaker:{self.bookmaker_id}/deposit",
                json={"amount": amount, "idempotency_key": f"topup_{uuid.uuid4().hex[:10]}"},
                timeout=5,
            )
            return jsonify(resp.json()), resp.status_code

        # ШАГ 1-4 СЦЕНАРИЯ СТАВКИ: ЗАПРОС КОТИРОВКИ (QUOTES)
        @self.app.route("/v1/quotes", methods=["POST"])
        def create_quote():
            data = request.json or {}
            token = data["token"]
            event_id = data["event_id"]
            selection = data["selection"]
            stake = int(data["stake"])
            zk_token_proof = data.get("zk_token_proof", f"schnorr_zk_noop:{token}:0000")

            # [CRYPTO HOOK — ЭТАП 2.2 (M3): Проверка ZK-доказательства Шнорра для токена P_B = s * H_B]
            if not self.token_policy.verify_token_proof(token, self.bookmaker_id, zk_token_proof):
                return jsonify({"error": "INVALID_TOKEN_ZK_PROOF"}), 400

            # В M0 проверяем допуск токена у регулятора (в M4 заменяется на локальную проверку BBS+)
            elig_resp = requests.get(f"{self.regulator_url}/v1/tokens/{token}/eligibility", timeout=5)
            if elig_resp.status_code != 200 or not elig_resp.json().get("valid"):
                return jsonify({"error": "TOKEN_NOT_ELIGIBLE"}), 403

            with self.SessionLocal() as session:
                ev = session.query(BmEventModel).filter_by(id=event_id).first()
                if not ev:
                    return jsonify({"error": "EVENT_NOT_FOUND"}), 404

                odds_str = self._calculate_pricing(session, token, ev, selection, stake)
                quote_id = f"q_{uuid.uuid4().hex[:10]}"
                expires_at = datetime.utcnow() + timedelta(minutes=5)

                # [CRYPTO HOOK — ЭТАП 3: Commitment на коэффициент до исхода события]
                # Букмекер фиксирует хэш котировки с солью, чтобы не изменить кэф задним числом
                commitment_raw = f"{quote_id}:{token}:{odds_str}:{stake}".encode("utf-8")
                odds_commitment = hashlib.sha256(commitment_raw).hexdigest()

                session.add(BmQuoteModel(
                    id=quote_id,
                    token=token,
                    event_id=event_id,
                    selection=selection,
                    stake=stake,
                    odds=odds_str,
                    odds_commitment=odds_commitment,
                    expires_at=expires_at,
                ))
                session.commit()

                return jsonify({
                    "quote_id": quote_id,
                    "token": token,
                    "odds": odds_str,
                    "odds_commitment": odds_commitment,
                    "expires_at": expires_at.isoformat(),
                }), 201

        # ШАГ 6-10 СЦЕНАРИЯ СТАВКИ: ОФОРМЛЕНИЕ СТАВКИ И ВЫДАЧА ПОДПИСАННОЙ КВИТАНЦИИ
        @self.app.route("/v1/bets", methods=["POST"])
        def place_bet():
            data = request.json or {}
            quote_id = data["quote_id"]
            token = data["token"]
            presentation = data.get("credential_presentation", {})
            client_sig = data["client_sig"]

            # [CRYPTO HOOK — ЭТАП 2.3 (M4): Локальная проверка BBS+ доказательства (18+, KYC, лимиты)]
            bbs_ok, _ = self.cred_service.verify_presentation(presentation)
            if not bbs_ok:
                return jsonify({"error": "INVALID_BBS_CREDENTIAL_PROOF"}), 403

            with self.SessionLocal() as session:
                quote = session.query(BmQuoteModel).filter_by(id=quote_id, token=token).first()
                if not quote:
                    return jsonify({"error": "QUOTE_NOT_FOUND"}), 404
                if quote.expires_at < datetime.utcnow():
                    return jsonify({"error": "QUOTE_EXPIRED"}), 400

                # Подпись букмекера под параметрами ставки перед отправкой регулятору
                bet_payload = {
                    "quote_id": quote.id,
                    "token": token,
                    "event_id": quote.event_id,
                    "selection": quote.selection,
                    "stake": quote.stake,
                    "odds": quote.odds,
                }
                bookmaker_sig = self.signer.sign(self.bookmaker_id, "", bet_payload)

                # Шаг 7: Вызываем регулятора для атомарного создания двух холдов в эскроу
                reg_resp = requests.post(
                    f"{self.regulator_url}/v1/bets",
                    json={
                        "token": token,
                        "bookmaker_id": self.bookmaker_id,
                        "event_id": quote.event_id,
                        "selection": quote.selection,
                        "stake": quote.stake,
                        "odds": quote.odds,
                        "quote_id": quote.id,
                        "client_sig": client_sig,
                        "bookmaker_sig": bookmaker_sig,
                    },
                    timeout=5,
                )
                if reg_resp.status_code != 201:
                    return jsonify(reg_resp.json()), reg_resp.status_code

                bet_id = reg_resp.json()["bet_id"]

                # Обновляем экспозицию по токену (без знания личности!)
                exp = session.query(BmTokenExposureModel).filter_by(token=token).first()
                if not exp:
                    exp = BmTokenExposureModel(token=token, bets_count=0, total_staked=0, won_count=0)
                    session.add(exp)
                exp.bets_count += 1
                exp.total_staked += quote.stake

                # [CRYPTO HOOK — ЭТАП 2.5 (M1): Подписанная квитанция букмекера Ed25519]
                receipt_payload = {
                    "bet_id": bet_id,
                    "bookmaker_id": self.bookmaker_id,
                    "token": token,
                    "event_id": quote.event_id,
                    "selection": quote.selection,
                    "stake": quote.stake,
                    "odds": quote.odds,
                    "odds_commitment": quote.odds_commitment,
                }
                receipt_sig = self.signer.sign(self.bookmaker_id, "", receipt_payload)

                session.add(BmBetModel(
                    id=bet_id,
                    quote_id=quote.id,
                    token=token,
                    event_id=quote.event_id,
                    selection=quote.selection,
                    stake=quote.stake,
                    odds=quote.odds,
                    status="ACCEPTED",
                    receipt_sig=receipt_sig,
                ))
                session.commit()

                return jsonify({
                    "bet_id": bet_id,
                    "status": "ACCEPTED",
                    "receipt": {
                        "payload": receipt_payload,
                        "bookmaker_sig": receipt_sig,
                    },
                }), 201

        @self.app.route("/v1/exposure", methods=["GET"])
        def get_exposure():
            with self.SessionLocal() as session:
                exps = session.query(BmTokenExposureModel).all()
                return jsonify([{
                    "token": x.token,
                    "bets_count": x.bets_count,
                    "total_staked": x.total_staked,
                    "won_count": x.won_count,
                } for x in exps])

        @self.app.route("/v1/internal/settled", methods=["POST"])
        def internal_settled():
            data = request.json or {}
            with self.SessionLocal() as session:
                b = session.query(BmBetModel).filter_by(id=data.get("bet_id")).first()
                if b:
                    b.status = data.get("status", "SETTLED")
                    if b.status == "SETTLED_WON":
                        exp = session.query(BmTokenExposureModel).filter_by(token=b.token).first()
                        if exp:
                            exp.won_count += 1
                    session.commit()
            return jsonify({"ack": True})
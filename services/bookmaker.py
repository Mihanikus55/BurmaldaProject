from datetime import datetime, timedelta
from decimal import Decimal
import uuid
from flask import Blueprint, jsonify, request

from common.crypto_ports import (
    cred_service_port, odds_commitment_port, signer_port, token_policy_port
)
from services.database import (
    BmBetModel, BmQuoteModel, BmTokenExposureModel, EventModel, SessionLocal
)
from services.regulator import (
    append_audit, get_or_create_account, record_double_entry
)

bookmaker_bp = Blueprint("bookmaker", __name__)

BOOKMAKER_ID = "bk_alpha"
QUOTE_TTL_SECONDS = 120


@bookmaker_bp.route("/liquidity/top-up", methods=["POST"])
def top_up_liquidity():
    data = request.get_json(silent=True) or {}
    amount = int(data.get("amount", 10000_00))

    with SessionLocal() as session:
        bk_acc = get_or_create_account(session, "bookmaker:bk_alpha")
        bank_acc = get_or_create_account(session, "external:bank")
        bank_acc.available -= amount
        bk_acc.available += amount
        bk_acc.version += 1

        record_double_entry(session, "external:bank", "bookmaker:bk_alpha", amount, "tx_bk_topup")
        append_audit(session, "bookmaker:bk_alpha", "LIQUIDITY_TOP_UP", {"amount": amount})
        session.commit()
        return jsonify({
            "owner_ref": bk_acc.owner_ref,
            "available": bk_acc.available,
            "held": bk_acc.held,
        })


# =============================================================================
# ЭТАП 2 (СТАВКА) — СТОРОНА БУКМЕКЕРА
#
# Что букмекер видит на входе: токен, доказательство, содержание ставки.
# Чего он НЕ видит и не может узнать: имя, паспорт, client_id, S_pub,
# баланс клиента, его ставки у конкурентов.
#
# Проверку доказательства он делегирует регулятору — только у того есть
# S_pub. Коэффициент при этом считает сам, по истории ЭТОГО токена у себя:
# для риск-менеджмента имя никогда и не было нужно.
# =============================================================================

def price_selection(session, token: str, selection: str) -> Decimal:
    """
    Расчёт коэффициента. Обычная бизнес-логика, криптографии здесь нет.

    База по исходу плюс поправка на поведение токена: чем чаще этот токен
    выигрывает, тем ниже ему коэффициент. Профиль копится по псевдониму,
    и этого для управления риском достаточно.
    """
    base = Decimal("2.40") if selection == "HOME_WIN" else Decimal("1.65")

    exposure = session.query(BmTokenExposureModel).filter_by(token=token).first()
    if exposure and exposure.bets_count >= 3:
        win_rate = Decimal(exposure.won_count) / Decimal(exposure.bets_count)
        if win_rate > Decimal("0.6"):
            base -= Decimal("0.15")          # срезаем выигрывающему псевдониму
    return base.quantize(Decimal("0.01"))


def quote_at_bookmaker(session, token: str, credential: dict, event_id: str,
                       selection: str, stake: int) -> dict:
    """Шаги 1-3 этапа 2: проверка справки, коэффициент, обязательство."""

    # --- проверка допуска ЛОКАЛЬНО, без обращения к регулятору -----------
    # Справка подписана регулятором Ed25519, в ней есть адресат и срок.
    # Букмекер проверяет подпись сам — это и быстрее, и регулятор не узнаёт,
    # в какой конторе клиент сейчас играет.
    ok, reason = cred_service_port.verify_credential(credential, BOOKMAKER_ID)
    if not ok:
        append_audit(session, BOOKMAKER_ID, "CREDENTIAL_REJECTED", {"reason": reason})
        return {"error": reason}
    if credential["claims"]["token"] != token:
        return {"error": "CREDENTIAL_TOKEN_MISMATCH"}

    # --- коэффициент -----------------------------------------------------
    odds = price_selection(session, token, selection)
    quote_id = f"q_{uuid.uuid4().hex[:8]}"

    # --- обязательство на коэффициент ------------------------------------
    # Хэш публикуется сейчас, коэффициент и соль раскрываются после исхода.
    commitment, salt = odds_commitment_port.commit({
        "quote_id": quote_id, "token": token, "event_id": event_id,
        "selection": selection, "stake": stake, "odds": f"{odds:.2f}",
    })

    session.add(BmQuoteModel(
        id=quote_id, token=token, bookmaker_id=BOOKMAKER_ID, event_id=event_id,
        selection=selection, stake=stake, odds=f"{odds:.2f}",
        odds_commitment=commitment, odds_salt=salt, status="OPEN",
    ))
    append_audit(session, BOOKMAKER_ID, "QUOTE_ISSUED", {
        "quote_id": quote_id, "token": token[:16], "odds": f"{odds:.2f}",
        "odds_commitment": commitment[:16],
    })

    claims = credential["claims"]
    return {
        "quote_id": quote_id,
        "odds": f"{odds:.2f}",
        "stake": stake,
        "selection": selection,
        "event_id": event_id,
        "odds_commitment": commitment,          # соль пока НЕ отдаём
        "expires_at": (datetime.utcnow() + timedelta(seconds=QUOTE_TTL_SECONDS)).isoformat(timespec="seconds"),
        "claims": {k: claims[k] for k in ("adult", "kyc_ok", "not_excluded", "limits_ok")},
    }


def accept_bet_at_bookmaker(session, quote_id: str, token: str, client_sig: str,
                            client_public_key: str) -> dict:
    """
    Шаг 5 этапа 2: проверка подписи клиента по его токену.

    Клиент подписывает котировку тем ключом, публичная часть которого
    лежит в справке. Букмекер проверяет подпись по ней и убеждается, что
    заявку подал владелец токена — не узнавая о клиенте ничего нового.
    """
    quote = session.query(BmQuoteModel).filter_by(id=quote_id).first()
    if not quote:
        return {"error": "QUOTE_NOT_FOUND"}
    if quote.status != "OPEN":
        return {"error": "QUOTE_ALREADY_USED"}
    if quote.token != token:
        return {"error": "QUOTE_TOKEN_MISMATCH"}
    if (datetime.utcnow() - quote.created_at).total_seconds() > QUOTE_TTL_SECONDS:
        quote.status = "EXPIRED"
        return {"error": "QUOTE_EXPIRED"}

    signed_payload = {
        "quote_id": quote.id,
        "token": quote.token,
        "event_id": quote.event_id,
        "selection": quote.selection,
        "stake": quote.stake,
        "odds": quote.odds,
    }
    if not token_policy_port.verify_token_signature(client_public_key, signed_payload, client_sig):
        append_audit(session, BOOKMAKER_ID, "CLIENT_SIGNATURE_REJECTED", {"quote_id": quote.id})
        return {"error": "CLIENT_SIGNATURE_INVALID"}

    quote.status = "USED"
    return {"ok": True, "quote": quote, "signed_payload": signed_payload}


@bookmaker_bp.route("/quotes", methods=["POST"])
def quote_endpoint():
    data = request.get_json(silent=True) or {}
    if not all(f in data for f in ("token", "credential", "selection")):
        return jsonify({"error": "MISSING_FIELDS"}), 400

    with SessionLocal() as session:
        result = quote_at_bookmaker(
            session,
            token=data["token"],
            credential=data["credential"],
            event_id=data.get("event_id", "ev_final_2026"),
            selection=data["selection"],
            stake=int(data.get("stake", 1000_00)),
        )
        session.commit()
        return jsonify(result), (403 if "error" in result else 201)


@bookmaker_bp.route("/quotes/<quote_id>/reveal", methods=["POST"])
def reveal_odds_endpoint(quote_id: str):
    """
    Раскрытие обязательства: соль отдаётся только после расчёта события.
    До этого момента проверить хэш невозможно — в этом и смысл.
    """
    with SessionLocal() as session:
        quote = session.query(BmQuoteModel).filter_by(id=quote_id).first()
        if not quote:
            return jsonify({"error": "QUOTE_NOT_FOUND"}), 404

        event = session.query(EventModel).filter_by(id=quote.event_id).first()
        if not event or not event.outcome:
            return jsonify({"error": "EVENT_NOT_SETTLED_YET"}), 409

        payload = {
            "quote_id": quote.id, "token": quote.token, "event_id": quote.event_id,
            "selection": quote.selection, "stake": quote.stake, "odds": quote.odds,
        }
        ok = odds_commitment_port.verify(quote.odds_commitment, quote.odds_salt, payload)
        return jsonify({
            "quote_id": quote.id,
            "odds": quote.odds,
            "salt": quote.odds_salt,
            "commitment": quote.odds_commitment,
            "commitment_valid": ok,
        })


@bookmaker_bp.route("/exposure", methods=["GET"])
def exposure_endpoint():
    """Риск букмекера в разрезе токенов. Имён здесь нет и быть не может."""
    with SessionLocal() as session:
        rows = session.query(BmTokenExposureModel).all()
        return jsonify([{
            "token": r.token,
            "bets_count": r.bets_count,
            "total_staked": r.total_staked,
            "won_count": r.won_count,
        } for r in rows])

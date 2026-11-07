from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
import uuid
from flask import Blueprint, jsonify, request

from common.crypto_ports import (
    cred_service_port, custody_port, sealer_port, signer_port, token_policy_port
)
from services.database import (
    ArbiterAuditModel, ArbiterShareModel, BmBetModel, BmTokenExposureModel,
    ClientModel, CustodyShareModel, DisclosureModel, DisclosureShareModel,
    EventModel, HoldModel, LinkModel, RegulatorBetModel, SessionLocal,
    SettlementModel, WalletReceiptModel, WalletStateModel
)
from services.bookmaker import accept_bet_at_bookmaker, quote_at_bookmaker
from services.regulator import (
    append_audit, get_or_create_account, record_double_entry,
    register_client_at_regulator, resolve_disclosure
)

client_bp = Blueprint("client_wallet", __name__)


# =============================================================================
# ЭТАП 1 (РЕГИСТРАЦИЯ) — СТОРОНА КЛИЕНТА
#
# Клиент показывает документы и получает обратно готовый набор:
# токены по конторам, приватные ключи подписи к ним, справки допуска
# и свою долю ключа от архива. Всё это создаёт регулятор.
# =============================================================================
@client_bp.route("/register", methods=["POST"])
def register_client_flow():
    data = request.get_json(silent=True) or {}
    full_name = data.get("full_name", "Иванов Иван Иванович")
    passport = data.get("passport", "4018 123456")
    age = int(data.get("age", 23))
    client_id = f"cli_{uuid.uuid4().hex[:8]}"

    with SessionLocal() as session:
        session.query(WalletStateModel).delete()
        session.query(WalletReceiptModel).delete()
        session.query(ClientModel).delete()
        session.query(LinkModel).delete()
        session.query(CustodyShareModel).delete()
        session.query(ArbiterShareModel).delete()
        session.query(DisclosureShareModel).delete()
        session.query(DisclosureModel).delete()
        session.flush()

        # --- всё делает регулятор ---------------------------------------
        issued = register_client_at_regulator(
            session, client_id=client_id, full_name=full_name,
            passport=passport, age=age,
        )

        # --- доля #3 уезжает арбитру -------------------------------------
        session.add(ArbiterShareModel(client_id=client_id, share_payload=issued["shares"]["arbiter"]))
        session.add(ArbiterAuditModel(
            ts=datetime.now().strftime("%H:%M:%S"),
            action="SHARE_STORED",
            details=f"Получена резервная доля #3 для {client_id}",
        ))

        # --- кошелёк клиента ---------------------------------------------
        session.add(WalletStateModel(
            client_id=client_id,
            full_name=full_name,
            passport=passport,
            age=age,
            book_private_keys=json.dumps(issued["private_keys"], ensure_ascii=False),
            client_share=issued["shares"]["client"],
            credential_id=issued["credentials"]["bk_alpha"]["cred_id"],
            credentials_blob=json.dumps(issued["credentials"], ensure_ascii=False),
            token_alpha=issued["tokens"]["bk_alpha"],
            token_beta=issued["tokens"]["bk_beta"],
            zk_alpha="", zk_beta="",
        ))
        session.commit()

    return jsonify({
        "client_id": client_id,
        "tokens": issued["tokens"],
        "credential_id": issued["credentials"]["bk_alpha"]["cred_id"],
    }), 201


@client_bp.route("/step2-deposit-all", methods=["POST"])
def step2_deposit_all():
    with SessionLocal() as session:
        w = session.query(WalletStateModel).first()
        if not w:
            return jsonify({"error": "CLIENT_NOT_REGISTERED"}), 400

        cli_ref = f"client:{w.client_id}"
        cli_acc = get_or_create_account(session, cli_ref)
        bk_acc = get_or_create_account(session, "bookmaker:bk_alpha")
        bank_acc = get_or_create_account(session, "external:bank")

        cli_amount = 3000_00
        bk_amount = 10000_00

        cli_acc.available += cli_amount
        cli_acc.version += 1
        bk_acc.available += bk_amount
        bk_acc.version += 1
        bank_acc.available -= (cli_amount + bk_amount)

        record_double_entry(session, "external:bank", cli_ref, cli_amount, "tx_cli_dep")
        record_double_entry(session, "external:bank", "bookmaker:bk_alpha", bk_amount, "tx_bk_topup")

        append_audit(session, cli_ref, "DEPOSIT", {"amount": cli_amount})
        append_audit(session, "bookmaker:bk_alpha", "LIQUIDITY_TOP_UP", {"amount": bk_amount})
        session.commit()
        return jsonify({"ok": True})


# =============================================================================
# ЭТАП 2 (СТАВКА) — СТОРОНА КЛИЕНТА
#
# Порядок шагов:
#   1. клиент берёт токен и справку допуска для этой конторы
#   2. идёт к букмекеру, передавая токен и справку
#   3. букмекер проверяет подпись регулятора на справке САМ, офлайн,
#      и выдаёт котировку с обязательством на коэффициент
#   4. клиент подписывает котировку своим ключом для этой конторы
#   5. букмекер проверяет подпись по публичному ключу из справки
#      и регистрирует ставку у регулятора — тот замораживает два холда
#
# Приватные ключи подписи не покидают кошелёк.
# =============================================================================
@client_bp.route("/place-bet", methods=["POST"])
def place_bet_flow():
    data = request.get_json(silent=True) or {}
    selection = data.get("selection", "HOME_WIN")
    stake_kop = int(data.get("stake", 1000_00))

    with SessionLocal() as session:
        w = session.query(WalletStateModel).first()
        if not w:
            return jsonify({"error": "CLIENT_NOT_REGISTERED"}), 400

        # --- шаг 1: берём токен и справку для этой конторы ------------------
        token = w.token_alpha
        credentials = json.loads(w.credentials_blob or "{}")
        credential = credentials.get("bk_alpha")
        if not credential:
            return jsonify({"error": "CREDENTIAL_NOT_FOUND"}), 400

        # --- шаги 2-3: котировка у букмекера --------------------------------
        quote = quote_at_bookmaker(
            session, token=token, credential=credential,
            event_id="ev_final_2026", selection=selection, stake=stake_kop,
        )
        if "error" in quote:
            session.commit()                      # журнал отказа сохраняем
            return jsonify(quote), 403

        odds_dec = Decimal(quote["odds"])
        odds_str = quote["odds"]
        quote_id = quote["quote_id"]

        potential_payout = int((Decimal(stake_kop) * odds_dec).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        bk_risk = potential_payout - stake_kop

        cli_ref = f"client:{w.client_id}"
        bk_ref = "bookmaker:bk_alpha"
        cli_acc = get_or_create_account(session, cli_ref)
        bk_acc = get_or_create_account(session, bk_ref)

        if cli_acc.available < stake_kop:
            return jsonify({"error": "INSUFFICIENT_CLIENT_FUNDS"}), 400
        if bk_acc.available < bk_risk:
            return jsonify({"error": "INSUFFICIENT_BOOKMAKER_LIQUIDITY"}), 400

        # --- шаг 4: клиент подписывает котировку ----------------------------
        signed_payload = {
            "quote_id": quote_id, "token": token, "event_id": "ev_final_2026",
            "selection": selection, "stake": stake_kop, "odds": odds_str,
        }
        private_keys = json.loads(w.book_private_keys or "{}")
        client_sig = token_policy_port.sign_as_token(private_keys["bk_alpha"], signed_payload)

        # --- шаг 5: букмекер проверяет подпись по ключу из справки ----------
        accepted = accept_bet_at_bookmaker(
            session, quote_id, token, client_sig,
            credential["claims"]["public_key"],
        )
        if "error" in accepted:
            session.commit()
            return jsonify(accepted), 403

        bet_id = f"bet_{uuid.uuid4().hex[:6]}"

        # Атомарная заморозка двух холдов в Эскроу Регулятора
        cli_acc.available -= stake_kop
        cli_acc.held += stake_kop
        cli_acc.version += 1

        bk_acc.available -= bk_risk
        bk_acc.held += bk_risk
        bk_acc.version += 1

        h_cli_id = f"hold_cli_{quote_id}"
        h_bk_id = f"hold_bk_{quote_id}"

        session.add(HoldModel(
            id=h_cli_id, owner_ref=cli_ref, amount=stake_kop, status="ACTIVE", hold_type="CLIENT_STAKE", ref_id=bet_id
        ))
        session.add(HoldModel(
            id=h_bk_id, owner_ref=bk_ref, amount=bk_risk, status="ACTIVE", hold_type="BOOKMAKER_RISK", ref_id=bet_id
        ))

        session.add(RegulatorBetModel(
            id=bet_id, token=token, bookmaker_id="bk_alpha", event_id="ev_final_2026",
            selection=selection, stake=stake_kop, odds=odds_str, status="ACCEPTED",
            client_hold_id=h_cli_id, bookmaker_hold_id=h_bk_id,
        ))

        # ЭТАП 2: обязательство пришло из котировки, вместе с солью.
        # Раньше здесь был голый SHA-256 от предсказуемых полей: коэффициентов
        # мало, и такой хэш подбирается перебором за секунду, то есть ничего
        # не скрывает. Теперь хэш считается с случайной солью, а соль
        # раскрывается только после расчёта события.
        commitment = accepted["quote"].odds_commitment
        receipt_sig = signer_port.sign("bk_alpha", "", {"bet_id": bet_id, "token": token, "odds": odds_str})

        exp = session.query(BmTokenExposureModel).filter_by(token=token).first()
        if not exp:
            exp = BmTokenExposureModel(token=token, bets_count=0, total_staked=0, won_count=0)
            session.add(exp)
        exp.bets_count += 1
        exp.total_staked += stake_kop

        session.add(BmBetModel(
            id=bet_id, quote_id=quote_id, token=token, event_id="ev_final_2026",
            selection=selection, stake=stake_kop, odds=odds_str,
            odds_commitment=commitment, odds_salt="", client_sig=client_sig,
            status="ACCEPTED", bookmaker_sig=receipt_sig,
        ))

        session.add(WalletReceiptModel(
            bet_id=bet_id, token=token, selection=selection,
            stake=stake_kop, odds=odds_str, bookmaker_sig=receipt_sig,
        ))

        ev = session.query(EventModel).filter_by(id="ev_final_2026").first()
        if ev:
            ev.status = "ACTIVE_BETS"
            ev.outcome = None

        append_audit(session, "bk_alpha", "CLIENT_SIGNATURE_VERIFIED", {"quote_id": quote_id})
        append_audit(session, "bk_alpha", "BET_ACCEPTED", {
            "bet_id": bet_id, "token": token[:16], "stake": stake_kop,
            "odds": odds_str, "bk_risk_hold": bk_risk
        })
        session.commit()
        return jsonify({
            "bet_id": bet_id, "status": "ACCEPTED", "quote_id": quote_id,
            "odds": odds_str, "odds_commitment": commitment,
        }), 201


# =============================================================================
# ЭТАП 4 (РАСКРЫТИЕ) — КЛИЕНТ ТОЛЬКО ПРОСИТ
#
# Собирать порог клиент не может: ключи подписи ему выдал регулятор,
# а значит регулятор мог бы подписать согласие за него и раскрыть запись
# в одиночку. Поэтому вторая доля приходит только от арбитра, а клиент
# лишь направляет ему просьбу.
# =============================================================================
@client_bp.route("/disclosures/approve", methods=["POST"])
def client_request_disclosure():
    data = request.get_json(silent=True) or {}
    with SessionLocal() as session:
        disc = session.query(DisclosureModel).order_by(DisclosureModel.created_at.desc()).first()
        if not disc:
            return jsonify({"error": "NO_ACTIVE_DISCLOSURE"}), 404

        append_audit(session, "client", "DISCLOSURE_CLIENT_REQUESTED_ARBITER", {
            "request_id": disc.id, "reason": data.get("reason", "Клиент просит подтвердить свою ставку"),
        })
        result = resolve_disclosure(session, disc.id)
        session.commit()
        return jsonify({
            "status": result.get("status"),
            "collected": result.get("collected", []),
            "message": "Просьба передана арбитру. Решение за ним.",
        })


@client_bp.route("/settlements", methods=["GET"])
def client_settlements():
    """
    ЭТАП 3: расчётные квитанции, подписанные регулятором.

    Клиент проверяет подпись сам и может предъявить квитанцию как
    доказательство того, что и сколько было выплачено.
    """
    with SessionLocal() as session:
        w = session.query(WalletStateModel).first()
        if not w:
            return jsonify([])
        rows = session.query(SettlementModel).filter_by(token=w.token_alpha).all()
        out = []
        for r in rows:
            body = {"bet_id": r.bet_id, "token": r.token, "event_id": r.event_id,
                    "outcome": r.outcome, "result": r.result, "amount": r.amount}
            out.append({
                **body,
                "regulator_sig": r.regulator_sig,
                "signature_valid": signer_port.verify("regulator", "", body, r.regulator_sig),
            })
        return jsonify(out)

from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
import uuid
from flask import Blueprint, jsonify, request

from common.crypto_ports import (
    cred_service_port, custody_port, schnorr_port, sealer_port, signer_port, token_policy_port
)
from services.database import (
    ArbiterAuditModel, ArbiterShareModel, BmBetModel, BmTokenExposureModel,
    ClientModel, CustodyShareModel, DisclosureModel, DisclosureShareModel,
    EventModel, HoldModel, LinkModel, RegulatorBetModel, SessionLocal,
    SettlementModel, WalletReceiptModel, WalletStateModel
)
from services.bookmaker import accept_bet_at_bookmaker, quote_at_bookmaker
from services.regulator import (
    SCHNORR_CONTEXT, append_audit, get_or_create_account, link_token_at_regulator,
    record_double_entry, register_client_at_regulator, resolve_disclosure,
    submit_disclosure_share
)

client_bp = Blueprint("client_wallet", __name__)


# =============================================================================
# ЭТАП 1 (РЕГИСТРАЦИЯ) — СТОРОНА КЛИЕНТА
#
# Порядок шагов принципиален и ровно такой:
#   2. клиент генерирует секрет s у себя (CSPRNG)
#   3. считает публичную точку S_pub = s*G и доказательство владения ею
#   -> отправляет регулятору ТОЛЬКО S_pub и доказательство, секрет остаётся тут
#   4-7. регулятор проверяет, шифрует запись, режет ключ Шамиром, выдаёт справку
#   8. клиент сохраняет s, свою долю и справку
#
# Секрет s не уходит из этой функции никуда, кроме локального кошелька.
# =============================================================================
@client_bp.route("/register", methods=["POST"])
def register_client_flow():
    data = request.get_json(silent=True) or {}
    full_name = data.get("full_name", "Иванов Иван Иванович")
    passport = data.get("passport", "4018 123456")
    age = int(data.get("age", 23))

    # --- шаг 2: CSPRNG, секрет клиента ---------------------------------------
    # Раньше здесь была строковая константа. Теперь это настоящие 256 бит
    # из криптографического генератора: на предсказуемости этого числа
    # держится вообще всё остальное.
    client_id = f"cli_{uuid.uuid4().hex[:8]}"
    secret_s = schnorr_port.generate_secret()

    # --- шаг 3: публичная анкета и доказательство владения -------------------
    s_pub = schnorr_port.public_point(secret_s)
    schnorr_proof = schnorr_port.prove(secret_s, SCHNORR_CONTEXT)

    # ЭТАП 2: деривация токенов P_B = s * H(контора) и ZK-доказательства
    # пока остаются заглушкой NoopTokenPolicy — это следующая веха.
    tok_alpha, zk_alpha = token_policy_port.derive_token(secret_s, "bk_alpha")
    tok_beta, zk_beta = token_policy_port.derive_token(secret_s, "bk_beta")

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

        # --- шаги 4-7: сторона регулятора (:5001) ----------------------------
        # Через границу уходят только s_pub и доказательство.
        try:
            reg_result = register_client_at_regulator(
                session,
                client_id=client_id,
                full_name=full_name,
                passport=passport,
                age=age,
                s_pub=s_pub,
                schnorr_proof=schnorr_proof,
            )
        except ValueError as exc:
            session.rollback()
            return jsonify({"error": str(exc)}), 403

        cred = reg_result["credential"]
        shares = reg_result["shares"]

        link_token_at_regulator(session, client_id, tok_alpha, "bk_alpha")
        link_token_at_regulator(session, client_id, tok_beta, "bk_beta")

        # --- доля #3 уезжает Арбитру (:5004) ---------------------------------
        session.add(ArbiterShareModel(client_id=client_id, share_payload=shares["arbiter"]))
        session.add(ArbiterAuditModel(
            ts=datetime.now().strftime("%H:%M:%S"),
            action="SHARE_STORED",
            details=f"Получена резервная доля #3 для {client_id}",
        ))

        # --- шаг 8: локальный кошелёк клиента (:5003) ------------------------
        session.add(WalletStateModel(
            client_id=client_id,
            full_name=full_name,
            passport=passport,
            age=age,
            client_secret_s=secret_s,
            s_pub=s_pub,
            schnorr_proof=schnorr_proof,
            client_share=shares["client"],
            credential_id=cred["cred_id"],
            credential_blob=json.dumps(cred, ensure_ascii=False),
            token_alpha=tok_alpha,
            token_beta=tok_beta,
            zk_alpha=zk_alpha,
            zk_beta=zk_beta,
        ))

        session.commit()

    return jsonify({
        "client_id": client_id,
        "s_pub": s_pub,
        "credential_id": cred["cred_id"],
        "token_alpha": tok_alpha,
        "token_beta": tok_beta,
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
#   1. клиент заново выводит токен P_B = s * H_B и строит свежее
#      доказательство Шаума-Педерсена
#   2. идёт к букмекеру за коэффициентом, передавая ТОЛЬКО токен и
#      доказательство
#   3. букмекер проверяет токен (через регулятора) и выдаёт котировку
#   4. клиент подписывает котировку ключом, привязанным к токену
#   5. букмекер проверяет подпись по токену и регистрирует ставку
#      у регулятора — тот замораживает два холда
#
# Секрет s снова не покидает эту функцию.
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

        # --- шаг 1: токен и свежее доказательство ---------------------------
        token, zk_proof = token_policy_port.derive_token(w.client_secret_s, "bk_alpha")
        if token != w.token_alpha:
            return jsonify({"error": "TOKEN_DERIVATION_MISMATCH"}), 500

        # --- шаги 2-3: котировка у букмекера --------------------------------
        quote = quote_at_bookmaker(
            session, token=token, zk_proof=zk_proof,
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
        client_sig = token_policy_port.sign_as_token(w.client_secret_s, "bk_alpha", signed_payload)

        # --- шаг 5: букмекер проверяет подпись ------------------------------
        accepted = accept_bet_at_bookmaker(session, quote_id, token, client_sig)
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
# ЭТАП 4 (РАСКРЫТИЕ) — ДОБРОВОЛЬНОЕ УЧАСТИЕ КЛИЕНТА
#
# Клиент отдаёт свою долю сам — например, чтобы доказать в споре, что
# ставка его. Именно эта возможность и есть смысл схемы «2 из 3»:
# в обычном случае раскрытие идёт С УЧАСТИЕМ клиента, а без него —
# только через арбитра и только по основанию.
# =============================================================================
@client_bp.route("/disclosures/approve", methods=["POST"])
def client_voluntary_disclosure():
    data = request.get_json(silent=True) or {}
    with SessionLocal() as session:
        disc = (session.query(DisclosureModel).filter_by(id=data["disclosure_id"]).first()
                if data.get("disclosure_id")
                else session.query(DisclosureModel).order_by(DisclosureModel.created_at.desc()).first())
        w = session.query(WalletStateModel).first()
        if not disc or not w:
            return jsonify({"error": "NO_ACTIVE_DISCLOSURE"}), 404

        submit_disclosure_share(session, disc.id, "client", w.client_share)
        result = resolve_disclosure(session, disc.id)

        append_audit(session, "client", "DISCLOSURE_VOLUNTARY_REVEALED", {
            "request_id": disc.id, "parties": result.get("collected", []),
        })
        session.commit()
        return jsonify({"status": result.get("status"), "collected": result.get("collected", [])})


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

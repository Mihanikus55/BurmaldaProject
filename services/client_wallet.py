from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import uuid
from flask import Blueprint, jsonify, request

from common.crypto_ports import (
    cred_service_port, custody_port, sealer_port, signer_port, token_policy_port
)
from services.database import (
    ArbiterAuditModel, ArbiterShareModel, BmBetModel, BmTokenExposureModel,
    ClientModel, CustodyShareModel, DisclosureModel, DisclosureShareModel,
    EventModel, HoldModel, LinkModel, RegulatorBetModel, SessionLocal,
    WalletReceiptModel, WalletStateModel
)
from services.regulator import append_audit, get_or_create_account, record_double_entry

client_bp = Blueprint("client_wallet", __name__)


@client_bp.route("/register", methods=["POST"])
def register_client_flow():
    data = request.json or {}
    full_name = data.get("full_name", "Иванов Иван Иванович")
    passport = data.get("passport", "4018 123456")
    age = int(data.get("age", 23))

    client_id = "cli_8a9de24b"
    secret_s = "sec_7f9a2b4c8e1d6f3a9b0c"
    dek = sealer_port.generate_dek()
    shares = custody_port.split_key(dek)

    tok_alpha, zk_alpha = token_policy_port.derive_token(secret_s, "bk_alpha")
    tok_beta, zk_beta = token_policy_port.derive_token(secret_s, "bk_beta")
    cred = cred_service_port.issue_credential(client_id, secret_s, {
        "adult": age >= 18,
        "kyc_ok": True,
        "not_excluded": True,
        "limits_ok": True,
    })

    pd_sealed = sealer_port.seal(dek, {
        "client_id": client_id,
        "full_name": full_name,
        "passport": passport,
        "age": age,
    })
    sealed_ref = sealer_port.seal(dek, {"client_id": client_id})

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

        # 1. Запись у Регулятора (:5001)
        session.add(ClientModel(id=client_id, kyc_status="VERIFIED", pd_blob=pd_sealed))
        session.add(CustodyShareModel(client_id=client_id, party="regulator", payload=shares["regulator"]))
        session.add(LinkModel(token=tok_alpha, bookmaker_id="bk_alpha", client_ref_sealed=sealed_ref))
        session.add(LinkModel(token=tok_beta, bookmaker_id="bk_beta", client_ref_sealed=sealed_ref))
        get_or_create_account(session, f"client:{client_id}")

        # 2. Запись у Арбитра (:5004)
        session.add(ArbiterShareModel(client_id=client_id, share_payload=shares["arbiter"]))
        session.add(ArbiterAuditModel(
            ts=datetime.now().strftime("%H:%M:%S"),
            action="SHARE_STORED",
            details=f"Получена резервная доля #3 для {client_id}",
        ))

        # 3. Запись в локальном Кошельке Клиента (:5003)
        session.add(WalletStateModel(
            client_id=client_id,
            full_name=full_name,
            passport=passport,
            age=age,
            client_secret_s=secret_s,
            client_share=shares["client"],
            credential_id=cred["cred_id"],
            token_alpha=tok_alpha,
            token_beta=tok_beta,
            zk_alpha=zk_alpha,
            zk_beta=zk_beta,
        ))

        append_audit(session, "regulator", "CLIENT_REGISTERED", {"client_id": client_id})
        append_audit(session, "regulator", "TOKEN_LINKED", {"token": tok_alpha, "bookmaker_id": "bk_alpha"})
        session.commit()

    return jsonify({"client_id": client_id, "token_alpha": tok_alpha, "token_beta": tok_beta}), 201


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


@client_bp.route("/place-bet", methods=["POST"])
def place_bet_flow():
    data = request.json or {}
    selection = data.get("selection", "HOME_WIN")
    stake_kop = int(data.get("stake", 1000_00))
    odds_dec = Decimal("2.40") if selection == "HOME_WIN" else Decimal("1.65")
    odds_str = f"{odds_dec:.2f}"

    potential_payout = int((Decimal(stake_kop) * odds_dec).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    bk_risk = potential_payout - stake_kop

    with SessionLocal() as session:
        w = session.query(WalletStateModel).first()
        if not w:
            return jsonify({"error": "CLIENT_NOT_REGISTERED"}), 400

        cli_ref = f"client:{w.client_id}"
        bk_ref = "bookmaker:bk_alpha"
        cli_acc = get_or_create_account(session, cli_ref)
        bk_acc = get_or_create_account(session, bk_ref)

        if cli_acc.available < stake_kop:
            return jsonify({"error": "INSUFFICIENT_CLIENT_FUNDS"}), 400
        if bk_acc.available < bk_risk:
            return jsonify({"error": "INSUFFICIENT_BOOKMAKER_LIQUIDITY"}), 400

        quote_id = f"q_{uuid.uuid4().hex[:6]}"
        bet_id = f"bet_{uuid.uuid4().hex[:6]}"
        token = w.token_alpha

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

        commitment = hashlib.sha256(f"{quote_id}:{token}:{odds_str}:{stake_kop}".encode("utf-8")).hexdigest()
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
            odds_commitment=commitment, status="ACCEPTED", bookmaker_sig=receipt_sig,
        ))

        session.add(WalletReceiptModel(
            bet_id=bet_id, token=token, selection=selection,
            stake=stake_kop, odds=odds_str, bookmaker_sig=receipt_sig,
        ))

        ev = session.query(EventModel).filter_by(id="ev_final_2026").first()
        if ev:
            ev.status = "ACTIVE_BETS"
            ev.outcome = None

        append_audit(session, "bk_alpha", "BET_ACCEPTED", {
            "bet_id": bet_id, "token": token, "stake": stake_kop, "odds": odds_str, "bk_risk_hold": bk_risk
        })
        session.commit()
        return jsonify({"bet_id": bet_id, "status": "ACCEPTED"}), 201


@client_bp.route("/disclosures/approve", methods=["POST"])
def client_voluntary_disclosure():
    with SessionLocal() as session:
        disc = session.query(DisclosureModel).first()
        w = session.query(WalletStateModel).first()
        if not disc or not w:
            return jsonify({"error": "NO_ACTIVE_DISCLOSURE"}), 404

        existing = session.query(DisclosureShareModel).filter_by(
            disclosure_id=disc.id, party="client"
        ).first()
        if not existing:
            session.add(DisclosureShareModel(
                disclosure_id=disc.id, party="client", payload=w.client_share
            ))
        disc.status = "REVEALED"

        append_audit(session, "client", "DISCLOSURE_VOLUNTARY_REVEALED", {
            "request_id": disc.id, "parties": ["regulator", "client"]
        })
        session.commit()
        return jsonify({"status": "REVEALED"})

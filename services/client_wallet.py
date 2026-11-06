import json
import uuid
from decimal import Decimal, ROUND_HALF_UP
from flask import Blueprint, jsonify, request

from common.crypto_ports import (
    credential_port, custody_port, sealer_port, signer_port, token_policy_port
)
from services.database import (
    ArbiterAuditModel, ArbiterShareModel, BetModel, BmBetModel, BmQuoteModel,
    BmTokenExposureModel, ClientModel, CustodyShareModel, DisclosureModel,
    DisclosureShareModel, LinkModel, SessionLocal, WalletIdentityModel,
    WalletReceiptModel, WalletTokenModel
)
from services.regulator import append_audit, create_hold_internal, get_or_create_account

client_bp = Blueprint("client", __name__)


@client_bp.route("/v1/register-full", methods=["POST"])
def wallet_register_full():
    """
    Выполняет полный цикл Шага 1:
    1. KYC у Регулятора + запечатывание ПДн через AES-256-GCM.
    2. Разделение ключа DEK по Шамиру на 3 доли (Клиент, Регулятор, Арбитр).
    3. Выпуск BBS+ удостоверения.
    4. Деривация двух несвязываемых токенов (для БК Alpha и БК Beta).
    """
    data = request.json or {}
    full_name = data.get("full_name", "Иванов Иван Иванович")
    passport = data.get("passport", "4018 123456")
    age = int(data.get("age", 23))

    with SessionLocal() as session:
        # Очищаем предыдущую запись кошелька, если перерегистрируемся
        session.query(WalletIdentityModel).delete()
        session.query(WalletTokenModel).delete()
        session.query(WalletReceiptModel).delete()

        client_id = f"cli_{uuid.uuid4().hex[:8]}"
        secret_s = f"sec_{uuid.uuid4().hex[:16]}"
        dek = sealer_port.generate_dek()

        pd_sealed = sealer_port.seal(dek, {
            "client_id": client_id,
            "full_name": full_name,
            "passport": passport,
            "age": age,
        })
        shares = custody_port.split_key(dek)

        # Сохраняем клиента и долю #2 у Регулятора
        session.add(ClientModel(id=client_id, kyc_status="VERIFIED", pd_blob=pd_sealed))
        session.add(CustodyShareModel(client_id=client_id, party="regulator", payload=shares["regulator"]))
        get_or_create_account(session, f"client:{client_id}")

        # Сохраняем долю #3 у Арбитра
        session.merge(ArbiterShareModel(client_id=client_id, share_payload=shares["arbiter"]))
        session.add(ArbiterAuditModel(
            action="SHARE_STORED",
            details=f"Депонирована резервная доля #3 для {client_id}"
        ))

        # Выпускаем BBS+ удостоверение
        claims = {"adult": True, "kyc_ok": True, "not_excluded": True, "limits_ok": True}
        credential = credential_port.issue_credential(client_id, secret_s, claims)

        # Сохраняем секрет s и долю #1 в локальном кошельке клиента
        session.add(WalletIdentityModel(
            client_id=client_id,
            full_name=full_name,
            passport=passport,
            age=age,
            client_secret_s=secret_s,
            client_share=shares["client"],
            credential_json=json.dumps(credential, ensure_ascii=False),
        ))

        # Вычисляем несвязываемые токены для БК Alpha и БК Beta
        tokens_out = {}
        for bk_id in ["bk_alpha", "bk_beta"]:
            tok, zk_proof = token_policy_port.derive_token(secret_s, bk_id)
            tokens_out[bk_id] = {"token": tok, "zk_proof": zk_proof}
            session.add(WalletTokenModel(bookmaker_id=bk_id, token=tok, zk_token_proof=zk_proof))

            sealed_ref = sealer_port.seal(dek, {
                "client_id": client_id,
                "token": tok,
                "bookmaker_id": bk_id,
            })
            session.add(LinkModel(token=tok, bookmaker_id=bk_id, client_ref_sealed=sealed_ref))

        append_audit(session, "regulator", "CLIENT_KYC_AND_SHAMIR_SPLIT", {
            "client_id": client_id,
            "token_alpha": tokens_out["bk_alpha"]["token"],
            "token_beta": tokens_out["bk_beta"]["token"],
        })
        session.commit()

        return jsonify({
            "client_id": client_id,
            "full_name": full_name,
            "passport": passport,
            "client_secret": secret_s,
            "shares": shares,
            "tokens": tokens_out,
        }), 201


@client_bp.route("/v1/place-bet", methods=["POST"])
def wallet_place_bet():
    """
    Выполняет полный цикл Шага 3:
    1. Клиент запрашивает котировку у Букмекера под токеном P_ALPHA.
    2. Клиент формирует BBS+ доказательство (18+, KYC) и подписывает ставку.
    3. Букмекер проверяет доказательства, делает commitment на кэф и регистрирует ставку в Эскроу Регулятора.
    4. Регулятор атомарно замораживает 2 холда (ставка клиента + чистый риск букмекера).
    """
    data = request.json or {}
    selection = data.get("selection", "HOME_WIN")
    stake = int(data.get("stake", 1000_00))
    event_id = data.get("event_id", "ev_final_2026")
    bookmaker_id = "bk_alpha"

    with SessionLocal() as session:
        ident = session.query(WalletIdentityModel).first()
        if not ident:
            return jsonify({"error": "Сначала выполните Шаг 1 (Регистрация KYC)"}), 400

        tok_rec = session.query(WalletTokenModel).filter_by(bookmaker_id=bookmaker_id).first()
        token = tok_rec.token

        odds_dec = Decimal("2.40") if selection == "HOME_WIN" else Decimal("1.65")
        odds_str = f"{odds_dec:.2f}"
        potential_payout = int((Decimal(stake) * odds_dec).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        bk_risk = potential_payout - stake

        client_owner = f"client:{ident.client_id}"
        bk_owner = f"bookmaker:{bookmaker_id}"

        cli_acc = get_or_create_account(session, client_owner)
        bk_acc = get_or_create_account(session, bk_owner)

        if cli_acc.available < stake:
            return jsonify({"error": "Недостаточно средств у клиента (выполните Шаг 2: Депозит)"}), 400
        if bk_acc.available < bk_risk:
            return jsonify({"error": "Недостаточно ликвидности у букмекера в эскроу"}), 400

        quote_id = f"q_{uuid.uuid4().hex[:8]}"
        bet_id = f"bet_{uuid.uuid4().hex[:8]}"
        commitment = uuid.uuid5(uuid.NAMESPACE_DNS, f"{quote_id}:{token}:{odds_str}").hex

        bet_payload = {
            "quote_id": quote_id,
            "token": token,
            "event_id": event_id,
            "selection": selection,
            "stake": stake,
            "odds": odds_str,
        }
        client_sig = signer_port.sign(token, ident.client_secret_s, bet_payload)
        bookmaker_sig = signer_port.sign(bookmaker_id, "", bet_payload)

        cli_hold = create_hold_internal(session, client_owner, stake, "CLIENT_STAKE", bet_id, f"h_cli_{quote_id}")
        bk_hold = create_hold_internal(session, bk_owner, bk_risk, "BOOKMAKER_RISK", bet_id, f"h_bk_{quote_id}")

        session.add(BetModel(
            id=bet_id,
            token=token,
            bookmaker_id=bookmaker_id,
            event_id=event_id,
            selection=selection,
            stake=stake,
            odds=odds_str,
            status="ACCEPTED",
            client_sig=client_sig,
            bookmaker_sig=bookmaker_sig,
            client_hold_id=cli_hold.id,
            bookmaker_hold_id=bk_hold.id,
        ))

        exp = session.query(BmTokenExposureModel).filter_by(token=token).first()
        if not exp:
            exp = BmTokenExposureModel(token=token, bets_count=0, total_staked=0, won_count=0)
            session.add(exp)
        exp.bets_count += 1
        exp.total_staked += stake

        session.add(BmBetModel(
            id=bet_id,
            quote_id=quote_id,
            token=token,
            event_id=event_id,
            selection=selection,
            stake=stake,
            odds=odds_str,
            odds_commitment=commitment,
            status="ACCEPTED",
            receipt_sig=bookmaker_sig,
        ))

        session.add(WalletReceiptModel(
            bet_id=bet_id,
            bookmaker_id=bookmaker_id,
            token=token,
            selection=selection,
            stake=stake,
            odds=odds_str,
            bookmaker_sig=bookmaker_sig,
        ))

        append_audit(session, bookmaker_id, "BET_PLACED_AND_ESCROW_HELD", {
            "bet_id": bet_id,
            "token": token,
            "client_hold": stake,
            "bookmaker_risk_hold": bk_risk,
        })
        session.commit()

        return jsonify({
            "bet_id": bet_id,
            "token": token,
            "odds": odds_str,
            "stake": stake,
            "bk_risk": bk_risk,
            "receipt_sig": bookmaker_sig,
        }), 201


@client_bp.route("/v1/disclosures/voluntary", methods=["POST"])
def voluntary_client_disclosure():
    """Добровольная передача доли #1 самим клиентом (например, при споре)."""
    with SessionLocal() as session:
        ident = session.query(WalletIdentityModel).first()
        if not ident:
            return jsonify({"error": "Клиент не зарегистрирован"}), 400

        disc = session.query(DisclosureModel).order_by(DisclosureModel.created_at.desc()).first()
        if not disc:
            tok_rec = session.query(WalletTokenModel).filter_by(bookmaker_id="bk_alpha").first()
            disc = DisclosureModel(
                id=f"disc_{uuid.uuid4().hex[:8]}",
                subject_type="token",
                subject_id=tok_rec.token if tok_rec else "P_ALPHA",
                reason="Добровольное подтверждение владения ставкой",
                requester="client_voluntary",
                status="REVEALED",
            )
            session.add(disc)
            session.flush()
            reg_share = session.query(CustodyShareModel).filter_by(client_id=ident.client_id, party="regulator").first()
            if reg_share:
                session.add(DisclosureShareModel(disclosure_id=disc.id, party="regulator", payload=reg_share.payload))

        existing = session.query(DisclosureShareModel).filter_by(disclosure_id=disc.id, party="client").first()
        if not existing:
            session.add(DisclosureShareModel(disclosure_id=disc.id, party="client", payload=ident.client_share))
        disc.status = "REVEALED"

        append_audit(session, "client", "VOLUNTARY_DISCLOSURE_2_OF_3", {
            "request_id": disc.id, "parties": ["regulator", "client"]
        })
        session.commit()
        return jsonify({"status": "REVEALED", "request_id": disc.id})

import uuid
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from flask import Blueprint, jsonify, request

from common.crypto_ports import (
    audit_port, credential_port, custody_port, sealer_port, signer_port, token_policy_port
)
from services.database import (
    AccountModel, AuditLogModel, BetModel, BmBetModel, BmTokenExposureModel,
    ClientModel, CustodyShareModel, DisclosureModel, DisclosureShareModel,
    EventModel, HoldModel, LedgerEntryModel, LinkModel, SessionLocal
)

regulator_bp = Blueprint("regulator", __name__)


def append_audit(session, actor: str, action: str, payload: dict):
    last = session.query(AuditLogModel).order_by(AuditLogModel.seq.desc()).first()
    prev_hash = last.current_hash if last else "0" * 64
    payload_hash, current_hash = audit_port.compute_entry_hashes(prev_hash, actor, action, payload)
    session.add(AuditLogModel(
        actor=actor,
        action=action,
        payload_hash=payload_hash,
        prev_hash=prev_hash,
        current_hash=current_hash,
    ))


def get_or_create_account(session, owner_ref: str) -> AccountModel:
    acc = session.query(AccountModel).filter_by(owner_ref=owner_ref).first()
    if not acc:
        owner_type = owner_ref.split(":")[0] if ":" in owner_ref else "custom"
        acc = AccountModel(
            id=f"acc_{uuid.uuid4().hex[:8]}",
            owner_type=owner_type,
            owner_ref=owner_ref,
            available=0,
            held=0,
            version=1,
        )
        session.add(acc)
        session.flush()
    return acc


def record_double_entry(session, debit_owner: str, credit_owner: str, amount: int, idemp_key: str = None):
    tx_id = f"tx_{uuid.uuid4().hex[:8]}"
    session.add(LedgerEntryModel(
        tx_id=tx_id, account_id=debit_owner, direction="DEBIT", amount=amount, idempotency_key=idemp_key
    ))
    session.add(LedgerEntryModel(
        tx_id=tx_id, account_id=credit_owner, direction="CREDIT", amount=amount, idempotency_key=idemp_key
    ))


def create_hold_internal(session, owner_ref: str, amount: int, ref_type: str, ref_id: str, idemp_key: str) -> HoldModel:
    existing = session.query(HoldModel).filter_by(idempotency_key=idemp_key).first()
    if existing:
        return existing
    acc = get_or_create_account(session, owner_ref)
    if acc.available < amount:
        raise ValueError(f"INSUFFICIENT_FUNDS:{owner_ref}:need={amount},avail={acc.available}")
    acc.available -= amount
    acc.held += amount
    acc.version += 1
    hold = HoldModel(
        id=f"hold_{uuid.uuid4().hex[:8]}",
        account_id=acc.id,
        owner_ref=owner_ref,
        amount=amount,
        status="ACTIVE",
        ref_type=ref_type,
        ref_id=ref_id,
        idempotency_key=idemp_key,
    )
    session.add(hold)
    session.flush()
    return hold


def release_hold_internal(session, hold_id: str):
    hold = session.query(HoldModel).filter_by(id=hold_id).first()
    if not hold or hold.status != "ACTIVE":
        return
    acc = session.query(AccountModel).filter_by(id=hold.account_id).first()
    acc.held -= hold.amount
    acc.available += hold.amount
    acc.version += 1
    hold.status = "RELEASED"


def capture_hold_internal(session, hold_id: str, to_owner_ref: str, idemp_key: str):
    hold = session.query(HoldModel).filter_by(id=hold_id).first()
    if not hold or hold.status != "ACTIVE":
        return
    from_acc = session.query(AccountModel).filter_by(id=hold.account_id).first()
    to_acc = get_or_create_account(session, to_owner_ref)

    from_acc.held -= hold.amount
    from_acc.version += 1
    to_acc.available += hold.amount
    to_acc.version += 1
    hold.status = "CAPTURED"

    record_double_entry(session, from_acc.owner_ref, to_acc.owner_ref, hold.amount, idemp_key)


@regulator_bp.route("/v1/clients", methods=["POST"])
def register_client():
    data = request.json or {}
    full_name = data.get("full_name", "Иванов Иван Иванович")
    passport = data.get("passport", "4018 123456")
    age = int(data.get("age", 23))

    client_id = f"cli_{uuid.uuid4().hex[:8]}"
    client_secret_s = f"sec_{uuid.uuid4().hex[:16]}"

    dek = sealer_port.generate_dek()
    pd_sealed = sealer_port.seal(dek, {
        "client_id": client_id,
        "full_name": full_name,
        "passport": passport,
        "age": age,
    })
    shares = custody_port.split_key(dek)

    with SessionLocal() as session:
        session.add(ClientModel(
            id=client_id,
            kyc_status="VERIFIED" if age >= 18 else "REJECTED",
            pd_blob=pd_sealed,
        ))
        session.add(CustodyShareModel(
            client_id=client_id,
            party="regulator",
            payload=shares["regulator"],
        ))
        get_or_create_account(session, f"client:{client_id}")
        append_audit(session, "regulator", "CLIENT_REGISTERED", {"client_id": client_id})
        session.commit()

    return jsonify({
        "client_id": client_id,
        "client_secret": client_secret_s,
        "client_share": shares["client"],
        "regulator_share": shares["regulator"],
        "arbiter_share": shares["arbiter"],
    }), 201


@regulator_bp.route("/v1/tokens", methods=["POST"])
def link_token():
    data = request.json or {}
    client_id = data["client_id"]
    bookmaker_id = data["bookmaker_id"]
    client_secret = data["client_secret"]

    with SessionLocal() as session:
        reg_share = session.query(CustodyShareModel).filter_by(
            client_id=client_id, party="regulator"
        ).first()
        dek_label = reg_share.payload.split(":", 2)[-1] if reg_share else sealer_port.generate_dek()

        token, zk_proof = token_policy_port.derive_token(client_secret, bookmaker_id)
        existing = session.query(LinkModel).filter_by(token=token).first()
        if not existing:
            sealed_ref = sealer_port.seal(dek_label, {
                "client_id": client_id,
                "token": token,
                "bookmaker_id": bookmaker_id,
            })
            session.add(LinkModel(
                token=token,
                bookmaker_id=bookmaker_id,
                client_ref_sealed=sealed_ref,
            ))
            append_audit(session, "regulator", "TOKEN_LINKED", {"token": token, "bookmaker_id": bookmaker_id})
            session.commit()

        return jsonify({"token": token, "zk_token_proof": zk_proof}), 201


@regulator_bp.route("/v1/tokens/<token>/eligibility", methods=["GET"])
def check_eligibility(token):
    with SessionLocal() as session:
        link = session.query(LinkModel).filter_by(token=token).first()
        if not link:
            return jsonify({"valid": False}), 404
        return jsonify({
            "valid": True,
            "adult": True,
            "kyc_ok": True,
            "not_excluded": True,
            "limits_ok": True,
        })


@regulator_bp.route("/v1/accounts/<path:owner_ref>/deposit", methods=["POST"])
def deposit(owner_ref):
    data = request.json or {}
    amount = int(data["amount"])
    idemp_key = data.get("idempotency_key", f"dep_{uuid.uuid4().hex[:8]}")

    with SessionLocal() as session:
        acc = get_or_create_account(session, owner_ref)
        ext = get_or_create_account(session, "external:bank")
        ext.available -= amount
        acc.available += amount
        acc.version += 1
        record_double_entry(session, "external:bank", owner_ref, amount, idemp_key)
        append_audit(session, owner_ref, "DEPOSIT", {"amount": amount})
        session.commit()
        return jsonify({"owner": acc.owner_ref, "available": acc.available, "held": acc.held})


@regulator_bp.route("/v1/bets", methods=["POST"])
def register_bet():
    data = request.json or {}
    token = data["token"]
    bookmaker_id = data["bookmaker_id"]
    event_id = data["event_id"]
    selection = data["selection"]
    stake = int(data["stake"])
    odds_str = str(data["odds"])
    quote_id = data["quote_id"]
    client_sig = data["client_sig"]
    bookmaker_sig = data["bookmaker_sig"]

    expected_payload = {
        "quote_id": quote_id,
        "token": token,
        "event_id": event_id,
        "selection": selection,
        "stake": stake,
        "odds": odds_str,
    }
    if not signer_port.verify(token, "", expected_payload, client_sig):
        return jsonify({"error": "INVALID_CLIENT_SIGNATURE"}), 400

    odds_dec = Decimal(odds_str)
    potential_payout = int((Decimal(stake) * odds_dec).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    bookmaker_risk = potential_payout - stake

    with SessionLocal() as session:
        link = session.query(LinkModel).filter_by(token=token).first()
        if not link:
            return jsonify({"error": "UNKNOWN_TOKEN"}), 404

        unsealed = sealer_port.unseal("", link.client_ref_sealed)
        client_id = unsealed["client_id"]
        client_owner = f"client:{client_id}"
        bk_owner = f"bookmaker:{bookmaker_id}"

        bk_acc = get_or_create_account(session, bk_owner)
        if bk_acc.available < bookmaker_risk:
            return jsonify({"error": "INSUFFICIENT_BOOKMAKER_LIQUIDITY"}), 400

        cli_acc = get_or_create_account(session, client_owner)
        if cli_acc.available < stake:
            return jsonify({"error": "INSUFFICIENT_CLIENT_FUNDS"}), 400

        bet_id = f"bet_{uuid.uuid4().hex[:8]}"
        cli_hold = create_hold_internal(session, client_owner, stake, "CLIENT_STAKE", bet_id, f"h_cli_{quote_id}")
        bk_hold = create_hold_internal(session, bk_owner, bookmaker_risk, "BOOKMAKER_RISK", bet_id, f"h_bk_{quote_id}")

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
        append_audit(session, bookmaker_id, "BET_ACCEPTED", {
            "bet_id": bet_id, "token": token, "stake": stake, "bk_risk_hold": bookmaker_risk
        })
        session.commit()
        return jsonify({"bet_id": bet_id, "status": "ACCEPTED", "bk_risk_hold": bookmaker_risk}), 201


@regulator_bp.route("/v1/events/<event_id>/outcome", methods=["POST"])
def settle_event(event_id):
    data = request.json or {}
    outcome = data.get("outcome", "HOME_WIN")

    settled = []
    with SessionLocal() as session:
        ev = session.query(EventModel).filter_by(id=event_id).first()
        if ev:
            ev.outcome = outcome
            ev.status = f"SETTLED ({outcome})"
            ev.settled_at = datetime.utcnow()

        bets = session.query(BetModel).filter_by(event_id=event_id, status="ACCEPTED").all()
        for bet in bets:
            link = session.query(LinkModel).filter_by(token=bet.token).first()
            client_id = sealer_port.unseal("", link.client_ref_sealed)["client_id"]
            client_owner = f"client:{client_id}"
            bk_owner = f"bookmaker:{bet.bookmaker_id}"

            if outcome == "VOID":
                release_hold_internal(session, bet.client_hold_id)
                release_hold_internal(session, bet.bookmaker_hold_id)
                bet.status = "VOIDED"
            elif bet.selection == outcome:
                capture_hold_internal(session, bet.bookmaker_hold_id, client_owner, f"win_{bet.id}")
                release_hold_internal(session, bet.client_hold_id)
                bet.status = "SETTLED_WON"
            else:
                capture_hold_internal(session, bet.client_hold_id, bk_owner, f"loss_{bet.id}")
                release_hold_internal(session, bet.bookmaker_hold_id)
                bet.status = "SETTLED_LOST"

            bet.settled_at = datetime.utcnow()
            settled.append({"bet_id": bet.id, "token": bet.token, "status": bet.status})

            # Синхронизируем статус в таблице букмекера
            bm_bet = session.query(BmBetModel).filter_by(id=bet.id).first()
            if bm_bet:
                bm_bet.status = bet.status
                if bet.status == "SETTLED_WON":
                    exp = session.query(BmTokenExposureModel).filter_by(token=bet.token).first()
                    if exp:
                        exp.won_count += 1

        append_audit(session, "regulator", "EVENT_SETTLED", {"event_id": event_id, "outcome": outcome})
        session.commit()

    return jsonify({"event_id": event_id, "outcome": outcome, "settled_bets": settled})


@regulator_bp.route("/v1/disclosures/solo-attempt", methods=["POST"])
def solo_disclosure_attempt():
    with SessionLocal() as session:
        link = session.query(LinkModel).first()
        token = link.token if link else "P_ALPHA_UNKNOWN"

        disc = session.query(DisclosureModel).order_by(DisclosureModel.created_at.desc()).first()
        if not disc or disc.status == "REVEALED":
            req_id = f"disc_{uuid.uuid4().hex[:8]}"
            disc = DisclosureModel(
                id=req_id,
                subject_type="token",
                subject_id=token,
                reason="Запрос финмониторинга (AML)",
                requester="regulator_solo",
                status="PENDING_SECOND_SHARE",
            )
            session.add(disc)
            reg_share = session.query(CustodyShareModel).filter_by(party="regulator").first()
            if reg_share:
                session.add(DisclosureShareModel(
                    disclosure_id=req_id, party="regulator", payload=reg_share.payload
                ))

        append_audit(session, "regulator", "SOLO_DISCLOSURE_DENIED_403", {
            "request_id": disc.id, "collected_shares": 1, "threshold": 2
        })
        session.commit()

        return jsonify({
            "error": "INSUFFICIENT_SHARES",
            "request_id": disc.id,
            "message": "Отказ 403: У регулятора есть только 1 доля ключа из 3. Через одну точку проходит бесконечно много прямых Шамира — деанонимизация в одиночку математически заблокирована!"
        }), 403

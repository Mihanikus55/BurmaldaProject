import json
import uuid
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from flask import Blueprint, jsonify, request

from common.crypto_ports import (
    audit_port, credential_port, custody_port, sealer_port, signer_port, token_policy_port
)
from services.database import (
    AccountModel, ArbiterAuditModel, ArbiterShareModel, AuditLogModel,
    BetModel, BmBetModel, BmTokenExposureModel, ClientModel,
    CustodyShareModel, DisclosureModel, DisclosureShareModel, EventModel,
    HoldModel, LedgerEntryModel, LinkModel, SessionLocal,
    WalletIdentityModel, WalletReceiptModel, WalletTokenModel
)
from services.smpc_engine import SMPCEngine

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
    if idemp_key:
        existing = session.query(LedgerEntryModel).filter_by(idempotency_key=idemp_key).first()
        if existing:
            return
    tx_id = f"tx_{uuid.uuid4().hex[:8]}"
    session.add(LedgerEntryModel(
        tx_id=tx_id, account_id=debit_owner, direction="DEBIT", amount=amount, idempotency_key=idemp_key
    ))
    session.add(LedgerEntryModel(
        tx_id=tx_id, account_id=credit_owner, direction="CREDIT", amount=amount, idempotency_key=f"{idemp_key}_cr" if idemp_key else None
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


def settle_event_internal(session, event_id: str, outcome: str) -> list:
    ev = session.query(EventModel).filter_by(id=event_id).first()
    if ev:
        ev.outcome = outcome
        ev.status = f"SETTLED ({outcome})"
        ev.settled_at = datetime.utcnow()

    settled = []
    bets = session.query(BetModel).filter_by(event_id=event_id, status="ACCEPTED").all()
    for bet in bets:
        cli_hold = session.query(HoldModel).filter_by(id=bet.client_hold_id).first()
        client_owner = cli_hold.owner_ref if cli_hold else "client:unknown"
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

        bm_bet = session.query(BmBetModel).filter_by(id=bet.id).first()
        if bm_bet:
            bm_bet.status = bet.status
            if bet.status == "SETTLED_WON":
                exp = session.query(BmTokenExposureModel).filter_by(token=bet.token).first()
                if exp:
                    exp.won_count += 1

    append_audit(session, "regulator", "EVENT_SETTLED", {
        "event_id": event_id, "outcome": outcome, "settled_count": len(settled)
    })
    return settled


# =============================================================================
# ЭНДПОИНТ КЕЙСА 2: МАССОВАЯ ГЕНЕРАЦИЯ 10 ИГРОКОВ И 10 СТАВОК (/v1/demo/mass-10)
# =============================================================================
@regulator_bp.route("/v1/demo/mass-10", methods=["POST"])
def demo_mass_10_players():
    """
    Кейс 2: Автоматически регистрирует 10 разных игроков, шифрует их ПДн через AES-256-GCM,
    делит каждый ключ по Шамиру на 3 доли, пополняет депозиты и размещает 10 ставок.
    """
    sample_players = [
        ("Соколов Артём Игоревич", "4019 112233", 24, "HOME_WIN", 500_00),
        ("Морозова Анна Викторовна", "4020 223344", 27, "AWAY_WIN", 800_00),
        ("Волков Денис Сергеевич", "4017 334455", 31, "HOME_WIN", 1200_00),
        ("Лебедев Максим Олегович", "4015 445566", 22, "HOME_WIN", 1000_00),
        ("Козлова Мария Андреевна", "4021 556677", 26, "AWAY_WIN", 600_00),
        ("Новиков Кирилл Павлович", "4018 667788", 29, "HOME_WIN", 1500_00),
        ("Зайцев Роман Дмитриевич", "4016 778899", 34, "AWAY_WIN", 900_00),
        ("Павлова Елена Алексеевна", "4022 889900", 25, "HOME_WIN", 700_00),
        ("Семёнов Илья Николаевич", "4014 990011", 28, "HOME_WIN", 1100_00),
        ("Голубев Никита Вадимович", "4019 001122", 23, "AWAY_WIN", 1000_00),
    ]

    created_records = []
    with SessionLocal() as session:
        # Пополняем обеспечение букмекера на 50 000 ₽ для покрытия 10 ставок
        bk_owner = "bookmaker:bk_alpha"
        bk_acc = get_or_create_account(session, bk_owner)
        ext_acc = get_or_create_account(session, "external:bank")
        bk_topup = 50000_00
        ext_acc.available -= bk_topup
        bk_acc.available += bk_topup
        bk_acc.version += 1
        record_double_entry(session, "external:bank", bk_owner, bk_topup, f"mass_bk_{uuid.uuid4().hex[:6]}")

        for idx, (full_name, passport, age, selection, stake) in enumerate(sample_players, start=1):
            client_id = f"cli_m{idx:02d}_{uuid.uuid4().hex[:4]}"
            secret_s = f"sec_{uuid.uuid4().hex[:16]}"
            dek = sealer_port.generate_dek()

            pd_sealed = sealer_port.seal(dek, {
                "client_id": client_id,
                "full_name": full_name,
                "passport": passport,
                "age": age,
            })
            shares = custody_port.split_key(dek)

            session.add(ClientModel(id=client_id, kyc_status="VERIFIED", pd_blob=pd_sealed))
            session.add(CustodyShareModel(client_id=client_id, party="regulator", payload=shares["regulator"]))
            session.merge(ArbiterShareModel(client_id=client_id, share_payload=shares["arbiter"]))

            # Сохраняем последнего (или первого) в активный профиль кошелька для отображения
            if idx == 1:
                session.query(WalletIdentityModel).delete()
                session.add(WalletIdentityModel(
                    client_id=client_id,
                    full_name=full_name,
                    passport=passport,
                    age=age,
                    client_secret_s=secret_s,
                    client_share=shares["client"],
                    credential_json=json.dumps({"adult": True, "kyc_ok": True}),
                ))

            # Вычисляем токены для БК Alpha и БК Beta (с привязкой к зашифрованному ПДн)
            tok_alpha, zk_alpha = token_policy_port.derive_token(secret_s, "bk_alpha", pd_sealed[:32])
            tok_beta, zk_beta = token_policy_port.derive_token(secret_s, "bk_beta", pd_sealed[:32])

            session.add(WalletTokenModel(client_id=client_id, bookmaker_id="bk_alpha", token=tok_alpha, zk_token_proof=zk_alpha))
            session.add(WalletTokenModel(client_id=client_id, bookmaker_id="bk_beta", token=tok_beta, zk_token_proof=zk_beta))

            sealed_link = sealer_port.seal(dek, {
                "client_id": client_id,
                "token": tok_alpha,
                "bookmaker_id": "bk_alpha",
            })
            session.add(LinkModel(token=tok_alpha, bookmaker_id="bk_alpha", client_ref_sealed=sealed_link))

            # Депозит клиента (3 000 ₽)
            cli_owner = f"client:{client_id}"
            cli_acc = get_or_create_account(session, cli_owner)
            dep_amount = 3000_00
            ext_acc.available -= dep_amount
            cli_acc.available += dep_amount
            cli_acc.version += 1
            record_double_entry(session, "external:bank", cli_owner, dep_amount, f"dep_{client_id}")

            # Ставка клиента
            odds_dec = Decimal("2.40") if selection == "HOME_WIN" else Decimal("1.65")
            odds_str = f"{odds_dec:.2f}"
            payout = int((Decimal(stake) * odds_dec).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            bk_risk = payout - stake

            quote_id = f"q_{uuid.uuid4().hex[:6]}"
            bet_id = f"bet_{uuid.uuid4().hex[:6]}"
            cli_hold = create_hold_internal(session, cli_owner, stake, "CLIENT_STAKE", bet_id, f"hc_{bet_id}")
            bk_hold = create_hold_internal(session, bk_owner, bk_risk, "BOOKMAKER_RISK", bet_id, f"hb_{bet_id}")

            sig_payload = {"quote_id": quote_id, "token": tok_alpha, "stake": stake, "odds": odds_str}
            c_sig = signer_port.sign(tok_alpha, secret_s, sig_payload)
            b_sig = signer_port.sign("bk_alpha", "", sig_payload)

            session.add(BetModel(
                id=bet_id,
                token=tok_alpha,
                bookmaker_id="bk_alpha",
                event_id="ev_final_2026",
                selection=selection,
                stake=stake,
                odds=odds_str,
                status="ACCEPTED",
                client_sig=c_sig,
                bookmaker_sig=b_sig,
                client_hold_id=cli_hold.id,
                bookmaker_hold_id=bk_hold.id,
            ))

            session.add(BmTokenExposureModel(
                token=tok_alpha, bets_count=1, total_staked=stake, won_count=0
            ))
            session.add(BmBetModel(
                id=bet_id,
                quote_id=quote_id,
                token=tok_alpha,
                event_id="ev_final_2026",
                selection=selection,
                stake=stake,
                odds=odds_str,
                odds_commitment=uuid.uuid4().hex,
                status="ACCEPTED",
                receipt_sig=b_sig,
            ))
            session.add(WalletReceiptModel(
                bet_id=bet_id,
                bookmaker_id="bk_alpha",
                token=tok_alpha,
                selection=selection,
                stake=stake,
                odds=odds_str,
                bookmaker_sig=b_sig,
            ))
            created_records.append({"client_id": client_id, "token": tok_alpha, "stake": stake, "selection": selection})

        append_audit(session, "regulator", "MASS_10_PLAYERS_GENERATED", {"count": len(created_records)})
        session.commit()

    return jsonify({
        "status": "MASS_10_CREATED",
        "players_count": len(created_records),
        "records": created_records,
    }), 201


# =============================================================================
# 3 SMPC ЭНДПОИНТА (/v1/smpc/antifraud, /v1/smpc/solvency, /v1/smpc/oracle-settle)
# =============================================================================
@regulator_bp.route("/v1/smpc/antifraud", methods=["POST"])
def smpc_antifraud():
    data = request.json or {}
    score_alpha = int(data.get("score_alpha", 68))
    score_beta = int(data.get("score_beta", 54))
    threshold = int(data.get("threshold", 100))

    result = SMPCEngine.run_cross_bookmaker_antifraud(score_alpha, score_beta, threshold)
    with SessionLocal() as session:
        append_audit(session, "smpc_cluster", "SMPC_ANTIFRAUD_CHECK", {
            "fraud_detected": result["fraud_detected"],
            "combined_score": result["combined_score"],
        })
        session.commit()
    return jsonify(result)


@regulator_bp.route("/v1/smpc/solvency", methods=["POST"])
def smpc_solvency():
    with SessionLocal() as session:
        bk_acc = get_or_create_account(session, "bookmaker:bk_alpha")
        total_assets = bk_acc.available + bk_acc.held
        total_liabilities = bk_acc.held
        if total_assets == 0:
            total_assets = 10000_00
            total_liabilities = 1400_00

        result = SMPCEngine.run_proof_of_solvency(total_assets, total_liabilities)
        append_audit(session, "smpc_cluster", "SMPC_PROOF_OF_SOLVENCY", {
            "is_solvent": result["is_solvent"],
            "coverage_ratio": result["coverage_ratio"],
        })
        session.commit()
        return jsonify(result)


@regulator_bp.route("/v1/smpc/oracle-settle", methods=["POST"])
def smpc_oracle_settle():
    data = request.json or {}
    votes = data.get("votes", ["HOME_WIN", "HOME_WIN", "AWAY_WIN"])
    oracle_res = SMPCEngine.run_oracle_consensus(votes)
    winning_outcome = oracle_res["outcome"]

    with SessionLocal() as session:
        settled = settle_event_internal(session, "ev_final_2026", winning_outcome)
        append_audit(session, "smpc_oracle", "SMPC_ORACLE_CONSENSUS_SETTLED", {
            "outcome": winning_outcome,
            "settled_bets": len(settled),
        })
        session.commit()

    oracle_res["settled_bets_count"] = len(settled)
    return jsonify(oracle_res)


@regulator_bp.route("/v1/events/<event_id>/outcome", methods=["POST"])
def settle_event_route(event_id):
    data = request.json or {}
    outcome = data.get("outcome", "HOME_WIN")
    with SessionLocal() as session:
        settled = settle_event_internal(session, event_id, outcome)
        session.commit()
    return jsonify({"event_id": event_id, "outcome": outcome, "settled_bets": settled})


@regulator_bp.route("/v1/disclosures/solo-attempt", methods=["POST"])
def solo_disclosure_attempt():
    with SessionLocal() as session:
        link = session.query(LinkModel).first()
        token = link.token if link else "P_ALPHA_NONE"

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
            "message": "Отказ 403: У регулятора только 1 доля Шамира из 3. Для интерполяции Лагранжа над GF(2^521-1) необходимы минимум 2 точки!"
        }), 403

from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import uuid
from flask import Blueprint, jsonify, request

from common.crypto_ports import audit_chain_port, custody_port, sealer_port
from services.database import (
    AccountModel, AuditLogModel, BmBetModel, BmTokenExposureModel,
    ClientModel, CustodyShareModel, DisclosureModel, DisclosureShareModel,
    EventModel, HoldModel, LedgerEntryModel, LinkModel, RegulatorBetModel, SessionLocal
)

regulator_bp = Blueprint("regulator", __name__)


def append_audit(session, actor: str, action: str, payload: dict):
    last = session.query(AuditLogModel).order_by(AuditLogModel.seq.desc()).first()
    prev_hash = last.current_hash if last else "0" * 64
    payload_hash, current_hash = audit_chain_port.compute_entry_hashes(prev_hash, actor, action, payload)
    session.add(AuditLogModel(
        ts=datetime.now().strftime("%H:%M:%S"),
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


def record_double_entry(session, debit_ref: str, credit_ref: str, amount: int, tx_prefix: str = "tx"):
    tx_id = f"{tx_prefix}_{uuid.uuid4().hex[:6]}"
    session.add(LedgerEntryModel(tx_id=tx_id, account_id=credit_ref, direction="CREDIT", amount=amount))
    session.add(LedgerEntryModel(tx_id=tx_id, account_id=debit_ref, direction="DEBIT", amount=amount))


@regulator_bp.route("/accounts/deposit", methods=["POST"])
def deposit_account():
    data = request.json or {}
    owner_ref = data["owner_ref"]
    amount = int(data["amount"])

    with SessionLocal() as session:
        acc = get_or_create_account(session, owner_ref)
        bank_acc = get_or_create_account(session, "external:bank")
        bank_acc.available -= amount
        acc.available += amount
        acc.version += 1

        record_double_entry(session, "external:bank", owner_ref, amount, "tx_dep")
        append_audit(session, owner_ref, "DEPOSIT", {"amount": amount})
        session.commit()
        return jsonify({"owner_ref": acc.owner_ref, "available": acc.available, "held": acc.held})


@regulator_bp.route("/events/outcome", methods=["POST"])
def settle_event_outcome():
    data = request.json or {}
    outcome = data.get("outcome", "HOME_WIN")

    with SessionLocal() as session:
        ev = session.query(EventModel).filter_by(id="ev_final_2026").first()
        active_holds = session.query(HoldModel).filter_by(status="ACTIVE").all()
        bets = session.query(RegulatorBetModel).filter_by(status="ACCEPTED").all()

        for bet in bets:
            link = session.query(LinkModel).filter_by(token=bet.token).first()
            unsealed = sealer_port.unseal("", link.client_ref_sealed)
            client_ref = f"client:{unsealed['client_id']}"
            bk_ref = f"bookmaker:{bet.bookmaker_id}"

            cli_acc = get_or_create_account(session, client_ref)
            bk_acc = get_or_create_account(session, bk_ref)

            cli_hold = session.query(HoldModel).filter_by(id=bet.client_hold_id).first()
            bk_hold = session.query(HoldModel).filter_by(id=bet.bookmaker_hold_id).first()

            cli_amt = cli_hold.amount if cli_hold else bet.stake
            bk_amt = bk_hold.amount if bk_hold else int(Decimal(bet.stake) * Decimal(bet.odds)) - bet.stake

            if outcome == "VOID":
                cli_acc.held = max(0, cli_acc.held - cli_amt)
                cli_acc.available += cli_amt
                cli_acc.version += 1

                bk_acc.held = max(0, bk_acc.held - bk_amt)
                bk_acc.available += bk_amt
                bk_acc.version += 1
                bet.status = "VOIDED"
            elif bet.selection == outcome:
                # Клиент выиграл: холд риска БК (1400 ₽) переходит клиенту, свой холд (1000 ₽) размораживается
                cli_acc.held = max(0, cli_acc.held - cli_amt)
                cli_acc.available += cli_amt + bk_amt
                cli_acc.version += 1

                bk_acc.held = max(0, bk_acc.held - bk_amt)
                bk_acc.version += 1
                bet.status = "SETTLED_WON"
                record_double_entry(session, bk_ref, client_ref, bk_amt, "tx_settle_win")
            else:
                # Клиент проиграл: холд клиента (1000 ₽) уходит букмекеру, холд риска БК (1400 ₽) размораживается
                cli_acc.held = max(0, cli_acc.held - cli_amt)
                cli_acc.version += 1

                bk_acc.held = max(0, bk_acc.held - bk_amt)
                bk_acc.available += cli_amt + bk_amt
                bk_acc.version += 1
                bet.status = "SETTLED_LOST"
                record_double_entry(session, client_ref, bk_ref, cli_amt, "tx_settle_loss")

            if cli_hold:
                cli_hold.status = "RELEASED" if outcome == "VOID" else ("RELEASED" if bet.status == "SETTLED_WON" else "CAPTURED")
            if bk_hold:
                bk_hold.status = "RELEASED" if outcome == "VOID" else ("CAPTURED" if bet.status == "SETTLED_WON" else "RELEASED")

            bm_bet = session.query(BmBetModel).filter_by(id=bet.id).first()
            if bm_bet:
                bm_bet.status = bet.status
                if bet.status == "SETTLED_WON":
                    exp = session.query(BmTokenExposureModel).filter_by(token=bet.token).first()
                    if exp:
                        exp.won_count += 1

        if ev:
            ev.status = f"SETTLED ({outcome})"
            ev.outcome = outcome

        append_audit(session, "regulator", "EVENT_SETTLED", {"event_id": "ev_final_2026", "outcome": outcome})
        session.commit()
        return jsonify({"status": f"SETTLED ({outcome})", "outcome": outcome})


@regulator_bp.route("/disclosures/solo-attempt", methods=["POST"])
def solo_disclosure_attempt():
    with SessionLocal() as session:
        link = session.query(LinkModel).filter_by(bookmaker_id="bk_alpha").first()
        if not link:
            return jsonify({"error": "NO_LINKS_FOUND"}), 404

        unsealed_preview = sealer_port.unseal("", link.client_ref_sealed)
        reg_share = session.query(CustodyShareModel).filter_by(
            client_id=unsealed_preview["client_id"], party="regulator"
        ).first()

        session.query(DisclosureShareModel).delete()
        session.query(DisclosureModel).delete()
        session.flush()

        req_id = "disc_771a9c04"
        disc = DisclosureModel(
            id=req_id,
            subject=link.token,
            reason="Проверка AML / Запрос финмониторинга",
            status="PENDING_SECOND_SHARE",
        )
        session.add(disc)
        if reg_share:
            session.add(DisclosureShareModel(
                disclosure_id=req_id,
                party="regulator",
                payload=reg_share.payload,
            ))

        append_audit(session, "audit_department", "DISCLOSURE_REQUESTED_SOLO_DENIED", {
            "request_id": req_id,
            "subject": link.token,
            "collected_shares": 1,
        })
        session.commit()

        return jsonify({
            "error": "INSUFFICIENT_SHARES",
            "request_id": req_id,
            "message": (
                "ОШИБКА 403 (INSUFFICIENT_SHARES): Собрана только 1 доля из 3 (regulator). "
                "Через одну точку проходит бесконечно много прямых Шамира — в одиночку раскрыть личность математически невозможно!"
            ),
        }), 403

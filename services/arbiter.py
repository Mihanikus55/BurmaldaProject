from datetime import datetime
from flask import Blueprint, jsonify, request

from services.database import (
    ArbiterAuditModel, ArbiterShareModel, DisclosureModel, DisclosureShareModel, SessionLocal
)
from services.regulator import append_audit

arbiter_bp = Blueprint("arbiter", __name__)


@arbiter_bp.route("/disclosures/approve", methods=["POST"])
def arbiter_approve_disclosure():
    data = request.json or {}
    reason = data.get("reason", "Судебный ордер №42 (Проверка AML)")

    with SessionLocal() as session:
        disc = session.query(DisclosureModel).first()
        arb_share = session.query(ArbiterShareModel).first()
        if not disc or not arb_share:
            return jsonify({"error": "DISCLOSURE_OR_SHARE_NOT_FOUND"}), 404

        existing = session.query(DisclosureShareModel).filter_by(
            disclosure_id=disc.id, party="arbiter"
        ).first()
        if not existing:
            session.add(DisclosureShareModel(
                disclosure_id=disc.id, party="arbiter", payload=arb_share.share_payload
            ))
        disc.status = "REVEALED"
        disc.reason = reason

        session.add(ArbiterAuditModel(
            ts=datetime.now().strftime("%H:%M:%S"),
            action="DISCLOSURE_APPROVED",
            details=f"{disc.id} одобрен ({reason})",
        ))
        append_audit(session, "arbiter", "DISCLOSURE_THRESHOLD_REVEALED", {
            "request_id": disc.id, "parties": ["regulator", "arbiter"], "reason": reason
        })
        session.commit()
        return jsonify({"status": "REVEALED", "request_id": disc.id})


@arbiter_bp.route("/disclosures/deny", methods=["POST"])
def arbiter_deny_disclosure():
    data = request.json or {}
    reason = data.get("reason", "Отсутствует судебное основание")

    with SessionLocal() as session:
        session.add(ArbiterAuditModel(
            ts=datetime.now().strftime("%H:%M:%S"),
            action="DISCLOSURE_DENIED",
            details=f"Отказ в выдаче доли #3 ({reason})",
        ))
        session.commit()
        return jsonify({"status": "DENIED"})

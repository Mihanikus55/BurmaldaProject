import uuid
from flask import Blueprint, jsonify, request

from services.database import (
    ArbiterAuditModel, ArbiterShareModel, CustodyShareModel,
    DisclosureModel, DisclosureShareModel, LinkModel, SessionLocal
)
from services.regulator import append_audit

arbiter_bp = Blueprint("arbiter", __name__)


@arbiter_bp.route("/v1/disclosures/approve", methods=["POST"])
def approve_disclosure():
    data = request.json or {}
    reason = data.get("reason", "Судебный ордер №42 (Законная проверка)")

    with SessionLocal() as session:
        arb_share = session.query(ArbiterShareModel).first()
        if not arb_share:
            return jsonify({"error": "Сначала зарегистрируйте клиента (Шаг 1)"}), 400

        disc = session.query(DisclosureModel).order_by(DisclosureModel.created_at.desc()).first()
        if not disc:
            link = session.query(LinkModel).first()
            req_id = f"disc_{uuid.uuid4().hex[:8]}"
            disc = DisclosureModel(
                id=req_id,
                subject_type="token",
                subject_id=link.token if link else "P_ALPHA",
                reason=reason,
                requester="court_order",
                status="PENDING",
            )
            session.add(disc)
            session.flush()
            reg_share = session.query(CustodyShareModel).filter_by(party="regulator").first()
            if reg_share:
                session.add(DisclosureShareModel(
                    disclosure_id=disc.id, party="regulator", payload=reg_share.payload
                ))

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
            action="DISCLOSURE_APPROVED",
            details=f"Запрос {disc.id} одобрен по основанию: {reason} (передана доля #3)"
        ))
        append_audit(session, "arbiter", "DISCLOSURE_THRESHOLD_2_OF_3_REVEALED", {
            "request_id": disc.id,
            "parties": ["regulator", "arbiter"],
            "reason": reason,
        })
        session.commit()

        return jsonify({"request_id": disc.id, "status": "REVEALED", "reason": reason})

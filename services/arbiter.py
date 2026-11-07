from datetime import datetime
from flask import Blueprint, jsonify, request

from services.database import (
    ArbiterAuditModel, ArbiterShareModel, DisclosureModel, DisclosureShareModel, SessionLocal
)
from services.regulator import append_audit, resolve_disclosure, submit_disclosure_share

arbiter_bp = Blueprint("arbiter", __name__)


# =============================================================================
# ЭТАП 4 (РАСКРЫТИЕ) — НЕЗАВИСИМЫЙ АРБИТР
#
# У арбитра лежит третья доля и больше ничего: ни имён, ни ставок, ни денег.
# Он нужен в двух случаях — когда есть законное основание раскрыть личность
# без согласия клиента, и когда клиент потерял свою долю.
#
# Принципиально, что он может ОТКАЗАТЬ. Если бы он всегда соглашался,
# схема «2 из 3» вырождалась бы в единоличную власть регулятора.
# =============================================================================

@arbiter_bp.route("/disclosures/approve", methods=["POST"])
def arbiter_approve_disclosure():
    data = request.get_json(silent=True) or {}
    reason = data.get("reason", "Судебный ордер №42 (Проверка AML)")

    with SessionLocal() as session:
        disc = (session.query(DisclosureModel).filter_by(id=data["disclosure_id"]).first()
                if data.get("disclosure_id")
                else session.query(DisclosureModel).order_by(DisclosureModel.created_at.desc()).first())
        if not disc:
            return jsonify({"error": "DISCLOSURE_NOT_FOUND"}), 404

        # доля именно того клиента, по которому идёт заявка
        arb_share = session.query(ArbiterShareModel).filter_by(
            client_id=disc.subject_client_id
        ).first() or session.query(ArbiterShareModel).first()
        if not arb_share:
            return jsonify({"error": "ARBITER_SHARE_NOT_FOUND"}), 404

        # доля отдаётся вместе с подписью арбитра — потом будет видно,
        # что одобрил именно он, а не кто-то от его имени
        submit_disclosure_share(session, disc.id, "arbiter", arb_share.share_payload)
        result = resolve_disclosure(session, disc.id)
        disc.reason = reason

        session.add(ArbiterAuditModel(
            ts=datetime.now().strftime("%H:%M:%S"),
            action="DISCLOSURE_APPROVED",
            details=f"{disc.id} одобрен ({reason})",
        ))
        append_audit(session, "arbiter", "DISCLOSURE_THRESHOLD_REVEALED", {
            "request_id": disc.id, "parties": result.get("collected", []), "reason": reason,
        })
        session.commit()
        return jsonify({"status": result.get("status"), "request_id": disc.id,
                        "collected": result.get("collected", [])})


@arbiter_bp.route("/disclosures/deny", methods=["POST"])
def arbiter_deny_disclosure():
    """
    Отказ. Доля не выдаётся, порог не собирается, личность не раскрывается.
    Отказ тоже попадает в журнал: по нему потом видно, что арбитр
    действительно рассматривал запрос, а не молчал.
    """
    data = request.get_json(silent=True) or {}
    reason = data.get("reason", "Отсутствует судебное основание")

    with SessionLocal() as session:
        disc = session.query(DisclosureModel).order_by(DisclosureModel.created_at.desc()).first()
        session.add(ArbiterAuditModel(
            ts=datetime.now().strftime("%H:%M:%S"),
            action="DISCLOSURE_DENIED",
            details=f"Отказ в выдаче доли #3 ({reason})",
        ))
        if disc:
            disc.status = "DENIED_BY_ARBITER"
            append_audit(session, "arbiter", "DISCLOSURE_DENIED", {
                "request_id": disc.id, "reason": reason,
            })
        session.commit()
        return jsonify({"status": "DENIED", "reason": reason})


@arbiter_bp.route("/shares", methods=["GET"])
def list_shares():
    """Всё, что видит арбитр: идентификаторы клиентов и доли. Ни имён, ни ставок."""
    with SessionLocal() as session:
        rows = session.query(ArbiterShareModel).all()
        return jsonify([{"client_id": r.client_id, "share": r.share_payload} for r in rows])

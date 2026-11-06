from decimal import Decimal
import uuid
from flask import Blueprint, jsonify, request

from services.database import SessionLocal
from services.regulator import append_audit, get_or_create_account, record_double_entry

bookmaker_bp = Blueprint("bookmaker", __name__)


@bookmaker_bp.route("/liquidity/top-up", methods=["POST"])
def top_up_liquidity():
    data = request.json or {}
    amount = int(data.get("amount", 10000_00))

    with SessionLocal() as session:
        bk_acc = get_or_create_account(session, "bookmaker:bk_alpha")
        bank_acc = get_or_create_account(session, "external:bank")
        bank_acc.available -= amount
        bk_acc.available += amount
        bk_acc.version += 1

        record_double_entry(session, "external:bank", "bookmaker:bk_alpha", amount, "tx_bk_topup")
        append_audit(session, "bookmaker:bk_alpha", "LIQUIDITY_TOP_UP", {"amount": amount})
        session.commit()
        return jsonify({
            "owner_ref": bk_acc.owner_ref,
            "available": bk_acc.available,
            "held": bk_acc.held,
        })

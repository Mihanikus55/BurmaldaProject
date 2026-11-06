import hashlib
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from flask import Blueprint, jsonify, request

from common.crypto_ports import credential_port, signer_port, token_policy_port
from services.database import (
    BmBetModel, BmQuoteModel, BmTokenExposureModel, SessionLocal
)
from services.regulator import (
    append_audit, create_hold_internal, get_or_create_account, sealer_port
)
from services.database import BetModel, LinkModel

bookmaker_bp = Blueprint("bookmaker", __name__)
BOOKMAKER_ID = "bk_alpha"


@bookmaker_bp.route("/v1/quotes", methods=["POST"])
def create_quote():
    data = request.json or {}
    token = data["token"]
    event_id = data.get("event_id", "ev_final_2026")
    selection = data.get("selection", "HOME_WIN")
    stake = int(data.get("stake", 1000_00))
    zk_proof = data.get("zk_token_proof", f"schnorr_zk:{token}:R=0x00")

    if not token_policy_port.verify_token_proof(token, BOOKMAKER_ID, zk_proof):
        return jsonify({"error": "INVALID_TOKEN_ZK_PROOF"}), 400

    base_odds = Decimal("2.40") if selection == "HOME_WIN" else Decimal("1.65")
    with SessionLocal() as session:
        exp = session.query(BmTokenExposureModel).filter_by(token=token).first()
        if exp and exp.won_count >= 3:
            base_odds = max(Decimal("1.10"), base_odds - Decimal("0.10"))
        odds_str = f"{base_odds:.2f}"

        quote_id = f"q_{uuid.uuid4().hex[:8]}"
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        commitment = hashlib.sha256(f"{quote_id}:{token}:{odds_str}:{stake}".encode("utf-8")).hexdigest()

        session.add(BmQuoteModel(
            id=quote_id,
            token=token,
            event_id=event_id,
            selection=selection,
            stake=stake,
            odds=odds_str,
            odds_commitment=commitment,
            expires_at=expires_at,
        ))
        session.commit()

        return jsonify({
            "quote_id": quote_id,
            "token": token,
            "odds": odds_str,
            "odds_commitment": commitment,
            "expires_at": expires_at.isoformat(),
        }), 201

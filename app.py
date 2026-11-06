from flask import Flask, jsonify, render_template

from common.crypto_ports import custody_port, sealer_port
from services.arbiter import arbiter_bp
from services.bookmaker import bookmaker_bp
from services.client_wallet import client_bp
from services.database import (
    AccountModel, ArbiterAuditModel, ArbiterShareModel, AuditLogModel,
    BmBetModel, BmTokenExposureModel, ClientModel, CustodyShareModel,
    DisclosureModel, DisclosureShareModel, EventModel, HoldModel,
    LedgerEntryModel, LinkModel, SessionLocal, WalletReceiptModel,
    WalletStateModel, init_db
)
from services.regulator import regulator_bp

app = Flask(__name__, template_folder="templates", static_folder="static")

# Регистрация 4 независимых сервисов как Flask Blueprints на едином порту :5000
app.register_blueprint(regulator_bp, url_prefix="/api/regulator")
app.register_blueprint(bookmaker_bp, url_prefix="/api/bookmaker")
app.register_blueprint(client_bp, url_prefix="/api/client")
app.register_blueprint(arbiter_bp, url_prefix="/api/arbiter")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/reset", methods=["POST"])
def api_reset():
    init_db(reset=True)
    return jsonify({"reset": True})


@app.route("/api/state", methods=["GET"])
def api_get_full_state():
    """Возвращает синхронизированный слемок состояния всех 4 сервисов и SQL-таблиц для дашборда."""
    with SessionLocal() as session:
        w = session.query(WalletStateModel).first()
        receipts = session.query(WalletReceiptModel).order_by(WalletReceiptModel.created_at.desc()).all()

        client_ref = f"client:{w.client_id}" if w else "client:unregistered"
        cli_acc = session.query(AccountModel).filter_by(owner_ref=client_ref).first()
        bk_acc = session.query(AccountModel).filter_by(owner_ref="bookmaker:bk_alpha").first()
        house_acc = session.query(AccountModel).filter_by(owner_ref="house:fees").first()

        reg_share_rec = session.query(CustodyShareModel).filter_by(party="regulator").first()
        links = session.query(LinkModel).all()
        holds = session.query(HoldModel).filter_by(status="ACTIVE").all()
        ledger = session.query(LedgerEntryModel).order_by(LedgerEntryModel.id.desc()).limit(12).all()
        ev = session.query(EventModel).filter_by(id="ev_final_2026").first()
        audit_logs = session.query(AuditLogModel).order_by(AuditLogModel.seq.desc()).all()

        exposures = session.query(BmTokenExposureModel).all()
        bm_bets = session.query(BmBetModel).order_by(BmBetModel.id.desc()).all()

        arb_share_rec = session.query(ArbiterShareModel).first()
        arb_audit = session.query(ArbiterAuditModel).order_by(ArbiterAuditModel.id.desc()).all()

        disc = session.query(DisclosureModel).first()
        disc_payload = None
        if disc:
            disc_shares = session.query(DisclosureShareModel).filter_by(disclosure_id=disc.id).all()
            collected_parties = [s.party for s in disc_shares]
            revealed_identity = None
            if len(disc_shares) >= 2:
                share_map = {s.party: s.payload for s in disc_shares}
                recovered_dek = custody_port.combine_shares(share_map)
                cli_rec = session.query(ClientModel).first()
                if cli_rec and recovered_dek:
                    revealed_identity = sealer_port.unseal(recovered_dek, cli_rec.pd_blob)
            disc_payload = {
                "id": disc.id,
                "subject": disc.subject,
                "reason": disc.reason,
                "status": disc.status,
                "collected": collected_parties,
                "revealedIdentity": revealed_identity,
            }

        audit_root = audit_logs[0].current_hash if audit_logs else "0" * 64

        return jsonify({
            "wallet": {
                "registered": bool(w),
                "clientId": w.client_id if w else "",
                "fullName": w.full_name if w else "",
                "passport": w.passport if w else "",
                "age": w.age if w else 23,
                "clientSecret": w.client_secret_s if w else "",
                "clientShare": w.client_share if w else "",
                "credentialId": w.credential_id if w else "",
                "tokens": {
                    "bk_alpha": w.token_alpha if w else "",
                    "bk_beta": w.token_beta if w else "",
                },
                "zkProofs": {
                    "bk_alpha": w.zk_alpha if w else "",
                    "zk_beta": w.zk_beta if w else "",
                },
                "receipts": [{
                    "bet_id": r.bet_id,
                    "token": r.token,
                    "selection": r.selection,
                    "stake": r.stake,
                    "odds": r.odds,
                    "bookmaker_sig": r.bookmaker_sig,
                } for r in receipts],
            },
            "accounts": {
                "client": {
                    "owner_ref": cli_acc.owner_ref if cli_acc else client_ref,
                    "available": cli_acc.available if cli_acc else 0,
                    "held": cli_acc.held if cli_acc else 0,
                    "version": cli_acc.version if cli_acc else 1,
                },
                "bookmaker": {
                    "owner_ref": "bookmaker:bk_alpha",
                    "available": bk_acc.available if bk_acc else 0,
                    "held": bk_acc.held if bk_acc else 0,
                    "version": bk_acc.version if bk_acc else 1,
                },
                "house": {
                    "owner_ref": "house:fees",
                    "available": house_acc.available if house_acc else 0,
                    "held": house_acc.held if house_acc else 0,
                    "version": house_acc.version if house_acc else 1,
                },
            },
            "regulator": {
                "regulatorShare": reg_share_rec.payload if reg_share_rec else "",
                "links": [{
                    "token": lk.token,
                    "bookmaker_id": lk.bookmaker_id,
                    "client_ref_sealed": lk.client_ref_sealed,
                } for lk in links],
                "holds": [{
                    "id": h.id,
                    "owner": h.owner_ref,
                    "amount": h.amount,
                    "status": h.status,
                    "type": h.hold_type,
                } for h in holds],
                "ledger": [{
                    "tx_id": le.tx_id,
                    "account_id": le.account_id,
                    "direction": le.direction,
                    "amount": le.amount,
                } for le in ledger],
                "eventStatus": ev.status if ev else "OPEN",
                "lastOutcome": ev.outcome if ev else None,
                "auditLogs": [{
                    "seq": al.seq,
                    "ts": al.ts,
                    "actor": al.actor,
                    "action": al.action,
                    "payload_hash": al.payload_hash,
                    "prev_hash": al.prev_hash,
                    "current_hash": al.current_hash,
                } for al in audit_logs],
                "auditRoot": audit_root,
            },
            "bookmaker": {
                "exposures": [{
                    "token": ex.token,
                    "bets_count": ex.bets_count,
                    "total_staked": ex.total_staked,
                    "won_count": ex.won_count,
                } for ex in exposures],
                "bets": [{
                    "id": b.id,
                    "quote_id": b.quote_id,
                    "token": b.token,
                    "selection": b.selection,
                    "stake": b.stake,
                    "odds": b.odds,
                    "odds_commitment": b.odds_commitment,
                    "status": b.status,
                } for b in bm_bets],
            },
            "arbiter": {
                "clientId": arb_share_rec.client_id if arb_share_rec else "",
                "storedShare": arb_share_rec.share_payload if arb_share_rec else "",
                "audit": [{
                    "ts": aa.ts,
                    "action": aa.action,
                    "details": aa.details,
                } for aa in arb_audit],
            },
            "disclosure": disc_payload,
        })


if __name__ == "__main__":
    init_db(reset=True)
    print("=" * 72)
    print("Платформа «Приватные Ставки & Эскроу» запущена на едином порту!")
    print("Откройте в браузере: http://127.0.0.1:5000")
    print("=" * 72)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)

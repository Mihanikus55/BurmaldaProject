import json
from flask import Flask, jsonify, render_template, request

from common.crypto_ports import custody_port, sealer_port
from services.arbiter import arbiter_bp
from services.bookmaker import bookmaker_bp
from services.client_wallet import client_bp
from services.database import (
    AccountModel, ArbiterAuditModel, ArbiterShareModel, AuditLogModel,
    BetModel, BmBetModel, BmTokenExposureModel, ClientModel, CustodyShareModel,
    DisclosureModel, DisclosureShareModel, EventModel, HoldModel,
    LedgerEntryModel, LinkModel, SessionLocal, WalletIdentityModel,
    WalletReceiptModel, WalletTokenModel, init_db, reset_db
)
from services.regulator import append_audit, get_or_create_account, record_double_entry, regulator_bp

app = Flask(__name__, template_folder="templates", static_folder="static")

# Регистрация независимых сервисов как Flask Blueprints на едином порту :5000
app.register_blueprint(regulator_bp, url_prefix="/api/regulator")
app.register_blueprint(bookmaker_bp, url_prefix="/api/bookmaker")
app.register_blueprint(client_bp, url_prefix="/api/client")
app.register_blueprint(arbiter_bp, url_prefix="/api/arbiter")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/demo/deposit-both", methods=["POST"])
def demo_deposit_both():
    """Шаг 2: Пополнение баланса клиента (3 000 ₽) и ликвидности букмекера (10 000 ₽)."""
    with SessionLocal() as session:
        ident = session.query(WalletIdentityModel).first()
        if not ident:
            return jsonify({"error": "Сначала выполните Шаг 1 (Регистрация)"}), 400

        cli_owner = f"client:{ident.client_id}"
        bk_owner = "bookmaker:bk_alpha"

        cli_acc = get_or_create_account(session, cli_owner)
        bk_acc = get_or_create_account(session, bk_owner)
        ext_acc = get_or_create_account(session, "external:bank")

        cli_amount = 3000_00
        bk_amount = 10000_00

        ext_acc.available -= (cli_amount + bk_amount)
        cli_acc.available += cli_amount
        cli_acc.version += 1
        bk_acc.available += bk_amount
        bk_acc.version += 1

        record_double_entry(session, "external:bank", cli_owner, cli_amount, "dep_cli_step2")
        record_double_entry(session, "external:bank", bk_owner, bk_amount, "dep_bk_step2")

        append_audit(session, "regulator", "DEPOSIT_AND_LIQUIDITY_FUNDED", {
            "client_deposit": cli_amount,
            "bookmaker_liquidity": bk_amount,
        })
        session.commit()

        return jsonify({
            "client_available": cli_acc.available,
            "bk_available": bk_acc.available,
        })


@app.route("/api/demo/reset", methods=["POST"])
def demo_reset():
    reset_db()
    return jsonify({"status": "RESET_OK"})


@app.route("/api/state", methods=["GET"])
def get_full_state():
    """Агрегированный срез состояния всех 4 микросервисов и таблиц SQLite для UI и Инспектора."""
    with SessionLocal() as session:
        ident = session.query(WalletIdentityModel).first()
        tokens = {t.bookmaker_id: {"token": t.token, "zk_proof": t.zk_token_proof}
                  for t in session.query(WalletTokenModel).all()}
        receipts = [{
            "bet_id": r.bet_id,
            "token": r.token,
            "selection": r.selection,
            "stake": r.stake,
            "odds": r.odds,
            "bookmaker_sig": r.bookmaker_sig,
        } for r in session.query(WalletReceiptModel).order_by(WalletReceiptModel.created_at.desc()).all()]

        client_owner = f"client:{ident.client_id}" if ident else "client:unregistered"
        cli_acc = session.query(AccountModel).filter_by(owner_ref=client_owner).first()
        bk_acc = session.query(AccountModel).filter_by(owner_ref="bookmaker:bk_alpha").first()
        house_acc = session.query(AccountModel).filter_by(owner_ref="house:fees").first()

        reg_share_rec = session.query(CustodyShareModel).filter_by(party="regulator").first()
        arb_share_rec = session.query(ArbiterShareModel).first()

        links_list = [{
            "token": l.token,
            "bookmaker_id": l.bookmaker_id,
            "client_ref_sealed": l.client_ref_sealed,
        } for l in session.query(LinkModel).all()]

        holds_list = [{
            "id": h.id,
            "owner_ref": h.owner_ref,
            "amount": h.amount,
            "status": h.status,
            "ref_type": h.ref_type,
        } for h in session.query(HoldModel).filter_by(status="ACTIVE").all()]

        all_holds_dump = [{
            "id": h.id,
            "owner_ref": h.owner_ref,
            "amount": h.amount,
            "status": h.status,
            "ref_type": h.ref_type,
        } for h in session.query(HoldModel).all()]

        ledger_list = [{
            "tx_id": e.tx_id,
            "account_id": e.account_id,
            "direction": e.direction,
            "amount": e.amount,
        } for e in session.query(LedgerEntryModel).order_by(LedgerEntryModel.id.desc()).limit(15).all()]

        exposures_list = [{
            "token": x.token,
            "bets_count": x.bets_count,
            "total_staked": x.total_staked,
            "won_count": x.won_count,
        } for x in session.query(BmTokenExposureModel).all()]

        bm_bets_list = [{
            "id": b.id,
            "quote_id": b.quote_id,
            "token": b.token,
            "selection": b.selection,
            "stake": b.stake,
            "odds": b.odds,
            "odds_commitment": b.odds_commitment,
            "status": b.status,
        } for b in session.query(BmBetModel).order_by(BmBetModel.id.desc()).all()]

        ev = session.query(EventModel).filter_by(id="ev_final_2026").first()

        disc = session.query(DisclosureModel).order_by(DisclosureModel.created_at.desc()).first()
        disc_data = None
        if disc:
            d_shares = session.query(DisclosureShareModel).filter_by(disclosure_id=disc.id).all()
            collected_parties = [s.party for s in d_shares]
            revealed_person = None
            if len(d_shares) >= 2:
                share_map = {s.party: s.payload for s in d_shares}
                recovered_dek = custody_port.combine_shares(share_map)
                cli_rec = session.query(ClientModel).first()
                if cli_rec and recovered_dek:
                    revealed_person = sealer_port.unseal(recovered_dek, cli_rec.pd_blob)
            disc_data = {
                "id": disc.id,
                "subject": disc.subject_id,
                "reason": disc.reason,
                "status": disc.status,
                "collected": collected_parties,
                "revealed_identity": revealed_person,
            }

        audit_logs = [{
            "seq": a.seq,
            "ts": a.ts.strftime("%H:%M:%S"),
            "actor": a.actor,
            "action": a.action,
            "payload_hash": a.payload_hash,
            "prev_hash": a.prev_hash,
            "current_hash": a.current_hash,
        } for a in session.query(AuditLogModel).order_by(AuditLogModel.seq.desc()).all()]

        arb_audit = [{
            "ts": a.ts.strftime("%H:%M:%S"),
            "action": a.action,
            "details": a.details,
        } for a in session.query(ArbiterAuditModel).order_by(ArbiterAuditModel.id.desc()).all()]

        return jsonify({
            "wallet": {
                "registered": bool(ident),
                "client_id": ident.client_id if ident else "",
                "full_name": ident.full_name if ident else "",
                "passport": ident.passport if ident else "",
                "age": ident.age if ident else 23,
                "client_secret": ident.client_secret_s if ident else "",
                "client_share": ident.client_share if ident else "",
                "tokens": {
                    "bk_alpha": tokens.get("bk_alpha", {}).get("token", ""),
                    "bk_beta": tokens.get("bk_beta", {}).get("token", ""),
                },
                "zk_proofs": {
                    "bk_alpha": tokens.get("bk_alpha", {}).get("zk_proof", ""),
                    "bk_beta": tokens.get("bk_beta", {}).get("zk_proof", ""),
                },
                "receipts": receipts,
            },
            "accounts": {
                "client": {
                    "owner_ref": client_owner,
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
                "regulator_share": reg_share_rec.payload if reg_share_rec else "",
                "links": links_list,
                "active_holds": holds_list,
                "all_holds": all_holds_dump,
                "ledger": ledger_list,
                "event_status": ev.status if ev else "OPEN",
                "last_outcome": ev.outcome if ev else None,
                "audit_logs": audit_logs,
                "audit_root": audit_logs[0]["current_hash"] if audit_logs else "0" * 64,
            },
            "bookmaker": {
                "exposures": exposures_list,
                "bets": bm_bets_list,
            },
            "arbiter": {
                "client_id": arb_share_rec.client_id if arb_share_rec else "",
                "stored_share": arb_share_rec.share_payload if arb_share_rec else "",
                "audit": arb_audit,
            },
            "disclosure": disc_data,
        })


if __name__ == "__main__":
    init_db()
    print("=" * 72)
    print(" Платформа «Приватные букмекерские ставки» успешно запущена!")
    print(" Откройте в браузере: http://127.0.0.1:5000")
    print("=" * 72)
    app.run(host="127.0.0.1", port=5000, debug=False)

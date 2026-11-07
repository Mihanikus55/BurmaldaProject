from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import json
import uuid
from flask import Blueprint, jsonify, request

from common.crypto_ports import (
    audit_chain_port, cred_service_port, custody_port, operational_link_key,
    outcome_oracle_port, sealer_port, signer_port, token_policy_port
)
from services.database import (
    AccountModel, AuditAnchorModel, AuditLogModel, BmBetModel, BmQuoteModel,
    BmTokenExposureModel, ClientModel, CustodyShareModel, DisclosureModel,
    DisclosureShareModel, EventModel, HoldModel, LedgerEntryModel, LinkModel,
    RegulatorBetModel, SessionLocal, SettlementModel
)

regulator_bp = Blueprint("regulator", __name__)

# =============================================================================
# ЭТАП 1 (РЕГИСТРАЦИЯ) — СТОРОНА РЕГУЛЯТОРА
#
# Регулятор делает всё: проверяет документы, генерирует токены и пары
# ключей для клиента, шифрует архив и режет ключ от него на три доли.
# Клиенту уходят токены, приватные ключи, справки и одна доля.
# =============================================================================
BOOKMAKERS = ("bk_alpha", "bk_beta")


def append_audit(session, actor: str, action: str, payload: dict):
    last = session.query(AuditLogModel).order_by(AuditLogModel.seq.desc()).first()
    prev_hash = last.current_hash if last else "0" * 64
    payload_hash, current_hash = audit_chain_port.compute_entry_hashes(prev_hash, actor, action, payload)
    session.add(AuditLogModel(
        ts=datetime.now().strftime("%H:%M:%S"),
        actor=actor,
        action=action,
        # ЭТАП 3: payload сохраняется целиком, иначе цепочку можно проверить
        # только на связность, но не на подмену содержимого записи.
        payload_json=json.dumps(payload, sort_keys=True, ensure_ascii=False),
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



def register_client_at_regulator(session, client_id: str, full_name: str,
                                 passport: str, age: int) -> dict:
    """Выполняет регистрацию и возвращает то, что уходит клиенту и арбитру."""

    # --- токены и пары ключей подписи, по одной на контору ----------------
    issued, public_keys, private_keys, credentials = {}, {}, {}, {}
    for book in BOOKMAKERS:
        pair = token_policy_port.issue(client_id, book)
        issued[book] = pair["token"]
        public_keys[book] = pair["public_key"]
        private_keys[book] = pair["private_key"]

    # --- архив персональных данных (AES-256-GCM) --------------------------
    vault_key = sealer_port.generate_dek()
    pd_sealed = sealer_port.seal(vault_key, {
        "client_id": client_id,
        "full_name": full_name,
        "passport": passport,
        "age": age,
    })

    # --- ключ архива режется по Шамиру «2 из 3» ---------------------------
    shares = custody_port.split_key(vault_key)
    vault_key = None          # целого ключа больше нет ни у кого

    # --- справки допуска: по одной на контору -----------------------------
    for book in BOOKMAKERS:
        credentials[book] = cred_service_port.issue_credential(client_id, book, {
            "token": issued[book],
            "public_key": public_keys[book],
            "adult": age >= 18,
            "kyc_ok": True,
            "not_excluded": True,
            "limits_ok": True,
        })

    # --- записи контура регулятора ----------------------------------------
    session.add(ClientModel(
        id=client_id, kyc_status="VERIFIED", pd_blob=pd_sealed,
        book_public_keys=json.dumps(public_keys, ensure_ascii=False),
        adult=age >= 18, not_excluded=True, limits_ok=True,
    ))
    session.add(CustodyShareModel(client_id=client_id, party="regulator", payload=shares["regulator"]))
    get_or_create_account(session, f"client:{client_id}")

    for book in BOOKMAKERS:
        link_token_at_regulator(session, client_id, issued[book], book)

    append_audit(session, "regulator", "CLIENT_REGISTERED", {"client_id": client_id})
    append_audit(session, "regulator", "TOKENS_ISSUED", {"client_id": client_id, "count": len(issued)})
    append_audit(session, "regulator", "PD_SEALED_AES_GCM", {"client_id": client_id})
    append_audit(session, "regulator", "SHAMIR_KEY_SPLIT_2_OF_3", {"client_id": client_id, "parties": 3})
    append_audit(session, "regulator", "CREDENTIALS_ISSUED", {"count": len(credentials)})

    return {
        "tokens": issued,
        "private_keys": private_keys,
        "credentials": credentials,
        "shares": shares,
    }


def link_token_at_regulator(session, client_id: str, token: str, bookmaker_id: str):
    """
    Кладёт в таблицу links соответствие «токен -> client_id».

    Шифруется ОПЕРАЦИОННЫМ ключом регулятора, а не разрезанным по Шамиру:
    при расчёте ставки регулятору нужно понять, с чьего счёта списывать
    деньги, и спрашивать для этого доли у клиента и арбитра невозможно.
    Защищает от выгрузки базы, но не от самого регулятора — так и задумано.
    """
    sealed_ref = sealer_port.seal(operational_link_key(), {"client_id": client_id})
    session.add(LinkModel(token=token, bookmaker_id=bookmaker_id, client_ref_sealed=sealed_ref))
    append_audit(session, "regulator", "TOKEN_LINKED", {"token": token, "bookmaker_id": bookmaker_id})


# =============================================================================
# ЭТАП 2 (СТАВКА) — СТОРОНА РЕГУЛЯТОРА
#
# Допуск букмекер проверяет САМ, по подписанной справке, не обращаясь сюда.
# Этот эндпоинт нужен только для отзыва: справка живёт сутки, и если
# клиент за это время попал в реестр самоограничения, букмекер может
# свериться со свежим статусом.
# =============================================================================
def token_status_at_regulator(session, token: str, bookmaker_id: str) -> dict:
    link = session.query(LinkModel).filter_by(token=token, bookmaker_id=bookmaker_id).first()
    if not link:
        return {"valid": False, "reason": "TOKEN_NOT_REGISTERED"}

    client_id = sealer_port.unseal(operational_link_key(), link.client_ref_sealed)["client_id"]
    client = session.query(ClientModel).filter_by(id=client_id).first()
    if not client:
        return {"valid": False, "reason": "CLIENT_NOT_FOUND"}

    eligible = bool(client.adult and client.kyc_status == "VERIFIED"
                    and client.not_excluded and client.limits_ok)
    return {
        "valid": True,
        "eligible": eligible,
        "adult": bool(client.adult),
        "kyc_ok": client.kyc_status == "VERIFIED",
        "not_excluded": bool(client.not_excluded),
        "limits_ok": bool(client.limits_ok),
    }


@regulator_bp.route("/tokens/status", methods=["POST"])
def token_status_endpoint():
    data = request.get_json(silent=True) or {}
    if not all(f in data for f in ("token", "bookmaker_id")):
        return jsonify({"error": "MISSING_FIELDS"}), 400
    with SessionLocal() as session:
        result = token_status_at_regulator(session, data["token"], data["bookmaker_id"])
        session.commit()
        return jsonify(result), (200 if result["valid"] else 404)


@regulator_bp.route("/clients/register", methods=["POST"])
def register_client_endpoint():
    data = request.get_json(silent=True) or {}
    required = ("client_id", "full_name", "passport", "age")
    if any(field not in data for field in required):
        return jsonify({"error": "MISSING_FIELDS", "required": list(required)}), 400

    with SessionLocal() as session:
        result = register_client_at_regulator(
            session,
            client_id=data["client_id"],
            full_name=data["full_name"],
            passport=data["passport"],
            age=int(data["age"]),
        )
        session.commit()
        return jsonify({
            "client_id": data["client_id"],
            "tokens": result["tokens"],
            "credentials": result["credentials"],
            "client_share": result["shares"]["client"],
            "arbiter_share": result["shares"]["arbiter"],
        }), 201


@regulator_bp.route("/accounts/deposit", methods=["POST"])
def deposit_account():
    data = request.get_json(silent=True) or {}
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


# =============================================================================
# ЭТАП 3 (РАСЧЁТ)
#
# Криптографии в самих деньгах нет — есть двойная запись и холды. Но три
# вещи вокруг расчёта криптографические, и без них расчёт нечестен:
#   1. исход приходит ПОДПИСАННЫМ от оракула, регулятор его не выдумывает;
#   2. по каждой ставке выпускается подписанная расчётная квитанция;
#   3. всё это ложится в хэш-цепочку, корень которой публикуется.
# =============================================================================
@regulator_bp.route("/events/outcome", methods=["POST"])
def settle_event_outcome():
    data = request.get_json(silent=True) or {}
    outcome = data.get("outcome", "HOME_WIN")
    event_id = data.get("event_id", "ev_final_2026")

    # --- подписанный исход ---------------------------------------------------
    # Если подпись пришла снаружи — проверяем её. Если нет, берём подпись
    # у локального оракула: в демо он в том же процессе, на проде это
    # отдельная организация со своим ключом, которого у регулятора нет.
    signed_outcome = data.get("signed_outcome")
    if signed_outcome:
        if not outcome_oracle_port.verify(signed_outcome):
            return jsonify({
                "error": "ORACLE_SIGNATURE_INVALID",
                "message": "Исход не подписан доверенным источником результатов.",
            }), 403
        outcome = signed_outcome["statement"]["outcome"]
        event_id = signed_outcome["statement"]["event_id"]
    else:
        signed_outcome = outcome_oracle_port.publish(event_id, outcome)

    with SessionLocal() as session:
        ev = session.query(EventModel).filter_by(id=event_id).first()
        active_holds = session.query(HoldModel).filter_by(status="ACTIVE").all()
        bets = session.query(RegulatorBetModel).filter_by(status="ACCEPTED").all()

        append_audit(session, outcome_oracle_port.ORACLE_ID, "OUTCOME_PUBLISHED_SIGNED", {
            "event_id": event_id, "outcome": outcome,
            "signature": signed_outcome["signature"][:40],
        })

        for bet in bets:
            link = session.query(LinkModel).filter_by(token=bet.token).first()
            # ЭТАП 1: таблица links теперь реально зашифрована AES-GCM,
            # поэтому читаем её операционным ключом регулятора.
            unsealed = sealer_port.unseal(operational_link_key(), link.client_ref_sealed)
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

            # --- подписанная расчётная квитанция -------------------------
            if bet.status == "SETTLED_WON":
                result, moved = "WON", bk_amt
            elif bet.status == "SETTLED_LOST":
                result, moved = "LOST", -cli_amt
            else:
                result, moved = "VOIDED", 0

            settlement_body = {
                "bet_id": bet.id, "token": bet.token, "event_id": bet.event_id,
                "outcome": outcome, "result": result, "amount": moved,
            }
            session.add(SettlementModel(
                id=f"stl_{uuid.uuid4().hex[:8]}",
                bet_id=bet.id, token=bet.token, event_id=bet.event_id,
                outcome=outcome, result=result, amount=moved,
                regulator_sig=signer_port.sign("regulator", "", settlement_body),
            ))

            bm_bet = session.query(BmBetModel).filter_by(id=bet.id).first()
            if bm_bet:
                bm_bet.status = bet.status
                # ЭТАП 2: событие рассчитано — раскрываем соль обязательства.
                # Теперь любой может пересчитать хэш и убедиться, что
                # коэффициент не переписан задним числом.
                quote = session.query(BmQuoteModel).filter_by(id=bm_bet.quote_id).first()
                if quote:
                    bm_bet.odds_salt = quote.odds_salt
                if bet.status == "SETTLED_WON":
                    exp = session.query(BmTokenExposureModel).filter_by(token=bet.token).first()
                    if exp:
                        exp.won_count += 1

        if ev:
            ev.status = f"SETTLED ({outcome})"
            ev.outcome = outcome
            ev.outcome_source = outcome_oracle_port.ORACLE_ID
            ev.outcome_sig = signed_outcome["signature"]
            ev.settled_at = datetime.utcnow()

        append_audit(session, "regulator", "EVENT_SETTLED", {"event_id": event_id, "outcome": outcome})
        session.commit()

        # Корень цепочки публикуется сразу после расчёта — с этого момента
        # переписать журнал задним числом уже не выйдет незаметно.
        anchor_audit_root(session_factory=SessionLocal, actor="regulator")
        return jsonify({"status": f"SETTLED ({outcome})", "outcome": outcome,
                        "oracle_signature": signed_outcome["signature"]})


# =============================================================================
# ЭТАП 3 (РАСЧЁТ) — ЖУРНАЛ
# =============================================================================
def anchor_audit_root(session_factory, actor: str = "regulator") -> dict:
    """Подписывает текущий корень хэш-цепочки и сохраняет его."""
    with session_factory() as session:
        rows = session.query(AuditLogModel).order_by(AuditLogModel.seq.asc()).all()
        if not rows:
            return {"anchored": False, "reason": "EMPTY_LOG"}
        root = rows[-1].current_hash
        body = {"seq": rows[-1].seq, "root_hash": root}
        session.add(AuditAnchorModel(
            seq=rows[-1].seq,
            root_hash=root,
            signature=signer_port.sign(actor, "", body),
            ts=datetime.now().strftime("%H:%M:%S"),
        ))
        session.commit()
        return {"anchored": True, "seq": body["seq"], "root_hash": root}


@regulator_bp.route("/audit/verify", methods=["GET"])
def verify_audit_chain():
    """
    Пересчитывает журнал с нуля и сверяет с опубликованными корнями.

    Это то, что в реальной системе делает внешний аудитор: он не верит
    базе регулятора, а проверяет её сам.
    """
    with SessionLocal() as session:
        rows = session.query(AuditLogModel).order_by(AuditLogModel.seq.asc()).all()
        result = audit_chain_port.verify_chain(rows)

        anchors = session.query(AuditAnchorModel).order_by(AuditAnchorModel.seq.asc()).all()
        anchor_report = []
        for anchor in anchors:
            row = next((r for r in rows if r.seq == anchor.seq), None)
            sig_ok = signer_port.verify("regulator", "", {"seq": anchor.seq, "root_hash": anchor.root_hash}, anchor.signature)
            anchor_report.append({
                "seq": anchor.seq,
                "root_hash": anchor.root_hash,
                "signature_valid": sig_ok,
                "matches_log": bool(row and row.current_hash == anchor.root_hash),
                "ts": anchor.ts,
            })

        return jsonify({**result, "anchors": anchor_report})


@regulator_bp.route("/audit/anchor", methods=["POST"])
def anchor_endpoint():
    return jsonify(anchor_audit_root(SessionLocal))


@regulator_bp.route("/audit/tamper-demo", methods=["POST"])
def tamper_demo():
    """
    ДЕМО-ЭНДПОИНТ. В продакшене его быть не должно.

    Подменяет содержимое одной старой записи журнала, чтобы показать,
    что проверка цепочки немедленно находит место подделки.
    """
    data = request.get_json(silent=True) or {}
    target_seq = int(data.get("seq", 1))
    with SessionLocal() as session:
        row = session.query(AuditLogModel).filter_by(seq=target_seq).first()
        if not row:
            return jsonify({"error": "ENTRY_NOT_FOUND"}), 404
        row.payload_json = json.dumps({"tampered": True}, ensure_ascii=False)
        session.commit()

        rows = session.query(AuditLogModel).order_by(AuditLogModel.seq.asc()).all()
        return jsonify({"tampered_seq": target_seq, "verification": audit_chain_port.verify_chain(rows)})


# =============================================================================
# ЭТАП 4 (РАСКРЫТИЕ)
#
# Раскрывается ОДНА запись по ОДНОЙ заявке, и нужны две доли из трёх.
# Доля регулятора лежит у него, но сама по себе не даёт ничего: через одну
# точку проходит бесконечно много прямых Шамира.
#
# Вторую долю даёт ТОЛЬКО арбитр. Клиент в сборе порога не участвует,
# потому что ключи подписи ему выдал регулятор — иначе регулятор подписал
# бы согласие за него и раскрыл запись сам.
# =============================================================================
def open_disclosure(session, subject_token: str, reason: str, kind: str = "AML",
                    requester: str = "audit_department") -> DisclosureModel:
    """Создаёт заявку и сразу кладёт в неё долю регулятора."""
    link = session.query(LinkModel).filter_by(token=subject_token).first()
    if not link:
        raise ValueError("TOKEN_NOT_FOUND")
    client_id = sealer_port.unseal(operational_link_key(), link.client_ref_sealed)["client_id"]

    disc = DisclosureModel(
        id=f"disc_{uuid.uuid4().hex[:8]}",
        subject=subject_token,
        subject_client_id=client_id,
        kind=kind,
        requester=requester,
        reason=reason,
        status="PENDING_SECOND_SHARE",
    )
    session.add(disc)

    reg_share = session.query(CustodyShareModel).filter_by(
        client_id=client_id, party="regulator"
    ).first()
    if reg_share:
        submit_disclosure_share(session, disc.id, "regulator", reg_share.payload)

    append_audit(session, requester, "DISCLOSURE_REQUESTED", {
        "request_id": disc.id, "subject": subject_token[:16], "kind": kind, "reason": reason,
    })
    return disc


def submit_disclosure_share(session, disclosure_id: str, party: str, payload: str) -> bool:
    """
    Сторона отдаёт свою долю вместе с подписью.

    Подпись нужна, чтобы потом можно было доказать, КТО именно согласился
    на раскрытие: без неё регулятор мог бы подложить чужую долю от имени
    арбитра и утверждать, что тот одобрил.
    """
    existing = session.query(DisclosureShareModel).filter_by(
        disclosure_id=disclosure_id, party=party
    ).first()
    if existing:
        return False

    body = {"disclosure_id": disclosure_id, "party": party, "payload": payload}
    session.add(DisclosureShareModel(
        disclosure_id=disclosure_id,
        party=party,
        payload=payload,
        signature=signer_port.sign(party, "", body),
    ))
    return True


def resolve_disclosure(session, disclosure_id: str) -> dict:
    """
    Собирает порог и расшифровывает ОДНУ запись — ту, что указана в заявке.

    Раньше здесь брался первый попавшийся клиент из таблицы. С одним
    клиентом в демо это работало, с двумя — раскрывало не того.
    """
    disc = session.query(DisclosureModel).filter_by(id=disclosure_id).first()
    if not disc:
        return {"error": "DISCLOSURE_NOT_FOUND"}

    shares = session.query(DisclosureShareModel).filter_by(disclosure_id=disclosure_id).all()
    parties = [sh.party for sh in shares]

    # проверяем подписи сторон, прежде чем вообще что-то собирать
    for sh in shares:
        body = {"disclosure_id": sh.disclosure_id, "party": sh.party, "payload": sh.payload}
        if sh.signature and not signer_port.verify(sh.party, "", body, sh.signature):
            return {"status": disc.status, "collected": parties,
                    "error": "SHARE_SIGNATURE_INVALID", "party": sh.party}

    if len(shares) < 2:
        return {"status": "PENDING_SECOND_SHARE", "collected": parties, "identity": None}

    recovered_key = custody_port.combine_shares({sh.party: sh.payload for sh in shares})
    client = session.query(ClientModel).filter_by(id=disc.subject_client_id).first()
    if not recovered_key or not client:
        return {"status": disc.status, "collected": parties, "error": "RECOVERY_FAILED"}

    identity = sealer_port.unseal(recovered_key, client.pd_blob)
    disc.status = "REVEALED"
    disc.resolved_at = datetime.utcnow()
    return {"status": "REVEALED", "collected": parties, "identity": identity}


@regulator_bp.route("/disclosures", methods=["POST"])
def create_disclosure_endpoint():
    data = request.get_json(silent=True) or {}
    with SessionLocal() as session:
        try:
            disc = open_disclosure(
                session,
                subject_token=data["token"],
                reason=data.get("reason", "Запрос финмониторинга"),
                kind=data.get("kind", "AML"),
                requester=data.get("requester", "audit_department"),
            )
        except (KeyError, ValueError) as exc:
            return jsonify({"error": str(exc) or "BAD_REQUEST"}), 400
        session.commit()
        return jsonify({"request_id": disc.id, "status": disc.status}), 201


@regulator_bp.route("/disclosures/<disclosure_id>/result", methods=["GET"])
def disclosure_result_endpoint(disclosure_id: str):
    with SessionLocal() as session:
        result = resolve_disclosure(session, disclosure_id)
        session.commit()
        code = 200 if result.get("status") == "REVEALED" else 403
        return jsonify(result), (code if "error" not in result else 400)


@regulator_bp.route("/disclosures/solo-attempt", methods=["POST"])
def solo_disclosure_attempt():
    """
    ЭТАП 4: регулятор пробует раскрыть личность В ОДИНОЧКУ.

    Заявка создаётся, его собственная доля в неё кладётся — и на этом всё
    останавливается. Одна доля не даёт ни одного бита о секрете: через
    одну точку проходит бесконечно много прямых Шамира, и каждая даёт своё
    значение в нуле. Это не «трудно подобрать», это отсутствие информации.
    """
    data = request.get_json(silent=True) or {}
    with SessionLocal() as session:
        # чистим прошлую заявку, чтобы демо-сценарий можно было повторять
        session.query(DisclosureShareModel).delete()
        session.query(DisclosureModel).delete()
        session.flush()

        token = data.get("token")
        if not token:
            link = session.query(LinkModel).filter_by(bookmaker_id="bk_alpha").first()
            if not link:
                return jsonify({"error": "NO_LINKS_FOUND"}), 404
            token = link.token

        try:
            disc = open_disclosure(
                session, subject_token=token,
                reason=data.get("reason", "Проверка AML / Запрос финмониторинга"),
                kind=data.get("kind", "AML"),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

        result = resolve_disclosure(session, disc.id)
        append_audit(session, "audit_department", "DISCLOSURE_REQUESTED_SOLO_DENIED", {
            "request_id": disc.id, "subject": token[:16], "collected_shares": len(result.get("collected", [])),
        })
        session.commit()

        return jsonify({
            "error": "INSUFFICIENT_SHARES",
            "request_id": disc.id,
            "collected": result.get("collected", []),
            "message": (
                "ОШИБКА 403 (INSUFFICIENT_SHARES): Собрана только 1 доля из 3 (regulator). "
                "Через одну точку проходит бесконечно много прямых Шамира — "
                "в одиночку раскрыть личность математически невозможно!"
            ),
        }), 403


@regulator_bp.route("/disclosures/<disclosure_id>/shares", methods=["POST"])
def submit_share_endpoint(disclosure_id: str):
    """Сторона (клиент или арбитр) отдаёт свою долю по конкретной заявке."""
    data = request.get_json(silent=True) or {}
    party = data.get("party")
    payload = data.get("payload")
    # Клиент как подтверждающая сторона исключён намеренно: его ключи
    # выдаёт регулятор, значит регулятор мог бы подписать одобрение за него
    # и собрать порог в одиночку. Вторая доля приходит только от арбитра.
    if party not in ("arbiter", "regulator") or not payload:
        return jsonify({"error": "BAD_PARTY_OR_PAYLOAD"}), 400

    with SessionLocal() as session:
        disc = session.query(DisclosureModel).filter_by(id=disclosure_id).first()
        if not disc:
            return jsonify({"error": "DISCLOSURE_NOT_FOUND"}), 404
        submit_disclosure_share(session, disclosure_id, party, payload)
        result = resolve_disclosure(session, disclosure_id)
        append_audit(session, party, "DISCLOSURE_SHARE_SUBMITTED", {
            "request_id": disclosure_id, "party": party, "collected": result.get("collected", []),
        })
        session.commit()
        return jsonify(result)

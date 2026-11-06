# regulator_service.py
import json
import uuid
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional

import requests
from flask import Flask, jsonify, request
from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Integer, String, Text, UniqueConstraint, create_engine
)
from sqlalchemy.orm import declarative_base, sessionmaker

from common_ports import (
    AuditLogPort, CredentialService, Custody, HashChainAuditPort,
    ManualOutcomeSource, NoopCredentialService, NoopCustody,
    NoopSealer, NoopSignerVerifier, NoopTokenPolicy, OutcomeSource,
    Sealer, SignerVerifier, TokenPolicy
)

RegulatorBase = declarative_base()


# =============================================================================
# МОДЕЛИ БАЗЫ ДАННЫХ РЕГУЛЯТОРА (SQLAlchemy)
# =============================================================================
class ClientModel(RegulatorBase):
    __tablename__ = "clients"
    id = Column(String(64), primary_key=True)
    kyc_status = Column(String(32), nullable=False, default="VERIFIED")
    # В M0 хранит открытый JSON, на этапе M2 шифруется через Sealer (AES-256-GCM)
    pd_blob = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class LinkModel(RegulatorBase):
    """
    Таблица связей «Токен (ключ) <-> Зашифрованный идентификатор клиента (имя)».
    Ради защиты этой таблицы строится гибридная схема AES-256-GCM + разделение ключа.
    """
    __tablename__ = "links"
    token = Column(String(128), primary_key=True)
    bookmaker_id = Column(String(64), nullable=False, index=True)
    # Зашифрованная ссылка на client_id и ФИО (в M0 — через NoopSealer, в M2 — AES-256-GCM)
    client_ref_sealed = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class KeyCustodyModel(RegulatorBase):
    __tablename__ = "key_custody"
    client_id = Column(String(64), primary_key=True)
    public_key = Column(String(256), nullable=False)
    scheme_version = Column(String(32), nullable=False, default="M0_NOOP_2_OF_3")
    created_at = Column(DateTime, default=datetime.utcnow)


class CustodyShareModel(RegulatorBase):
    """У регулятора в этой таблице хранится ТОЛЬКО ЕГО собственная доля ключа."""
    __tablename__ = "custody_shares"
    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String(64), nullable=False, index=True)
    party = Column(String(32), nullable=False)  # 'regulator'
    payload = Column(Text, nullable=False)


class CredentialModel(RegulatorBase):
    __tablename__ = "credentials"
    id = Column(String(64), primary_key=True)
    client_id = Column(String(64), nullable=False, index=True)
    claims = Column(Text, nullable=False)
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)


class AccountModel(RegulatorBase):
    """
    Все суммы хранятся строго в целых копейках (BigInteger / int64). Никаких float!
    owner_ref имеет вид: 'client:{id}', 'bookmaker:{id}', 'house:fees', 'external:bank'.
    """
    __tablename__ = "accounts"
    id = Column(String(64), primary_key=True)
    owner_type = Column(String(32), nullable=False)
    owner_ref = Column(String(128), nullable=False, unique=True, index=True)
    available = Column(BigInteger, nullable=False, default=0)
    held = Column(BigInteger, nullable=False, default=0)
    version = Column(Integer, nullable=False, default=1)


class LedgerEntryModel(RegulatorBase):
    """Двойная запись: каждое движение денег создает 2 проводки (DEBIT и CREDIT) с суммой 0."""
    __tablename__ = "ledger_entries"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tx_id = Column(String(64), nullable=False, index=True)
    account_id = Column(String(64), nullable=False, index=True)
    direction = Column(String(16), nullable=False)  # 'DEBIT' (-) или 'CREDIT' (+)
    amount = Column(BigInteger, nullable=False)     # Всегда положительное число в копейках
    idempotency_key = Column(String(128), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class HoldModel(RegulatorBase):
    __tablename__ = "holds"
    id = Column(String(64), primary_key=True)
    account_id = Column(String(64), nullable=False, index=True)
    amount = Column(BigInteger, nullable=False)
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, RELEASED, CAPTURED
    ref_type = Column(String(32), nullable=False)
    ref_id = Column(String(64), nullable=False)
    idempotency_key = Column(String(128), nullable=False, unique=True)


class BetModel(RegulatorBase):
    """Статусы: QUOTED -> PLACED -> ACCEPTED -> SETTLED_WON | SETTLED_LOST | VOIDED | REJECTED"""
    __tablename__ = "bets"
    id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=False, index=True)
    bookmaker_id = Column(String(64), nullable=False)
    event_id = Column(String(64), nullable=False, index=True)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)  # В копейках
    odds = Column(String(32), nullable=False)   # Строка коэффициента, напр. "2.40"
    status = Column(String(32), nullable=False)
    client_sig = Column(Text, nullable=False)
    bookmaker_sig = Column(Text, nullable=False)
    client_hold_id = Column(String(64), nullable=True)
    bookmaker_hold_id = Column(String(64), nullable=True)
    placed_at = Column(DateTime, default=datetime.utcnow)
    settled_at = Column(DateTime, nullable=True)


class EventModel(RegulatorBase):
    __tablename__ = "events"
    id = Column(String(64), primary_key=True)
    name = Column(String(256), nullable=False)
    starts_at = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="OPEN")  # OPEN, SETTLED, VOIDED
    outcome = Column(String(64), nullable=True)
    outcome_source = Column(String(128), nullable=True)
    settled_at = Column(DateTime, nullable=True)


class DisclosureModel(RegulatorBase):
    __tablename__ = "disclosures"
    id = Column(String(64), primary_key=True)
    subject_type = Column(String(32), nullable=False)  # 'token' или 'bet_id'
    subject_id = Column(String(128), nullable=False)
    reason = Column(Text, nullable=False)
    requester = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="PENDING")  # PENDING, READY, REVEALED
    created_at = Column(DateTime, default=datetime.utcnow)


class DisclosureShareModel(RegulatorBase):
    __tablename__ = "disclosure_shares"
    id = Column(Integer, primary_key=True, autoincrement=True)
    disclosure_id = Column(String(64), nullable=False, index=True)
    party = Column(String(32), nullable=False)  # 'regulator', 'client', 'arbiter'
    payload = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint("disclosure_id", "party", name="uq_disclosure_party"),)


class AuditLogModel(RegulatorBase):
    __tablename__ = "audit_log"
    seq = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, default=datetime.utcnow)
    actor = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    payload_hash = Column(String(128), nullable=False)
    prev_hash = Column(String(128), nullable=False)
    current_hash = Column(String(128), nullable=False)


# =============================================================================
# КЛАСС СЕРВИСА РЕГУЛЯТОРА (Flask + SQLAlchemy)
# =============================================================================
class RegulatorService:
    def __init__(
        self,
        db_url: str = "sqlite:///regulator.db",
        bookmaker_internal_urls: Optional[dict] = None,
        signer: SignerVerifier = None,
        sealer: Sealer = None,
        custody: Custody = None,
        token_policy: TokenPolicy = None,
        cred_service: CredentialService = None,
        audit_port: AuditLogPort = None,
        outcome_source: OutcomeSource = None,
    ):
        self.app = Flask("RegulatorService")
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

        self.bookmaker_urls = bookmaker_internal_urls or {}
        self.signer = signer or NoopSignerVerifier()
        self.sealer = sealer or NoopSealer()
        self.custody = custody or NoopCustody()
        self.token_policy = token_policy or NoopTokenPolicy()
        self.cred_service = cred_service or NoopCredentialService()
        self.audit_port = audit_port or HashChainAuditPort()
        self.outcome_source = outcome_source or ManualOutcomeSource()

        # ИСПРАВЛЕНИЕ: Создаем таблицы ПОСЛЕ инициализации всех переменных.
        # SQLAlchemy уже точно "видит" все модели (ClientModel и т.д.),
        # так как класс RegulatorService объявлен ниже них в файле.
        RegulatorBase.metadata.create_all(self.engine)

        self._init_system_accounts()
        self._register_routes()

    def _init_system_accounts(self):
        with self.SessionLocal() as session:
            for owner_type, owner_ref in [("house", "house:fees"), ("external", "external:bank")]:
                acc = session.query(AccountModel).filter_by(owner_ref=owner_ref).first()
                if not acc:
                    session.add(AccountModel(
                        id=f"acc_{uuid.uuid4().hex[:10]}",
                        owner_type=owner_type,
                        owner_ref=owner_ref,
                        available=0,
                        held=0,
                    ))
            session.commit()

    def _append_audit(self, session, actor: str, action: str, payload: dict):
        last_entry = session.query(AuditLogModel).order_by(AuditLogModel.seq.desc()).first()
        prev_hash = last_entry.current_hash if last_entry else "0" * 64
        payload_hash, current_hash = self.audit_port.compute_entry_hashes(prev_hash, actor, action, payload)
        session.add(AuditLogModel(
            actor=actor,
            action=action,
            payload_hash=payload_hash,
            prev_hash=prev_hash,
            current_hash=current_hash,
        ))

    def _get_or_create_account(self, session, owner_ref: str) -> AccountModel:
        acc = session.query(AccountModel).filter_by(owner_ref=owner_ref).first()
        if not acc:
            owner_type = owner_ref.split(":")[0] if ":" in owner_ref else "custom"
            acc = AccountModel(
                id=f"acc_{uuid.uuid4().hex[:10]}",
                owner_type=owner_type,
                owner_ref=owner_ref,
                available=0,
                held=0,
            )
            session.add(acc)
            session.flush()
        return acc

    def _record_double_entry(self, session, debit_acc_id: str, credit_acc_id: str, amount: int, idemp_key: str = None):
        """Двойная запись: списывает с одного счёта и начисляет на другой, сумма проводок = 0."""
        tx_id = f"tx_{uuid.uuid4().hex[:12]}"
        session.add(LedgerEntryModel(
            tx_id=tx_id, account_id=debit_acc_id, direction="DEBIT", amount=amount, idempotency_key=idemp_key
        ))
        session.add(LedgerEntryModel(
            tx_id=tx_id, account_id=credit_acc_id, direction="CREDIT", amount=amount, idempotency_key=idemp_key
        ))

    def _create_hold_internal(self, session, owner_ref: str, amount: int, ref_type: str, ref_id: str, idemp_key: str) -> HoldModel:
        existing = session.query(HoldModel).filter_by(idempotency_key=idemp_key).first()
        if existing:
            return existing
        acc = self._get_or_create_account(session, owner_ref)
        if acc.available < amount:
            raise ValueError(f"INSUFFICIENT_FUNDS:{owner_ref}:need={amount},avail={acc.available}")
        acc.available -= amount
        acc.held += amount
        acc.version += 1
        hold = HoldModel(
            id=f"hold_{uuid.uuid4().hex[:10]}",
            account_id=acc.id,
            amount=amount,
            status="ACTIVE",
            ref_type=ref_type,
            ref_id=ref_id,
            idempotency_key=idemp_key,
        )
        session.add(hold)
        session.flush()
        return hold

    def _release_hold_internal(self, session, hold_id: str):
        hold = session.query(HoldModel).filter_by(id=hold_id).first()
        if not hold or hold.status != "ACTIVE":
            return
        acc = session.query(AccountModel).filter_by(id=hold.account_id).first()
        acc.held -= hold.amount
        acc.available += hold.amount
        acc.version += 1
        hold.status = "RELEASED"

    def _capture_hold_internal(self, session, hold_id: str, to_owner_ref: str, idemp_key: str):
        hold = session.query(HoldModel).filter_by(id=hold_id).first()
        if not hold or hold.status != "ACTIVE":
            return
        from_acc = session.query(AccountModel).filter_by(id=hold.account_id).first()
        to_acc = self._get_or_create_account(session, to_owner_ref)

        from_acc.held -= hold.amount
        from_acc.version += 1
        to_acc.available += hold.amount
        to_acc.version += 1
        hold.status = "CAPTURED"

        self._record_double_entry(session, from_acc.id, to_acc.id, hold.amount, idemp_key)

    def _register_routes(self):
        # 1. РЕГИСТРАЦИЯ КЛИЕНТА (KYC + CSPRNG + AES-GCM Sealer + Shamir 2-of-3)
        @self.app.route("/v1/clients", methods=["POST"])
        def register_client():
            data = request.json or {}
            full_name = data.get("full_name", "Аноним")
            passport = data.get("passport", "0000 000000")
            age = int(data.get("age", 21))

            client_id = f"cli_{uuid.uuid4().hex[:8]}"
            # [CRYPTO HOOK — ЭТАП 1.2: Генерация секрета клиента s через CSPRNG]
            client_secret_s = f"sec_{uuid.uuid4().hex}"

            # [CRYPTO HOOK — ЭТАП 1.3: Генерация ключа DEK и запирание ПДн через AES-256-GCM]
            dek = self.sealer.generate_dek()
            pd_sealed = self.sealer.seal(dek, {
                "client_id": client_id,
                "full_name": full_name,
                "passport": passport,
                "age": age,
            })

            # [CRYPTO HOOK — ЭТАП 4: Разделение ключа DEK по схеме Шамира / Эль-Гамаля на 3 доли]
            shares = self.custody.split_key(dek)

            with self.SessionLocal() as session:
                session.add(ClientModel(
                    id=client_id,
                    kyc_status="VERIFIED" if age >= 18 else "REJECTED_AGE",
                    pd_blob=pd_sealed,
                ))
                session.add(KeyCustodyModel(
                    client_id=client_id,
                    public_key=f"pub_{client_id}",
                    scheme_version="M0_SHAMIR_2_OF_3",
                ))
                # Регулятор сохраняет в БД ТОЛЬКО СВОЮ долю ключа!
                session.add(CustodyShareModel(
                    client_id=client_id,
                    party="regulator",
                    payload=shares["regulator"],
                ))
                self._get_or_create_account(session, f"client:{client_id}")
                self._append_audit(session, "regulator", "CLIENT_REGISTERED", {"client_id": client_id})
                session.commit()

            return jsonify({
                "client_id": client_id,
                "client_secret": client_secret_s,
                "client_share": shares["client"],
                "arbiter_share": shares["arbiter"],  # Передается арбитру при инициализации
            }), 201

        @self.app.route("/v1/clients/<client_id>", methods=["GET"])
        def get_client(client_id):
            with self.SessionLocal() as session:
                cli = session.query(ClientModel).filter_by(id=client_id).first()
                if not cli:
                    return jsonify({"error": "NOT_FOUND"}), 404
                return jsonify({"id": cli.id, "kyc_status": cli.kyc_status, "pd_blob": cli.pd_blob})

        # 2. ВЫДАЧА ТОКЕНА И СОХРАНЕНИЕ ЗАШИФРОВАННОЙ СВЯЗИ В ТАБЛИЦУ LINKS
        @self.app.route("/v1/tokens", methods=["POST"])
        def issue_token():
            data = request.json or {}
            client_id = data["client_id"]
            bookmaker_id = data["bookmaker_id"]
            client_secret = data.get("client_secret", f"sec_{client_id}")

            with self.SessionLocal() as session:
                cli = session.query(ClientModel).filter_by(id=client_id).first()
                if not cli:
                    return jsonify({"error": "CLIENT_NOT_FOUND"}), 404

                reg_share = session.query(CustodyShareModel).filter_by(
                    client_id=client_id, party="regulator"
                ).first()
                # Восстанавливаем метку DEK в M0 для запечатывания связи в links
                dek_label = reg_share.payload.split(":", 2)[-1] if reg_share else self.sealer.generate_dek()

                token, zk_proof = self.token_policy.derive_token(client_secret, bookmaker_id)

                existing_link = session.query(LinkModel).filter_by(token=token).first()
                if not existing_link:
                    # [CRYPTO HOOK — ЭТАП 1.3: Шифрование связи «токен <-> клиент» через AES-256-GCM]
                    sealed_ref = self.sealer.seal(dek_label, {
                        "client_id": client_id,
                        "token": token,
                        "bookmaker_id": bookmaker_id,
                    })
                    session.add(LinkModel(
                        token=token,
                        bookmaker_id=bookmaker_id,
                        client_ref_sealed=sealed_ref,
                    ))
                    self._append_audit(session, "regulator", "TOKEN_LINKED", {"token": token, "bookmaker_id": bookmaker_id})
                    session.commit()

                return jsonify({"token": token, "zk_token_proof": zk_proof}), 201

        # 3. ПРОВЕРКА ДОПУСКА ТОКЕНА (ELIGIBILITY) И УДОСТОВЕРЕНИЯ (BBS+)
        @self.app.route("/v1/tokens/<token>/eligibility", methods=["GET"])
        def check_eligibility(token):
            # В M0 вызывается букмекером по REST. На этапе M4 заменяется на офлайн-проверку BBS+
            with self.SessionLocal() as session:
                link = session.query(LinkModel).filter_by(token=token).first()
                if not link:
                    return jsonify({
                        "valid": False, "adult": False, "kyc_ok": False, "not_excluded": False, "limits_ok": False
                    }), 404
                return jsonify({
                    "valid": True,
                    "adult": True,
                    "kyc_ok": True,
                    "not_excluded": True,
                    "limits_ok": True,
                })

        @self.app.route("/v1/credentials/issue", methods=["POST"])
        def issue_credential():
            data = request.json or {}
            client_id = data["client_id"]
            client_secret = data.get("client_secret", "")
            claims = {
                "adult": True,
                "kyc_ok": True,
                "not_excluded": True,
                "limits_ok": True,
                "valid_until": (datetime.utcnow() + timedelta(days=365)).isoformat(),
            }
            cred = self.cred_service.issue_credential(client_id, client_secret, claims)
            with self.SessionLocal() as session:
                session.add(CredentialModel(
                    id=cred["cred_id"],
                    client_id=client_id,
                    claims=json.dumps(claims),
                    expires_at=datetime.utcnow() + timedelta(days=365),
                    revoked=False,
                ))
                session.commit()
            return jsonify(cred), 201

        @self.app.route("/v1/credentials/verify", methods=["POST"])
        def verify_credential():
            presentation = request.json or {}
            ok, claims = self.cred_service.verify_presentation(presentation)
            return jsonify({"valid": ok, "claims": claims})

        # 4. ДЕНЕЖНЫЕ ОПЕРАЦИИ И ДВОЙНАЯ ЗАПИСЬ (СЧЕТА, ДЕПОЗИТЫ, ВЫВОДЫ, ХОЛДЫ)
        @self.app.route("/v1/accounts/<path:owner_ref>", methods=["GET"])
        def get_account(owner_ref):
            with self.SessionLocal() as session:
                acc = self._get_or_create_account(session, owner_ref)
                session.commit()
                return jsonify({
                    "owner": acc.owner_ref,
                    "available": acc.available,
                    "held": acc.held,
                })

        @self.app.route("/v1/accounts/<path:owner_ref>/deposit", methods=["POST"])
        def deposit(owner_ref):
            data = request.json or {}
            amount = int(data["amount"])  # Строго в целых копейках!
            idemp_key = data["idempotency_key"]

            with self.SessionLocal() as session:
                existing = session.query(LedgerEntryModel).filter_by(idempotency_key=idemp_key).first()
                acc = self._get_or_create_account(session, owner_ref)
                if not existing:
                    ext_acc = self._get_or_create_account(session, "external:bank")
                    ext_acc.available -= amount
                    acc.available += amount
                    acc.version += 1
                    self._record_double_entry(session, ext_acc.id, acc.id, amount, idemp_key)
                    self._append_audit(session, owner_ref, "DEPOSIT", {"amount": amount, "idempotency_key": idemp_key})
                    session.commit()
                return jsonify({"owner": acc.owner_ref, "available": acc.available, "held": acc.held})

        @self.app.route("/v1/accounts/<path:owner_ref>/withdraw", methods=["POST"])
        def withdraw(owner_ref):
            data = request.json or {}
            amount = int(data["amount"])
            idemp_key = data["idempotency_key"]

            with self.SessionLocal() as session:
                existing = session.query(LedgerEntryModel).filter_by(idempotency_key=idemp_key).first()
                acc = self._get_or_create_account(session, owner_ref)
                if not existing:
                    if acc.available < amount:
                        return jsonify({"error": "INSUFFICIENT_FUNDS"}), 400
                    ext_acc = self._get_or_create_account(session, "external:bank")
                    acc.available -= amount
                    ext_acc.available += amount
                    acc.version += 1
                    self._record_double_entry(session, acc.id, ext_acc.id, amount, idemp_key)
                    self._append_audit(session, owner_ref, "WITHDRAW", {"amount": amount, "idempotency_key": idemp_key})
                    session.commit()
                return jsonify({"owner": acc.owner_ref, "available": acc.available, "held": acc.held})

        @self.app.route("/v1/holds", methods=["POST"])
        def create_hold():
            data = request.json or {}
            with self.SessionLocal() as session:
                try:
                    hold = self._create_hold_internal(
                        session, data["owner"], int(data["amount"]), "MANUAL", data["ref"], data["idempotency_key"]
                    )
                    session.commit()
                    return jsonify({"hold_id": hold.id, "status": hold.status}), 201
                except ValueError as e:
                    session.rollback()
                    return jsonify({"error": str(e)}), 400

        @self.app.route("/v1/holds/<hold_id>/release", methods=["POST"])
        def release_hold(hold_id):
            with self.SessionLocal() as session:
                self._release_hold_internal(session, hold_id)
                session.commit()
                return jsonify({"hold_id": hold_id, "status": "RELEASED"})

        @self.app.route("/v1/holds/<hold_id>/capture", methods=["POST"])
        def capture_hold(hold_id):
            data = request.json or {}
            with self.SessionLocal() as session:
                self._capture_hold_internal(session, hold_id, data["to_owner"], f"cap_{hold_id}")
                session.commit()
                return jsonify({"hold_id": hold_id, "status": "CAPTURED"})

        @self.app.route("/v1/ledger", methods=["GET"])
        def get_ledger():
            with self.SessionLocal() as session:
                entries = session.query(LedgerEntryModel).all()
                return jsonify([{
                    "tx_id": e.tx_id,
                    "account_id": e.account_id,
                    "direction": e.direction,
                    "amount": e.amount,
                    "created_at": e.created_at.isoformat(),
                } for e in entries])

        # 5. ПРИЁМ И РЕГИСТРАЦИЯ СТАВКИ ОТ БУКМЕКЕРА (АТОМАРНОЕ СОЗДАНИЕ ДВУХ ХОЛДОВ)
        @self.app.route("/v1/bets", methods=["POST"])
        def register_bet():
            data = request.json or {}
            token = data["token"]
            bookmaker_id = data["bookmaker_id"]
            event_id = data["event_id"]
            selection = data["selection"]
            stake = int(data["stake"])  # В копейках (например, 1000 руб = 100000 коп.)
            odds_str = str(data["odds"])
            quote_id = data["quote_id"]
            client_sig = data["client_sig"]
            bookmaker_sig = data["bookmaker_sig"]

            # Проверка подписи клиента (гарантия того, что букмекер не списывает деньги сам)
            expected_payload = {
                "quote_id": quote_id,
                "token": token,
                "event_id": event_id,
                "selection": selection,
                "stake": stake,
                "odds": odds_str,
            }
            if not self.signer.verify(token, "", expected_payload, client_sig):
                return jsonify({"error": "INVALID_CLIENT_SIGNATURE", "status": "REJECTED"}), 400

            # Расчёт потенциальной выплаты и риска букмекера строго в целых копейках
            odds_dec = Decimal(odds_str)
            potential_payout = int((Decimal(stake) * odds_dec).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            bookmaker_risk = potential_payout - stake

            with self.SessionLocal() as session:
                link = session.query(LinkModel).filter_by(token=token).first()
                if not link:
                    return jsonify({"error": "UNKNOWN_TOKEN", "status": "REJECTED"}), 404

                # Внутри эскроу регулятор определяет счёт для резервирования средств
                # Примечание по приватности (раздел 9 ТЗ): в боевом режиме счёт привязывается к
                # слепому ваучеру/токену, чтобы исключить временную корреляцию пополнений и ставок.
                unsealed_ref = self.sealer.unseal("", link.client_ref_sealed)
                client_id = unsealed_ref["client_id"]

                client_owner = f"client:{client_id}"
                bk_owner = f"bookmaker:{bookmaker_id}"

                bk_acc = self._get_or_create_account(session, bk_owner)
                if bk_acc.available < bookmaker_risk:
                    return jsonify({"error": "INSUFFICIENT_LIQUIDITY", "status": "REJECTED"}), 400

                cli_acc = self._get_or_create_account(session, client_owner)
                if cli_acc.available < stake:
                    return jsonify({"error": "INSUFFICIENT_CLIENT_FUNDS", "status": "REJECTED"}), 400

                bet_id = f"bet_{uuid.uuid4().hex[:10]}"
                try:
                    # Атомарное создание двух холдов: ставки клиента и обеспечения букмекера
                    cli_hold = self._create_hold_internal(
                        session, client_owner, stake, "BET", bet_id, f"hold_cli_{quote_id}"
                    )
                    bk_hold = self._create_hold_internal(
                        session, bk_owner, bookmaker_risk, "BET_RISK", bet_id, f"hold_bk_{quote_id}"
                    )

                    bet = BetModel(
                        id=bet_id,
                        token=token,
                        bookmaker_id=bookmaker_id,
                        event_id=event_id,
                        selection=selection,
                        stake=stake,
                        odds=odds_str,
                        status="ACCEPTED",
                        client_sig=client_sig,
                        bookmaker_sig=bookmaker_sig,
                        client_hold_id=cli_hold.id,
                        bookmaker_hold_id=bk_hold.id,
                    )
                    session.add(bet)
                    self._append_audit(session, bookmaker_id, "BET_ACCEPTED", {
                        "bet_id": bet_id, "token": token, "stake": stake, "odds": odds_str
                    })
                    session.commit()
                    return jsonify({"bet_id": bet_id, "status": "ACCEPTED"}), 201
                except Exception as e:
                    session.rollback()
                    return jsonify({"error": str(e), "status": "REJECTED"}), 400

        @self.app.route("/v1/bets/<bet_id>", methods=["GET"])
        def get_bet(bet_id):
            with self.SessionLocal() as session:
                b = session.query(BetModel).filter_by(id=bet_id).first()
                if not b:
                    return jsonify({"error": "NOT_FOUND"}), 404
                return jsonify({
                    "bet_id": b.id, "token": b.token, "event_id": b.event_id,
                    "selection": b.selection, "stake": b.stake, "odds": b.odds, "status": b.status
                })

        # 6. СОБЫТИЯ И АВТОМАТИЧЕСКИЙ РАСЧЁТ (SETTLEMENT)
        @self.app.route("/v1/events", methods=["POST"])
        def create_event():
            data = request.json or {}
            with self.SessionLocal() as session:
                ev = EventModel(
                    id=data["event_id"],
                    name=data["name"],
                    starts_at=data.get("starts_at", datetime.utcnow().isoformat()),
                    status="OPEN",
                )
                session.merge(ev)
                self._append_audit(session, "regulator", "EVENT_CREATED", {"event_id": data["event_id"]})
                session.commit()
            return jsonify({"event_id": data["event_id"], "status": "OPEN"}), 201

        @self.app.route("/v1/events/<event_id>/outcome", methods=["POST"])
        def settle_event(event_id):
            data = request.json or {}
            outcome = data["outcome"]
            source = data.get("source", "official_feed")

            if not self.outcome_source.verify_outcome(event_id, outcome, source):
                return jsonify({"error": "INVALID_OUTCOME_SOURCE"}), 400

            settled_Summary = []
            with self.SessionLocal() as session:
                ev = session.query(EventModel).filter_by(id=event_id).first()
                if not ev:
                    return jsonify({"error": "EVENT_NOT_FOUND"}), 404

                ev.outcome = outcome
                ev.outcome_source = source
                ev.status = "SETTLED"
                ev.settled_at = datetime.utcnow()

                bets = session.query(BetModel).filter_by(event_id=event_id, status="ACCEPTED").all()
                for bet in bets:
                    link = session.query(LinkModel).filter_by(token=bet.token).first()
                    client_id = self.sealer.unseal("", link.client_ref_sealed)["client_id"]
                    client_owner = f"client:{client_id}"
                    bk_owner = f"bookmaker:{bet.bookmaker_id}"

                    if outcome == "VOID":
                        self._release_hold_internal(session, bet.client_hold_id)
                        self._release_hold_internal(session, bet.bookmaker_hold_id)
                        bet.status = "VOIDED"
                    elif bet.selection == outcome:
                        # Клиент выиграл: забираем холд букмекера (1400) клиенту и освобождаем холд клиента (1000)
                        self._capture_hold_internal(session, bet.bookmaker_hold_id, client_owner, f"settle_win_{bet.id}")
                        self._release_hold_internal(session, bet.client_hold_id)
                        bet.status = "SETTLED_WON"
                    else:
                        # Клиент проиграл: забираем холд клиента (1000) букмекеру и освобождаем холд букмекера (1400)
                        self._capture_hold_internal(session, bet.client_hold_id, bk_owner, f"settle_loss_{bet.id}")
                        self._release_hold_internal(session, bet.bookmaker_hold_id)
                        bet.status = "SETTLED_LOST"

                    bet.settled_at = datetime.utcnow()
                    settled_Summary.append({"bet_id": bet.id, "token": bet.token, "status": bet.status})

                self._append_audit(session, "regulator", "EVENT_SETTLED", {
                    "event_id": event_id, "outcome": outcome, "settled_count": len(settled_Summary)
                })
                session.commit()

            # Уведомляем букмекера о расчёте
            for item in settled_Summary:
                for bk_id, bk_url in self.bookmaker_urls.items():
                    try:
                        requests.post(f"{bk_url}/v1/internal/settled", json=item, timeout=2)
                    except Exception:
                        pass

            return jsonify({"event_id": event_id, "outcome": outcome, "settled_bets": settled_Summary})

        # 7. ПОРОГОВОЕ РАСКРЫТИЕ ЛИЧНОСТИ («2 ИЗ 3»: РЕГУЛЯТОР + КЛИЕНТ ИЛИ АРБИТР)
        @self.app.route("/v1/disclosures", methods=["POST"])
        def create_disclosure():
            data = request.json or {}
            subject_type = data.get("subject_type", "token")
            subject_id = data["subject"]
            reason = data["reason"]
            requester = data["requester"]

            req_id = f"disc_{uuid.uuid4().hex[:10]}"
            with self.SessionLocal() as session:
                disc = DisclosureModel(
                    id=req_id,
                    subject_type=subject_type,
                    subject_id=subject_id,
                    reason=reason,
                    requester=requester,
                    status="PENDING",
                )
                session.add(disc)

                # Регулятор автоматически прикладывает свою долю (1 из 3)
                token = subject_id
                if subject_type == "bet_id":
                    b = session.query(BetModel).filter_by(id=subject_id).first()
                    token = b.token if b else subject_id

                link = session.query(LinkModel).filter_by(token=token).first()
                if link:
                    # В M0 находим client_id для подтягивания серверной доли регулятора
                    cli_id = self.sealer.unseal("", link.client_ref_sealed)["client_id"]
                    reg_share = session.query(CustodyShareModel).filter_by(
                        client_id=cli_id, party="regulator"
                    ).first()
                    if reg_share:
                        session.add(DisclosureShareModel(
                            disclosure_id=req_id, party="regulator", payload=reg_share.payload
                        ))

                self._append_audit(session, requester, "DISCLOSURE_REQUESTED", {
                    "request_id": req_id, "subject": subject_id, "reason": reason
                })
                session.commit()

            return jsonify({"request_id": req_id, "status": "PENDING", "threshold": 2}), 201

        @self.app.route("/v1/disclosures/<req_id>", methods=["GET"])
        def get_disclosure_status(req_id):
            with self.SessionLocal() as session:
                disc = session.query(DisclosureModel).filter_by(id=req_id).first()
                if not disc:
                    return jsonify({"error": "NOT_FOUND"}), 404
                shares = session.query(DisclosureShareModel).filter_by(disclosure_id=req_id).all()
                collected = [s.party for s in shares]
                return jsonify({
                    "request_id": disc.id,
                    "status": disc.status,
                    "needed_parties": 2,
                    "collected": collected,
                })

        @self.app.route("/v1/disclosures/<req_id>/shares", methods=["POST"])
        def submit_disclosure_share(req_id):
            data = request.json or {}
            party = data["party"]      # 'client' или 'arbiter'
            payload = data["payload"]  # Криптографическая доля (или частичное дешифрование d_i = x_i * R)

            with self.SessionLocal() as session:
                disc = session.query(DisclosureModel).filter_by(id=req_id).first()
                if not disc:
                    return jsonify({"error": "NOT_FOUND"}), 404

                existing = session.query(DisclosureShareModel).filter_by(
                    disclosure_id=req_id, party=party
                ).first()
                if not existing:
                    session.add(DisclosureShareModel(
                        disclosure_id=req_id, party=party, payload=payload
                    ))
                    session.flush()

                all_shares = session.query(DisclosureShareModel).filter_by(disclosure_id=req_id).all()
                if len(all_shares) >= 2:
                    disc.status = "REVEALED"

                self._append_audit(session, party, "DISCLOSURE_SHARE_SUBMITTED", {
                    "request_id": req_id, "party": party, "collected_count": len(all_shares)
                })
                session.commit()
                return jsonify({"request_id": req_id, "status": disc.status, "collected_count": len(all_shares)})

        @self.app.route("/v1/disclosures/<req_id>/result", methods=["GET"])
        def get_disclosure_result(req_id):
            with self.SessionLocal() as session:
                disc = session.query(DisclosureModel).filter_by(id=req_id).first()
                if not disc:
                    return jsonify({"error": "NOT_FOUND"}), 404
                shares = session.query(DisclosureShareModel).filter_by(disclosure_id=req_id).all()
                if len(shares) < 2:
                    return jsonify({
                        "error": "INSUFFICIENT_SHARES",
                        "message": "В одиночку регулятор не может раскрыть личность. Нужно минимум 2 доли из 3.",
                        "collected": [s.party for s in shares],
                    }), 403

                share_map = {s.party: s.payload for s in shares}
                # [CRYPTO HOOK — ЭТАП 4/5: Сборка ключа из 2 долей по Шамиру или Пороговому Эль-Гамалю]
                recovered_dek = self.custody.combine_shares(share_map)

                token = disc.subject_id
                if disc.subject_type == "bet_id":
                    b = session.query(BetModel).filter_by(id=disc.subject_id).first()
                    token = b.token if b else disc.subject_id

                link = session.query(LinkModel).filter_by(token=token).first()
                unsealed_link = self.sealer.unseal(recovered_dek, link.client_ref_sealed)
                cli = session.query(ClientModel).filter_by(id=unsealed_link["client_id"]).first()
                unsealed_pd = self.sealer.unseal(recovered_dek, cli.pd_blob)

                self._append_audit(session, "regulator", "DISCLOSURE_RESULT_ACCESSED", {
                    "request_id": req_id, "parties_used": list(share_map.keys())
                })
                session.commit()

                return jsonify({
                    "request_id": req_id,
                    "token": token,
                    "participating_parties": list(share_map.keys()),
                    "revealed_identity": unsealed_pd,
                })

        # 8. АУДИТ И КОРЕНЬ ХЭШ-ЦЕПОЧКИ
        @self.app.route("/v1/audit/root", methods=["GET"])
        def get_audit_root():
            with self.SessionLocal() as session:
                last = session.query(AuditLogModel).order_by(AuditLogModel.seq.desc()).first()
                return jsonify({
                    "seq": last.seq if last else 0,
                    "root_hash": last.current_hash if last else "0" * 64,
                })

        @self.app.route("/v1/audit", methods=["GET"])
        def get_audit_logs():
            with self.SessionLocal() as session:
                logs = session.query(AuditLogModel).order_by(AuditLogModel.seq.asc()).all()
                return jsonify([{
                    "seq": l.seq, "actor": l.actor, "action": l.action,
                    "payload_hash": l.payload_hash, "prev_hash": l.prev_hash, "current_hash": l.current_hash
                } for l in logs])
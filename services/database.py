from datetime import datetime
from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Integer, String, Text, UniqueConstraint, create_engine
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

Base = declarative_base()


# =============================================================================
# МОДЕЛИ РЕГУЛЯТОРА И ЭСКРОУ
# =============================================================================
class ClientModel(Base):
    __tablename__ = "clients"
    id = Column(String(64), primary_key=True)
    kyc_status = Column(String(32), nullable=False, default="VERIFIED")
    pd_blob = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class LinkModel(Base):
    """Таблица зашифрованных связей «Токен <-> Зашифрованный ID клиента»."""
    __tablename__ = "links"
    token = Column(String(128), primary_key=True)
    bookmaker_id = Column(String(64), nullable=False, index=True)
    client_ref_sealed = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class CustodyShareModel(Base):
    """Хранит долю ключа Регулятора (share #2)."""
    __tablename__ = "custody_shares"
    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String(64), nullable=False, index=True)
    party = Column(String(32), nullable=False)
    payload = Column(Text, nullable=False)


class AccountModel(Base):
    """Счета в целых копейках (int64). Никаких float!"""
    __tablename__ = "accounts"
    id = Column(String(64), primary_key=True)
    owner_type = Column(String(32), nullable=False)
    owner_ref = Column(String(128), nullable=False, unique=True, index=True)
    available = Column(BigInteger, nullable=False, default=0)
    held = Column(BigInteger, nullable=False, default=0)
    version = Column(Integer, nullable=False, default=1)


class LedgerEntryModel(Base):
    """Двойная бухгалтерская запись (DEBIT / CREDIT)."""
    __tablename__ = "ledger_entries"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tx_id = Column(String(64), nullable=False, index=True)
    account_id = Column(String(64), nullable=False, index=True)
    direction = Column(String(16), nullable=False)
    amount = Column(BigInteger, nullable=False)
    idempotency_key = Column(String(128), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class HoldModel(Base):
    """Активные холды ставок клиента и риска букмекера."""
    __tablename__ = "holds"
    id = Column(String(64), primary_key=True)
    account_id = Column(String(64), nullable=False, index=True)
    owner_ref = Column(String(128), nullable=False)
    amount = Column(BigInteger, nullable=False)
    status = Column(String(32), nullable=False, default="ACTIVE")
    ref_type = Column(String(32), nullable=False)
    ref_id = Column(String(64), nullable=False)
    idempotency_key = Column(String(128), nullable=False, unique=True)


class BetModel(Base):
    __tablename__ = "bets"
    id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=False, index=True)
    bookmaker_id = Column(String(64), nullable=False)
    event_id = Column(String(64), nullable=False, index=True)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)
    client_sig = Column(Text, nullable=False)
    bookmaker_sig = Column(Text, nullable=False)
    client_hold_id = Column(String(64), nullable=True)
    bookmaker_hold_id = Column(String(64), nullable=True)
    placed_at = Column(DateTime, default=datetime.utcnow)
    settled_at = Column(DateTime, nullable=True)


class EventModel(Base):
    __tablename__ = "events"
    id = Column(String(64), primary_key=True)
    name = Column(String(256), nullable=False)
    status = Column(String(32), nullable=False, default="OPEN")
    outcome = Column(String(64), nullable=True)
    settled_at = Column(DateTime, nullable=True)


class DisclosureModel(Base):
    __tablename__ = "disclosures"
    id = Column(String(64), primary_key=True)
    subject_type = Column(String(32), nullable=False)
    subject_id = Column(String(128), nullable=False)
    reason = Column(Text, nullable=False)
    requester = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="PENDING")
    created_at = Column(DateTime, default=datetime.utcnow)


class DisclosureShareModel(Base):
    __tablename__ = "disclosure_shares"
    id = Column(Integer, primary_key=True, autoincrement=True)
    disclosure_id = Column(String(64), nullable=False, index=True)
    party = Column(String(32), nullable=False)
    payload = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint("disclosure_id", "party", name="uq_disc_party"),)


class AuditLogModel(Base):
    __tablename__ = "audit_log"
    seq = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, default=datetime.utcnow)
    actor = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    payload_hash = Column(String(128), nullable=False)
    prev_hash = Column(String(128), nullable=False)
    current_hash = Column(String(128), nullable=False)


# =============================================================================
# МОДЕЛИ БУКМЕКЕРА (БЕЗ ПЕРСОНАЛЬНЫХ ДАННЫХ)
# =============================================================================
class BmTokenExposureModel(Base):
    __tablename__ = "bm_token_exposure"
    token = Column(String(128), primary_key=True)
    bets_count = Column(Integer, nullable=False, default=0)
    total_staked = Column(BigInteger, nullable=False, default=0)
    won_count = Column(Integer, nullable=False, default=0)


class BmQuoteModel(Base):
    __tablename__ = "bm_quotes"
    id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=False, index=True)
    event_id = Column(String(64), nullable=False)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    odds_commitment = Column(String(128), nullable=False)
    expires_at = Column(DateTime, nullable=False)


class BmBetModel(Base):
    __tablename__ = "bm_bets"
    id = Column(String(64), primary_key=True)
    quote_id = Column(String(64), nullable=False)
    token = Column(String(128), nullable=False, index=True)
    event_id = Column(String(64), nullable=False)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    odds_commitment = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False)
    receipt_sig = Column(Text, nullable=False)


# =============================================================================
# МОДЕЛИ КЛИЕНТСКОГО КОШЕЛЬКА И НЕЗАВИСИМОГО АРБИТРА
# =============================================================================
class WalletIdentityModel(Base):
    __tablename__ = "wallet_identity"
    client_id = Column(String(64), primary_key=True)
    full_name = Column(String(128), nullable=False)
    passport = Column(String(64), nullable=False)
    age = Column(Integer, nullable=False, default=23)
    client_secret_s = Column(String(128), nullable=False)
    client_share = Column(Text, nullable=False)
    credential_json = Column(Text, nullable=False)


class WalletTokenModel(Base):
    __tablename__ = "wallet_tokens"
    bookmaker_id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=False)
    zk_token_proof = Column(Text, nullable=False)


class WalletReceiptModel(Base):
    __tablename__ = "wallet_receipts"
    bet_id = Column(String(64), primary_key=True)
    bookmaker_id = Column(String(64), nullable=False)
    token = Column(String(128), nullable=False)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    bookmaker_sig = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ArbiterShareModel(Base):
    __tablename__ = "arbiter_shares"
    client_id = Column(String(64), primary_key=True)
    share_payload = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ArbiterAuditModel(Base):
    __tablename__ = "arbiter_audit"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, default=datetime.utcnow)
    action = Column(String(64), nullable=False)
    details = Column(Text, nullable=False)


# =============================================================================
# ИНИЦИАЛИЗАЦИЯ ДВИЖКА SQLITE
# =============================================================================
DB_URL = "sqlite:///burmalda_platform.db"

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db():
    Base.metadata.create_all(engine)
    with SessionLocal() as session:
        for owner_type, owner_ref in [
            ("bookmaker", "bookmaker:bk_alpha"),
            ("house", "house:fees"),
            ("external", "external:bank"),
        ]:
            if not session.query(AccountModel).filter_by(owner_ref=owner_ref).first():
                session.add(AccountModel(
                    id=f"acc_{owner_ref.replace(':', '_')}",
                    owner_type=owner_type,
                    owner_ref=owner_ref,
                    available=0,
                    held=0,
                    version=1,
                ))
        if not session.query(EventModel).filter_by(id="ev_final_2026").first():
            session.add(EventModel(
                id="ev_final_2026",
                name="Финал Кубка: Команда А vs Команда Б",
                status="OPEN",
            ))
        session.commit()


def reset_db():
    Base.metadata.drop_all(engine)
    init_db()

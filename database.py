from datetime import datetime
import uuid
from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Integer, String, Text, UniqueConstraint, create_engine
)
from sqlalchemy.orm import declarative_base, sessionmaker

DB_URL = "sqlite:///burmalda_platform.db"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()


# =============================================================================
# 1. ТАБЛИЦЫ КОНТУРА РЕГУЛЯТОРА И ЭСКРОУ (:5001)
# =============================================================================
class ClientModel(Base):
    __tablename__ = "clients"
    id = Column(String(64), primary_key=True)
    kyc_status = Column(String(32), nullable=False, default="VERIFIED")
    pd_blob = Column(Text, nullable=False)
    # Публичные ключи клиента по конторам: {"bk_alpha": "hex", ...}.
    # Приватные части регулятор отдал клиенту и у себя не хранит —
    # иначе он мог бы подписывать заявки от его имени.
    book_public_keys = Column(Text, nullable=False, default="{}")
    # ЭТАП 2: флаги допуска лежат открыто и это осознанно — булевы значения
    # не являются персональными данными. Именно их отдаёт регулятор
    # букмекеру при проверке токена, а имя и паспорт остаются в pd_blob
    # под ключом, разрезанным Шамиром.
    adult = Column(Boolean, nullable=False, default=True)
    not_excluded = Column(Boolean, nullable=False, default=True)
    limits_ok = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class LinkModel(Base):
    """Зашифрованная таблица соответствия: Токен (публичный) <-> Запечатанный client_id."""
    __tablename__ = "links"
    token = Column(String(128), primary_key=True)
    bookmaker_id = Column(String(64), nullable=False, index=True)
    client_ref_sealed = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class CustodyShareModel(Base):
    """Хранилище собственной доли ключа Регулятора (#2 из 3)."""
    __tablename__ = "custody_shares"
    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(String(64), nullable=False, index=True)
    party = Column(String(32), nullable=False)
    payload = Column(Text, nullable=False)


class AccountModel(Base):
    """Все балансы строго в целых копейках (BigInteger / int64). Никаких float!"""
    __tablename__ = "accounts"
    id = Column(String(64), primary_key=True)
    owner_type = Column(String(32), nullable=False)
    owner_ref = Column(String(128), nullable=False, unique=True, index=True)
    available = Column(BigInteger, nullable=False, default=0)
    held = Column(BigInteger, nullable=False, default=0)
    version = Column(Integer, nullable=False, default=1)


class LedgerEntryModel(Base):
    """Двойная бухгалтерская запись: каждая транзакция создает DEBIT и CREDIT на одну сумму."""
    __tablename__ = "ledger_entries"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tx_id = Column(String(64), nullable=False, index=True)
    account_id = Column(String(64), nullable=False, index=True)
    direction = Column(String(16), nullable=False)  # 'DEBIT' или 'CREDIT'
    amount = Column(BigInteger, nullable=False)     # В целых копейках
    created_at = Column(DateTime, default=datetime.utcnow)


class HoldModel(Base):
    """Атомарные холды: заморозка ставки клиента и чистого риска букмекера."""
    __tablename__ = "holds"
    id = Column(String(64), primary_key=True)
    owner_ref = Column(String(128), nullable=False, index=True)
    amount = Column(BigInteger, nullable=False)
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, RELEASED, CAPTURED
    hold_type = Column(String(32), nullable=False)                 # CLIENT_STAKE, BOOKMAKER_RISK
    ref_id = Column(String(64), nullable=False)


class RegulatorBetModel(Base):
    __tablename__ = "regulator_bets"
    id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=False, index=True)
    bookmaker_id = Column(String(64), nullable=False)
    event_id = Column(String(64), nullable=False)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default="ACCEPTED")
    client_hold_id = Column(String(64), nullable=False)
    bookmaker_hold_id = Column(String(64), nullable=False)
    placed_at = Column(DateTime, default=datetime.utcnow)


class EventModel(Base):
    __tablename__ = "events"
    id = Column(String(64), primary_key=True)
    name = Column(String(256), nullable=False)
    status = Column(String(32), nullable=False, default="OPEN")
    outcome = Column(String(64), nullable=True)
    # ЭТАП 3: исход приходит от оракула подписанным. Регулятор не может
    # объявить результат сам — иначе он бы «назначал» нужный исход
    # и перераспределял деньги.
    outcome_source = Column(String(64), nullable=False, default="")
    outcome_sig = Column(Text, nullable=False, default="")
    settled_at = Column(DateTime, nullable=True)


class SettlementModel(Base):
    """
    ЭТАП 3: подписанная регулятором расчётная квитанция по каждой ставке.

    Клиент и букмекер могут предъявить её как доказательство того, что
    и сколько было выплачено. Подпись Ed25519 над каноническим JSON.
    """
    __tablename__ = "settlements"
    id = Column(String(64), primary_key=True)
    bet_id = Column(String(64), nullable=False, index=True)
    token = Column(String(128), nullable=False)
    event_id = Column(String(64), nullable=False)
    outcome = Column(String(64), nullable=False)
    result = Column(String(32), nullable=False)        # WON, LOST, VOIDED
    amount = Column(BigInteger, nullable=False)        # движение по счёту клиента, в копейках
    regulator_sig = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditAnchorModel(Base):
    """
    ЭТАП 3: опубликованный корень хэш-цепочки.

    Пока корень не опубликован, журнал теоретически можно переписать
    целиком. После публикации подделка становится заметной: достаточно
    сверить пересчитанный корень с тем, что подписан и сохранён здесь.
    """
    __tablename__ = "audit_anchors"
    id = Column(Integer, primary_key=True, autoincrement=True)
    seq = Column(Integer, nullable=False)
    root_hash = Column(String(128), nullable=False)
    signature = Column(Text, nullable=False)
    ts = Column(String(32), nullable=False)


class DisclosureModel(Base):
    """ЭТАП 4: заявка на раскрытие. Одна заявка — одна запись, не вся база."""
    __tablename__ = "disclosures"
    id = Column(String(64), primary_key=True)
    subject = Column(String(128), nullable=False)          # токен, по которому идёт запрос
    subject_client_id = Column(String(64), nullable=False, default="")
    kind = Column(String(32), nullable=False, default="AML")   # AML, DISPUTE, KEY_RECOVERY
    requester = Column(String(64), nullable=False, default="audit_department")
    reason = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="PENDING_SECOND_SHARE")
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)


class DisclosureShareModel(Base):
    __tablename__ = "disclosure_shares"
    id = Column(Integer, primary_key=True, autoincrement=True)
    disclosure_id = Column(String(64), nullable=False, index=True)
    party = Column(String(32), nullable=False)
    payload = Column(Text, nullable=False)
    # ЭТАП 4: подпись стороны над (disclosure_id, party, payload).
    # Нужна, чтобы потом можно было доказать, КТО именно согласился
    # на раскрытие, и чтобы никто не подложил чужую долю от его имени.
    signature = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint("disclosure_id", "party", name="uq_disc_party"),)


class AuditLogModel(Base):
    __tablename__ = "audit_log"
    seq = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(String(32), nullable=False)
    actor = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    # ЭТАП 3: сам payload тоже сохраняем. Без него проверить можно только
    # связность цепочки, но не то, что содержимое записи не подменили.
    payload_json = Column(Text, nullable=False, default="{}")
    payload_hash = Column(String(128), nullable=False)
    prev_hash = Column(String(128), nullable=False)
    current_hash = Column(String(128), nullable=False)


# =============================================================================
# 2. ТАБЛИЦЫ КОНТУРА БУКМЕКЕРА (:5002) — БЕЗ КОЛОНОК ПДн И ПАСПОРТОВ
# =============================================================================
class BmTokenExposureModel(Base):
    __tablename__ = "bm_token_exposure"
    token = Column(String(128), primary_key=True)
    bets_count = Column(Integer, nullable=False, default=0)
    total_staked = Column(BigInteger, nullable=False, default=0)
    won_count = Column(Integer, nullable=False, default=0)


class BmQuoteModel(Base):
    """
    ЭТАП 2: котировка букмекера.

    Живёт между запросом коэффициента и подачей ставки. Клиент подписывает
    именно quote_id, поэтому букмекер не может подменить коэффициент после
    того, как клиент согласился.
    """
    __tablename__ = "bm_quotes"
    id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=False, index=True)
    bookmaker_id = Column(String(64), nullable=False, default="bk_alpha")
    event_id = Column(String(64), nullable=False)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    odds_commitment = Column(String(128), nullable=False)
    odds_salt = Column(String(64), nullable=False)      # раскрывается после исхода
    status = Column(String(32), nullable=False, default="OPEN")  # OPEN, USED, EXPIRED
    created_at = Column(DateTime, default=datetime.utcnow)


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
    # ЭТАП 2: соль обязательства и подпись клиента по его токену.
    # Соль пустая, пока событие не рассчитано, — в этом и смысл обязательства.
    odds_salt = Column(String(64), nullable=False, default="")
    client_sig = Column(Text, nullable=False, default="")
    status = Column(String(32), nullable=False, default="ACCEPTED")
    bookmaker_sig = Column(Text, nullable=False)


# =============================================================================
# 3. ТАБЛИЦЫ ЛОКАЛЬНОГО КОШЕЛЬКА КЛИЕНТА (:5003)
# =============================================================================
class WalletStateModel(Base):
    __tablename__ = "wallet_state"
    client_id = Column(String(64), primary_key=True)
    full_name = Column(String(256), nullable=False)
    passport = Column(String(64), nullable=False)
    age = Column(Integer, nullable=False)
    # Приватные ключи подписи по конторам: {"bk_alpha": "hex", ...}.
    # Живут ТОЛЬКО здесь, в кошельке клиента. В проде это Keychain на iOS
    # или Keystore на Android, а не строка в базе: в SQLite они лежат лишь
    # потому, что все четыре сервиса в демо работают в одном процессе.
    book_private_keys = Column(Text, nullable=False, default="{}")
    client_share = Column(Text, nullable=False)
    credential_id = Column(String(64), nullable=False)
    # Справки допуска по конторам: {"bk_alpha": {...}, ...}
    credentials_blob = Column(Text, nullable=False, default="{}")
    token_alpha = Column(String(128), nullable=False)
    token_beta = Column(String(128), nullable=False)
    zk_alpha = Column(Text, nullable=False)
    zk_beta = Column(Text, nullable=False)


class WalletReceiptModel(Base):
    __tablename__ = "wallet_receipts"
    bet_id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=False)
    selection = Column(String(64), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    bookmaker_sig = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# =============================================================================
# 4. ТАБЛИЦЫ НЕЗАВИСИМОГО АРБИТРА (:5004)
# =============================================================================
class ArbiterShareModel(Base):
    __tablename__ = "arbiter_shares"
    client_id = Column(String(64), primary_key=True)
    share_payload = Column(Text, nullable=False)


class ArbiterAuditModel(Base):
    __tablename__ = "arbiter_audit"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(String(32), nullable=False)
    action = Column(String(64), nullable=False)
    details = Column(Text, nullable=False)


def init_db(reset: bool = False):
    if reset:
        Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as session:
        for owner_type, owner_ref in [
            ("bookmaker", "bookmaker:bk_alpha"),
            ("house", "house:fees"),
            ("external", "external:bank"),
        ]:
            if not session.query(AccountModel).filter_by(owner_ref=owner_ref).first():
                session.add(AccountModel(
                    id=f"acc_{uuid.uuid4().hex[:8]}",
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

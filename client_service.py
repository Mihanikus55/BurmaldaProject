# client_service.py
import json
import uuid
from datetime import datetime

import requests
from flask import Flask, jsonify, request
from sqlalchemy import BigInteger, Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from common_ports import (
    CredentialService, NoopCredentialService, NoopSignerVerifier,
    NoopTokenPolicy, SignerVerifier, TokenPolicy
)

ClientBase = declarative_base()


class WalletIdentityModel(ClientBase):
    """Локальное защищённое хранилище клиента: секрет s, доля ключа и BBS+ справка."""
    __tablename__ = "wallet_identity"
    client_id = Column(String(64), primary_key=True)
    client_secret_s = Column(String(128), nullable=False)
    client_share = Column(Text, nullable=False)
    credential_json = Column(Text, nullable=True)


class WalletTokenModel(ClientBase):
    __tablename__ = "wallet_tokens"
    bookmaker_id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=False)
    zk_token_proof = Column(Text, nullable=False)


class WalletReceiptModel(ClientBase):
    __tablename__ = "wallet_receipts"
    bet_id = Column(String(64), primary_key=True)
    bookmaker_id = Column(String(64), nullable=False)
    token = Column(String(128), nullable=False)
    stake = Column(BigInteger, nullable=False)
    odds = Column(String(32), nullable=False)
    receipt_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ClientService:
    def __init__(
        self,
        regulator_url: str,
        arbiter_url: str,
        db_url: str = "sqlite:///client_wallet.db",
        signer: SignerVerifier = None,
        token_policy: TokenPolicy = None,
        cred_service: CredentialService = None,
    ):
        self.regulator_url = regulator_url.rstrip("/")
        self.arbiter_url = arbiter_url.rstrip("/")
        self.app = Flask("ClientWalletService")
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

        self.signer = signer or NoopSignerVerifier()
        self.token_policy = token_policy or NoopTokenPolicy()
        self.cred_service = cred_service or NoopCredentialService()

        ClientBase.metadata.create_all(self.engine)
        self._register_routes()

    # -------------------------------------------------------------------------
    # ВЫСОКОУРОВНЕВЫЕ PYTHON-МЕТОДЫ КЛИЕНТСКОГО КОШЕЛЬКА
    # -------------------------------------------------------------------------
    def register(self, full_name: str, passport: str, age: int = 25) -> dict:
        """Регистрация у регулятора, получение секрета s, доли ключа и BBS+ удостоверения."""
        resp = requests.post(
            f"{self.regulator_url}/v1/clients",
            json={"full_name": full_name, "passport": passport, "age": age},
            timeout=5,
        )
        resp.raise_for_status()
        reg_data = resp.json()

        client_id = reg_data["client_id"]
        client_secret = reg_data["client_secret"]
        client_share = reg_data["client_share"]
        arbiter_share = reg_data["arbiter_share"]

        # Передаём третью резервную долю ключа независимому арбитру
        requests.post(
            f"{self.arbiter_url}/v1/custody/store",
            json={"client_id": client_id, "arbiter_share": arbiter_share},
            timeout=5,
        ).raise_for_status()

        # Получаем от регулятора подписанную справку (BBS+ credential)
        cred_resp = requests.post(
            f"{self.regulator_url}/v1/credentials/issue",
            json={"client_id": client_id, "client_secret": client_secret},
            timeout=5,
        )
        cred_resp.raise_for_status()
        credential = cred_resp.json()

        with self.SessionLocal() as session:
            session.merge(WalletIdentityModel(
                client_id=client_id,
                client_secret_s=client_secret,
                client_share=client_share,
                credential_json=json.dumps(credential),
            ))
            session.commit()

        return {"client_id": client_id, "credential_id": credential["cred_id"]}

    def deposit(self, amount_kopecks: int) -> dict:
        """Пополнение счёта у регулятора (от имени client_id, токен здесь НЕ фигурирует)."""
        with self.SessionLocal() as session:
            ident = session.query(WalletIdentityModel).first()
            resp = requests.post(
                f"{self.regulator_url}/v1/accounts/client:{ident.client_id}/deposit",
                json={"amount": amount_kopecks, "idempotency_key": f"dep_{uuid.uuid4().hex[:10]}"},
                timeout=5,
            )
            resp.raise_for_status()
            return resp.json()

    def get_balance(self) -> dict:
        with self.SessionLocal() as session:
            ident = session.query(WalletIdentityModel).first()
            resp = requests.get(
                f"{self.regulator_url}/v1/accounts/client:{ident.client_id}",
                timeout=5,
            )
            resp.raise_for_status()
            return resp.json()

    def get_or_create_token(self, bookmaker_id: str) -> tuple[str, str]:
        """
        Вычисляет уникальный несвязываемый токен P_B = s * H_B для конкретного букмекера.
        Для двух разных контор (BK_ALPHA и BK_BETA) токены будут совершенно разными!
        """
        with self.SessionLocal() as session:
            tok_rec = session.query(WalletTokenModel).filter_by(bookmaker_id=bookmaker_id).first()
            if tok_rec:
                return tok_rec.token, tok_rec.zk_token_proof

            ident = session.query(WalletIdentityModel).first()
            resp = requests.post(
                f"{self.regulator_url}/v1/tokens",
                json={
                    "client_id": ident.client_id,
                    "bookmaker_id": bookmaker_id,
                    "client_secret": ident.client_secret_s,
                },
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            session.add(WalletTokenModel(
                bookmaker_id=bookmaker_id,
                token=data["token"],
                zk_token_proof=data["zk_token_proof"],
            ))
            session.commit()
            return data["token"], data["zk_token_proof"]

    def place_bet(self, bookmaker_id: str, bookmaker_url: str, event_id: str, selection: str, stake_kopecks: int) -> dict:
        """
        Полный цикл ставки (шаги 1-10):
        Клиент общается с букмекером ТОЛЬКО через токен (client_id никогда не покидает кошелёк!).
        """
        bk_url = bookmaker_url.rstrip("/")
        token, zk_token_proof = self.get_or_create_token(bookmaker_id)

        # Шаг 1: Запрос котировки у букмекера под токеном
        q_resp = requests.post(
            f"{bk_url}/v1/quotes",
            json={
                "token": token,
                "event_id": event_id,
                "selection": selection,
                "stake": stake_kopecks,
                "zk_token_proof": zk_token_proof,
            },
            timeout=5,
        )
        q_resp.raise_for_status()
        quote = q_resp.json()

        with self.SessionLocal() as session:
            ident = session.query(WalletIdentityModel).first()
            credential = json.loads(ident.credential_json)

            # [CRYPTO HOOK — ЭТАП 2.3 (M4): Формирование BBS+ презентации («18+, KYC пройден»)]
            presentation = self.cred_service.create_presentation(credential, token, bookmaker_id)

            # [CRYPTO HOOK — ЭТАП 2.4 (M1): Подпись параметров ставки ключом клиента]
            bet_payload = {
                "quote_id": quote["quote_id"],
                "token": token,
                "event_id": event_id,
                "selection": selection,
                "stake": stake_kopecks,
                "odds": quote["odds"],
            }
            client_sig = self.signer.sign(token, ident.client_secret_s, bet_payload)

            # Шаг 6: Отправка подписанной ставки букмекеру
            b_resp = requests.post(
                f"{bk_url}/v1/bets",
                json={
                    "quote_id": quote["quote_id"],
                    "token": token,
                    "credential_presentation": presentation,
                    "client_sig": client_sig,
                },
                timeout=5,
            )
            b_resp.raise_for_status()
            bet_result = b_resp.json()

            # Проверяем подпись квитанции букмекера и сохраняем её локально
            receipt = bet_result["receipt"]
            if not self.signer.verify(bookmaker_id, "", receipt["payload"], receipt["bookmaker_sig"]):
                raise RuntimeError("Invalid bookmaker receipt signature!")

            session.add(WalletReceiptModel(
                bet_id=bet_result["bet_id"],
                bookmaker_id=bookmaker_id,
                token=token,
                stake=stake_kopecks,
                odds=quote["odds"],
                receipt_json=json.dumps(receipt),
            ))
            session.commit()
            return bet_result

    def approve_disclosure(self, request_id: str) -> dict:
        """Добровольная передача доли клиента регулятору (например, при споре с букмекером)."""
        with self.SessionLocal() as session:
            ident = session.query(WalletIdentityModel).first()
            resp = requests.post(
                f"{self.regulator_url}/v1/disclosures/{request_id}/shares",
                json={"party": "client", "payload": ident.client_share},
                timeout=5,
            )
            resp.raise_for_status()
            return resp.json()

    def _register_routes(self):
        @self.app.route("/v1/wallet/register", methods=["POST"])
        def api_register():
            d = request.json or {}
            return jsonify(self.register(d["full_name"], d["passport"], int(d.get("age", 25)))), 201

        @self.app.route("/v1/wallet/deposit", methods=["POST"])
        def api_deposit():
            return jsonify(self.deposit(int(request.json["amount"])))

        @self.app.route("/v1/wallet/balance", methods=["GET"])
        def api_balance():
            return jsonify(self.get_balance())

        @self.app.route("/v1/wallet/place-bet", methods=["POST"])
        def api_place_bet():
            d = request.json or {}
            res = self.place_bet(d["bookmaker_id"], d["bookmaker_url"], d["event_id"], d["selection"], int(d["stake"]))
            return jsonify(res), 201

        @self.app.route("/v1/wallet/disclosures/<req_id>/approve", methods=["POST"])
        def api_approve_disclosure(req_id):
            return jsonify(self.approve_disclosure(req_id))
# arbiter_service.py
import uuid
from datetime import datetime

import requests
from flask import Flask, jsonify, request
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

ArbiterBase = declarative_base()


class ArbiterShareModel(ArbiterBase):
    """Хранилище третьей резервной доли ключа на стороне независимого арбитра."""
    __tablename__ = "arbiter_shares"
    client_id = Column(String(64), primary_key=True)
    token = Column(String(128), nullable=True, index=True)
    share_payload = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ArbiterDisputeModel(ArbiterBase):
    __tablename__ = "arbiter_disputes"
    id = Column(String(64), primary_key=True)
    bet_id = Column(String(64), nullable=False)
    claim = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="OPEN")
    created_at = Column(DateTime, default=datetime.utcnow)


class ArbiterAuditModel(ArbiterBase):
    __tablename__ = "arbiter_audit"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, default=datetime.utcnow)
    action = Column(String(64), nullable=False)
    details = Column(Text, nullable=False)


class ArbiterService:
    def __init__(self, regulator_url: str, db_url: str = "sqlite:///arbiter.db"):
        self.regulator_url = regulator_url.rstrip("/")
        self.app = Flask("ArbiterService")
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
        ArbiterBase.metadata.create_all(self.engine)
        self._register_routes()

    def _register_routes(self):
        @self.app.route("/v1/health", methods=["GET"])
        def health():
            return jsonify({"service": "arbiter", "status": "OK"})

        @self.app.route("/v1/custody/store", methods=["POST"])
        def store_third_share():
            data = request.json or {}
            with self.SessionLocal() as session:
                session.merge(ArbiterShareModel(
                    client_id=data["client_id"],
                    token=data.get("token"),
                    share_payload=data["arbiter_share"],
                ))
                session.add(ArbiterAuditModel(
                    action="SHARE_STORED", details=f"client_id={data['client_id']}"
                ))
                session.commit()
            return jsonify({"stored": True}), 201

        @self.app.route("/v1/disclosures/<disclosure_id>/approve", methods=["POST"])
        def approve_disclosure(disclosure_id):
            data = request.json or {}
            reason = data.get("reason", "Законное требование / восстановление доступа")
            client_id = data.get("client_id")
            token = data.get("token")

            with self.SessionLocal() as session:
                q = session.query(ArbiterShareModel)
                share_rec = q.filter_by(client_id=client_id).first() if client_id else q.filter_by(token=token).first()
                if not share_rec:
                    share_rec = q.first()
                if not share_rec:
                    return jsonify({"error": "SHARE_NOT_FOUND"}), 404

                # [CRYPTO HOOK — ЭТАП 5 (M5): Пороговое дешифрование + Доказательство Шаума-Педерсена]
                # Вместо отправки самой доли x_3 арбитр берет точку R из записи регулятора,
                # вычисляет частичное дешифрование d_3 = x_3 * R и прикладывает ZK-доказательство
                # Шаума-Педерсена, что d_3 вычислено честно.
                resp = requests.post(
                    f"{self.regulator_url}/v1/disclosures/{disclosure_id}/shares",
                    json={"party": "arbiter", "payload": share_rec.share_payload},
                    timeout=5,
                )
                session.add(ArbiterAuditModel(
                    action="DISCLOSURE_APPROVED",
                    details=f"disclosure_id={disclosure_id}, reason={reason}",
                ))
                session.commit()
                return jsonify(resp.json()), resp.status_code

        @self.app.route("/v1/disclosures/<disclosure_id>/deny", methods=["POST"])
        def deny_disclosure(disclosure_id):
            data = request.json or {}
            with self.SessionLocal() as session:
                session.add(ArbiterAuditModel(
                    action="DISCLOSURE_DENIED",
                    details=f"disclosure_id={disclosure_id}, reason={data.get('reason', '')}",
                ))
                session.commit()
            return jsonify({"disclosure_id": disclosure_id, "decision": "DENIED"})

        @self.app.route("/v1/disputes", methods=["POST"])
        def create_dispute():
            data = request.json or {}
            dispute_id = f"disp_{uuid.uuid4().hex[:8]}"
            with self.SessionLocal() as session:
                session.add(ArbiterDisputeModel(
                    id=dispute_id, bet_id=data["bet_id"], claim=data["claim"], status="OPEN"
                ))
                session.commit()
            return jsonify({"dispute_id": dispute_id, "status": "OPEN"}), 201

        @self.app.route("/v1/audit", methods=["GET"])
        def get_audit():
            with self.SessionLocal() as session:
                logs = session.query(ArbiterAuditModel).all()
                return jsonify([{"id": l.id, "action": l.action, "details": l.details} for l in logs])
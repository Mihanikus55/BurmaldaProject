"""
База данных. У КАЖДОГО сервиса своя, отдельным файлом SQLite.

Это принципиально, а не для удобства: смысл схемы в том, что ни одна
сторона не владеет полной картиной. Общая база обнулила бы всю конструкцию,
и демонстрация доказывала бы только то, что мы умеем писать SQL.

Файлы лежат в ./data/ и в git не попадают.
"""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def make_db(service_name: str):
    """Движок, базовый класс моделей и фабрика сессий для одного сервиса."""
    DATA_DIR.mkdir(exist_ok=True)
    engine = create_engine(
        f"sqlite:///{DATA_DIR / (service_name + '.db')}",
        connect_args={"check_same_thread": False},
    )
    Base = declarative_base()
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    return engine, Base, SessionLocal

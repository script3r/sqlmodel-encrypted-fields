from __future__ import annotations

from sqlmodel import Session, SQLModel, create_engine

engine = create_engine("sqlite:///./example_app_fastapi.db", echo=False)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Session:
    return Session(engine)

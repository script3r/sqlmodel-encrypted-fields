from __future__ import annotations

from sqlmodel import Session, create_engine

from example_app_flask.models import Customer

engine = create_engine("sqlite:///./example_app_flask.db", echo=False)


def init_db() -> None:
    Customer.metadata.create_all(engine)


def get_session() -> Session:
    return Session(engine)

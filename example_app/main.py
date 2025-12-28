from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from sqlmodel import Session, select

from example_app.database import get_session, init_db
from example_app.models import Customer
from sqlmodel_encrypted_fields import configure_keysets

@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_keysets(
        {
            "default": {"path": "./tests/fixtures/aead_keyset.json", "cleartext": True},
            "deterministic": {"path": "./tests/fixtures/daead_keyset.json", "cleartext": True},
        }
    )
    init_db()
    yield


app = FastAPI(title="SQLModel Encrypted Fields Example", lifespan=lifespan)


@app.post("/customers", response_model=Customer)
def create_customer(customer: Customer, session: Session = Depends(get_session)) -> Customer:
    session.add(customer)
    session.commit()
    session.refresh(customer)
    return customer


@app.get("/customers/{customer_id}", response_model=Customer)
def get_customer(customer_id: int, session: Session = Depends(get_session)) -> Customer:
    customer = session.get(Customer, customer_id)
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer


@app.get("/customers/by-email/{email}", response_model=Customer)
def get_customer_by_email(email: str, session: Session = Depends(get_session)) -> Customer:
    statement = select(Customer).where(Customer.email_lookup == email)
    customer = session.exec(statement).first()
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer

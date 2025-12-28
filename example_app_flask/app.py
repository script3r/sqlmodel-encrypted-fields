from __future__ import annotations

from flask import Flask, jsonify, request
from sqlmodel import Session, select

from example_app_flask.database import get_session, init_db
from example_app_flask.models import Customer


def create_app() -> Flask:
    app = Flask(__name__)

    @app.before_first_request
    def _init_db() -> None:
        init_db()

    @app.post("/customers")
    def create_customer():
        payload = request.get_json(force=True)
        customer = Customer(**payload)
        with get_session() as session:
            session.add(customer)
            session.commit()
            session.refresh(customer)
            return jsonify(customer.model_dump())

    @app.get("/customers/<int:customer_id>")
    def get_customer(customer_id: int):
        with get_session() as session:
            customer = session.get(Customer, customer_id)
            if customer is None:
                return jsonify({"detail": "Customer not found"}), 404
            return jsonify(customer.model_dump())

    @app.get("/customers/by-email/<string:email>")
    def get_customer_by_email(email: str):
        with get_session() as session:
            statement = select(Customer).where(Customer.email_lookup == email)
            customer = session.exec(statement).first()
            if customer is None:
                return jsonify({"detail": "Customer not found"}), 404
            return jsonify(customer.model_dump())

    return app


if __name__ == "__main__":
    create_app().run(debug=True)

import pytest
from backend import create_app, db

@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })

    with app.app_context():
        db.create_all()  # Create tables before each test
        yield app
        db.session.rollback()  # Ensure transactions are cleared
        db.session.remove()  # Clear the session
        db.drop_all()  # Drop tables after each test

@pytest.fixture
def client(app):
    return app.test_client()

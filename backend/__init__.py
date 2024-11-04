from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config, TestingConfig

# Create instances of SQLAlchemy and Migrate
db = SQLAlchemy()
migrate = Migrate()

def init_app(app):
    # Initialize the app with the database and migration
    db.init_app(app)
    migrate.init_app(app, db)

# App creator: using Factory pattern
def create_app(config_class=TestingConfig):  # Set TestingConfig as default for testing
    app = Flask(__name__)
    app.config.from_object(config_class)

    init_app(app)

    # Register blueprints with the correct URL prefix
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')  # Add /auth prefix here

    return app

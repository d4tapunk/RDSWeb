from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Create instances of SQLAlchemy and Migrate
db = SQLAlchemy()
migrate = Migrate()

def init_app(app):
    # Initialize the app with the database and migration
    db.init_app(app)
    migrate.init_app(app, db)

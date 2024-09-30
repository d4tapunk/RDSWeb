from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from config.config import rdswebDbConfig

app = Flask(__name__)

# Configuring the app for PostgreSQL and JWT

app.config.from_object(rdswebDbConfig)

db = SQLAlchemy(app)
jwt = JWTManager(app)


# Set up Flask-Migrate
migrate = Migrate(app, db)


if __name__ == "__main__":
    app.run(debug=True)

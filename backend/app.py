import os
from flask import Flask
from flask_jwt_extended import JWTManager
from config.config import Config
from backend import db, migrate, init_app  # Import from backend/__init__.py
from backend.auth import auth as auth_blueprint  # Import the auth blueprint


app = Flask(__name__, template_folder='../templates')


# Set the secret key for session handling (important for flashing messages)
app.secret_key = os.urandom(24)  # Generates a random secret key

# Configuring the app for PostgreSQL and JWT
app.config.from_object(Config)

# Initialize database and migration
init_app(app)

jwt = JWTManager(app)


# Register the auth blueprint
app.register_blueprint(auth_blueprint, url_prefix='/auth')

# Print the paths where Flask is looking for templates
print("Flask template search paths:", app.jinja_loader.searchpath)

if __name__ == "__main__":
    app.run(debug=True)
from dotenv import load_dotenv
import os
from flasgger import Swagger
from flask import Flask
from flask_jwt_extended import JWTManager
from config.config import Config
from backend import db, migrate, init_app  # Import from backend/__init__.py
from backend.auth import auth as auth_blueprint  # Import the auth blueprint
from backend.rateLimiter import initRateLimiter  # Correct the import path here

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, template_folder='../templates')

# Set Swagger options and template file for OpenAPI 3.0
swagger_file_path = os.path.abspath(os.path.join("config", "swagger.yml"))
app.config['SWAGGER'] = {
    'title': 'User Authentication and Profile Management API',
    'uiversion': 3,
    'openapi': '3.0.0'
}
swagger = Swagger(app, template_file=swagger_file_path)

# Set the secret key for session handling (important for flashing messages)
app.secret_key = os.getenv('SECRET_KEY')

# Set the JWT secret key
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

# Configuring the app for PostgreSQL and JWT
app.config.from_object(Config)

# Initialize database and migration
init_app(app)

# Initialize JWT manager
jwt = JWTManager(app)

# Rate Limiter
limiter = initRateLimiter(app)

# Register the auth blueprint
app.register_blueprint(auth_blueprint, url_prefix='/auth')

# Print the paths where Flask is looking for templates
print("Flask template search paths:", app.jinja_loader.searchpath)

# Run the app
if __name__ == "__main__":
    app.run(debug=True)

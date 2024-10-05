# backend/config/config.py
from dotenv import load_dotenv
import os

class Config:
    # Database URI with credentials
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'Merwebo'  # Change this key to something more secure

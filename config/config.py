# backend/config/config.py
import os

class Config:
    # Database URI with credentials
    SQLALCHEMY_DATABASE_URI = 'postgresql://d4tapunk:142536@localhost/rdsweb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'Merwebo'  # Change this key to something more secure

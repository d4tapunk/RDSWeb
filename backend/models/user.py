from flask_sqlalchemy import SQLAlchemy
from app import db
from datetime import datetime


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=True) 
    lastname = db.Column(db.String(50), nullable=True)  
    age = db.Column(db.Integer, nullable=True) 
    registration_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
from backend import db
from sqlalchemy import func
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Auto-incrementing integer
    customId = db.Column(db.String(50), unique=True, nullable=False)  # Store formatted custom ID
    userName = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=True)
    lastName = db.Column(db.String(50), nullable=True)
    age = db.Column(db.Integer, nullable=True)
    registrationDate = db.Column(db.DateTime, default=func.now(), nullable=False)
    resetToken = db.Column(db.String(512), nullable=True)
    tokenUsed = db.Column(db.Boolean, default=False)
    resetTokenCreatedAt = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        self.customId = self.generateCustomId()  # Generate the custom ID upon creation

    def generateCustomId(self):
        # Get the current year
        currentYear = datetime.now().year
        # Combine prefix, ID, and year (id is available only after commit)
        return f"RDS{self.id}{currentYear}"

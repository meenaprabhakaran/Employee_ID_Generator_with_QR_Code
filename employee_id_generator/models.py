from db_config import db
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    __tablename__ = 'users'  # Explicit table name

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # Update here
    role = db.Column(db.Enum('admin', 'user'), default='user', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<User {self.username}, Role: {self.role}>"

class Employee(db.Model):
    __tablename__ = 'employees'  

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    numeric_id = db.Column(db.BigInteger, unique=True, nullable=False)  
    phone = db.Column(db.String(15), nullable=True)  # Add phone field
    address = db.Column(db.String(255), nullable=True)  # Add address field
    qr_code_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  

    def __repr__(self):
        return f"<Employee {self.name}, ID: {self.numeric_id}>"


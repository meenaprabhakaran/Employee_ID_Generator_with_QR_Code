from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Database Configuration for MySQL Workbench
MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Root',  
    'database': 'employee_db'
}

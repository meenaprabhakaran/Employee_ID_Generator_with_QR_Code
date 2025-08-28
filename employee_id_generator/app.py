from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from db_config import db, MYSQL_CONFIG
from models import User, Employee
from datetime import datetime
import pymysql
import qrcode
import os
from io import BytesIO
import base64

app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{MYSQL_CONFIG['user']}:{MYSQL_CONFIG['password']}@{MYSQL_CONFIG['host']}/{MYSQL_CONFIG['database']}"
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) if user_id else None

@app.route('/')
def home():
    return render_template('home.html')

# ---------------------- User Registration ----------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered! Please log in.", "danger")
            return redirect(url_for('login'))

        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, email=email, password_hash=hashed_password, role="user")
            db.session.add(new_user)
            db.session.commit()

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f"Database Error: {str(e)}", "danger")

    return render_template('register.html')

# ---------------------- User Login ----------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password. Please try again.", "danger")

    return render_template('login.html')

# ---------------------- Dashboard ----------------------
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            # Ensure latest employees are fetched
            employees = db.session.execute(db.select(Employee)).scalars().all()

            return render_template('admin_dashboard.html', 
                                   user=current_user,
                                   employees=employees,
                                   current_time=datetime.now().timestamp())

        # For normal users, show only their QR Code
        employee = Employee.query.filter_by(email=current_user.email).first()
        if employee:
            qr_data = f"Name: {employee.name}\nEmail: {employee.email}\nEmployee ID: {employee.numeric_id}"
            qr = qrcode.make(qr_data)
            qr_io = BytesIO()
            qr.save(qr_io, format="PNG")
            qr_base64 = base64.b64encode(qr_io.getvalue()).decode('utf-8')

            return render_template('user_dashboard.html', 
                                   user=employee, 
                                   qr_code=qr_base64)

        flash("Employee details not found! Contact admin.", "danger")
        return redirect(url_for('login'))

    return redirect(url_for('login'))


# ---------------------- Unique Employee Name Handling ----------------------
def get_unique_employee_name(base_name):
    count = 1
    unique_name = base_name
    while Employee.query.filter_by(name=unique_name).first():
        unique_name = f"{base_name}{count}"
        count += 1
    return unique_name

# ---------------------- QR Code Generation Function ----------------------
def generate_qr_code(name, email, numeric_id, phone, address, role):
    qr_data = f"Name: {name}\nEmail: {email}\nEmployee ID: {numeric_id}\nPhone: {phone}\nAddress: {address}"

    qr_folder = os.path.join(app.static_folder, 'qrcodes')
    os.makedirs(qr_folder, exist_ok=True)

    qr_filename = f"{numeric_id}.png"
    qr_path = os.path.join(qr_folder, qr_filename)

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)

    qr_img = qr.make_image(fill='black', back_color='white')
    qr_img.save(qr_path)

    return f"qrcodes/{qr_filename}"


# ---------------------- Add Employee (with Auto QR Code) ----------------------
@app.route('/add_employee', methods=['GET', 'POST'])
@login_required
def add_employee():
    if current_user.role != 'admin':
        flash("You are not authorized to add employees.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name').strip()
        email = request.form.get('email').strip()
        phone = request.form.get('phone').strip()
        address = request.form.get('address').strip()

        if not name or not email or not phone or not address:
            flash("All fields are required!", "danger")
            return redirect(url_for('add_employee'))

        try:
            # Ensure unique name
            unique_name = get_unique_employee_name(name)

            # Generate numeric ID
            numeric_id = sum(ord(char) for char in unique_name)

            # Generate QR Code
            qr_code_path = generate_qr_code(unique_name, email, numeric_id, phone, address)

            # Save employee details
            employee = Employee(name=unique_name, email=email, numeric_id=numeric_id, phone=phone, address=address, qr_code_path=qr_code_path)
            db.session.add(employee)
            db.session.commit()

            # Debugging: Print confirmation in terminal
            print(f"Employee {unique_name} added successfully with ID {numeric_id}")

            flash("Employee added successfully!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            print(f"Error adding employee: {e}")  # Debugging output
            flash(f"Error: {str(e)}", "danger")

    return render_template('add_employee.html')

# ---------------------- Regenerate All QR Codes ----------------------
def generate_qr_code(name, email, numeric_id, phone, address):
    # Ensure all employee details are included in the QR code
    qr_data = f"Name: {name}\nEmployee ID: {numeric_id}\nEmail: {email}\nPhone: {phone}\nAddress: {address}"

    qr_folder = os.path.join(app.static_folder, 'qrcodes')
    os.makedirs(qr_folder, exist_ok=True)

    qr_filename = f"{numeric_id}.png"
    qr_path = os.path.join(qr_folder, qr_filename)

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)

    qr_img = qr.make_image(fill='black', back_color='white')
    qr_img.save(qr_path)

    return f"qrcodes/{qr_filename}"
# ---------------------- Scan QR Code ----------------------
@app.route('/scan_qr', methods=['POST'])
@login_required
def scan_qr():
    scanned_data = request.form.get('scanned_data')  # Get scanned QR data

    if current_user.role == 'admin':
        return render_template('scan_result.html', details=scanned_data)  # Show full details
    else:
        # Show limited details for regular users
        allowed_keys = ["Name", "Employee ID", "Email"]
        filtered_data = "\n".join([line for line in scanned_data.split("\n") if any(k in line for k in allowed_keys)])
        return render_template('scan_result.html', details=filtered_data)

# ---------------------- Logout ----------------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

# ---------------------- Run App ----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

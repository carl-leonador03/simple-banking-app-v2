# Developer: V.J. Ayuban
import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
import secrets
import pymysql
from flask_wtf.csrf import CSRFProtect
from flask_limiter.errors import RateLimitExceeded

# Load environment variables early
load_dotenv()

# Import extensions
from extensions import db, login_manager, bcrypt, limiter

# Initialize CSRF protection
csrf = CSRFProtect()

# MySQL connection
pymysql.install_as_MySQLdb()

def validate_env_variables():
    # Set default values if environment variables are missing
    os.environ.setdefault('MYSQL_USER', 'root')
    os.environ.setdefault('MYSQL_PASSWORD', '')  # Empty password for default MySQL installation
    os.environ.setdefault('MYSQL_HOST', 'localhost')
    os.environ.setdefault('MYSQL_DATABASE', 'simple_banking')
    os.environ.setdefault('SECRET_KEY', secrets.token_hex(16))
    os.environ.setdefault('FLASK_ENV', 'development')
    os.environ.setdefault('PORT', '5000')

def create_app():
    validate_env_variables()

    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

    # CSRF Protection
    csrf.init_app(app)

    # Database configuration
    mysql_user = os.environ.get('MYSQL_USER')
    mysql_password = os.environ.get('MYSQL_PASSWORD')
    mysql_host = os.environ.get('MYSQL_HOST')
    mysql_port = os.environ.get('MYSQL_PORT', '3306')
    mysql_database = os.environ.get('MYSQL_DATABASE')

    mysql_port = str(mysql_port)
    db_uri = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}"
    print(f"Database URI: {db_uri}")
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)

    # Register custom error handler for rate limiting
    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit_exceeded(e):
        if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
            return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429
        return render_template('rate_limit_error.html', message=str(e)), 429

    return app

# Create Flask app
app = create_app()

# Import models after db initialization
from models import User, Transaction

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import routes after app creation
from routes import *
from flask_limiter.util import get_remote_address

def init_db():
    """Initialize the database with required tables and default admin user."""
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            admin_user = User(
                username="admin",
                email="admin@bankapp.com",
                account_number="0000000001",
                status="active",
                is_admin=True,
                balance=0.0
            )
            admin_user.set_password("admin123")
            db.session.add(admin_user)
            db.session.commit()
            print("Created admin user with username 'admin' and password 'admin123'")

if __name__ == '__main__':
    print(f"Environment variables:")
    print(f"MYSQL_HOST: {os.environ.get('MYSQL_HOST')}")
    print(f"MYSQL_USER: {os.environ.get('MYSQL_USER')}")
    print(f"MYSQL_DATABASE: {os.environ.get('MYSQL_DATABASE')}")
    with app.app_context():
        db.create_all()
    app.run(debug=True)

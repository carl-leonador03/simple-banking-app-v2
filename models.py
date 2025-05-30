# Developer: V.J. Ayuban
from extensions import db, bcrypt
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import random
import string
import jwt
from datetime import timedelta
import os

def generate_account_number():
    """Generate a random 10-digit account number"""
    return ''.join(random.choices(string.digits, k=10))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(120), unique=True, index=True)
    firstname = db.Column(db.String(64), nullable=True)
    lastname = db.Column(db.String(64), nullable=True)
    # Detailed address fields
    address_line = db.Column(db.String(256), nullable=True)  # Street address, building, etc.
    region_code = db.Column(db.String(20), nullable=True)
    region_name = db.Column(db.String(100), nullable=True)
    province_code = db.Column(db.String(20), nullable=True)
    province_name = db.Column(db.String(100), nullable=True)
    city_code = db.Column(db.String(20), nullable=True)
    city_name = db.Column(db.String(100), nullable=True)
    barangay_code = db.Column(db.String(20), nullable=True)
    barangay_name = db.Column(db.String(100), nullable=True)
    postal_code = db.Column(db.String(10), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(128))
    account_number = db.Column(db.String(10), unique=True, default=generate_account_number)
    balance = db.Column(db.Float, default=1000.0)  # Match schema.sql default of 1000.0
    status = db.Column(db.String(20), default='pending')  # 'active', 'deactivated', or 'pending'
    is_admin = db.Column(db.Boolean, default=False)  # Admin status
    is_manager = db.Column(db.Boolean, default=False)  # Manager status (can manage admins)
    date_registered = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(100), nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(100), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)
    transactions_sent = db.relationship('Transaction', foreign_keys='Transaction.sender_id', backref='sender', lazy='dynamic')
    transactions_received = db.relationship('Transaction', foreign_keys='Transaction.receiver_id', backref='receiver', lazy='dynamic')
    login_history = db.relationship('LoginHistory', backref='user', lazy='dynamic')
    
    @property
    def full_address(self):
        """Return the full formatted address"""
        address_parts = []
        if self.address_line:
            address_parts.append(self.address_line)
        if self.barangay_name:
            address_parts.append(f"Barangay {self.barangay_name}")
        if self.city_name:
            address_parts.append(self.city_name)
        if self.province_name:
            address_parts.append(self.province_name)
        if self.region_name:
            address_parts.append(self.region_name)
        if self.postal_code:
            address_parts.append(self.postal_code)
        
        if address_parts:
            return ", ".join(address_parts)
        return "No address provided"
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        # Use bcrypt for secure password hashing with salt
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        # Use bcrypt to verify password
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def generate_password_reset_token(self):
        """Generate a password reset token"""
        token = jwt.encode(
            {
                'user_id': self.id,
                'exp': datetime.datetime.utcnow() + timedelta(hours=1)
            },
            os.environ.get('SECRET_KEY', 'default-secret-key'),
            algorithm='HS256'
        )
        self.password_reset_token = token
        self.password_reset_expires = datetime.datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        return token
    
    def verify_password_reset_token(self, token):
        """Verify password reset token"""
        try:
            data = jwt.decode(
                token,
                os.environ.get('SECRET_KEY', 'default-secret-key'),
                algorithms=['HS256']
            )
            return data['user_id'] == self.id
        except:
            return False
    
    def generate_email_verification_token(self):
        """Generate email verification token"""
        token = jwt.encode(
            {
                'user_id': self.id,
                'email': self.email,
                'exp': datetime.datetime.utcnow() + timedelta(days=1)
            },
            os.environ.get('SECRET_KEY', 'default-secret-key'),
            algorithm='HS256'
        )
        self.email_verification_token = token
        db.session.commit()
        return token
    
    def verify_email_token(self, token):
        """Verify email verification token"""
        try:
            data = jwt.decode(
                token,
                os.environ.get('SECRET_KEY', 'default-secret-key'),
                algorithms=['HS256']
            )
            return data['user_id'] == self.id and data['email'] == self.email
        except:
            return False
    
    @property
    def is_active(self):
        """Check if account is active and not locked"""
        if self.account_locked_until and self.account_locked_until > datetime.datetime.utcnow():
            return False
        return self.status == 'active'
    
    def record_failed_login(self):
        """Record a failed login attempt"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()
    
    def reset_failed_login_attempts(self):
        """Reset failed login attempts after successful login"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.last_login = datetime.datetime.utcnow()
        db.session.commit()
    
    def transfer_money(self, recipient, amount):
        """Transfer money to another user with enhanced security checks"""
        if not self.is_active:
            return False, "Account is not active or is locked"
        
        if self.balance < amount:
            return False, "Insufficient funds"
        
        if amount <= 0:
            return False, "Invalid amount"
        
        if not recipient.is_active:
            return False, "Recipient account is not active"
        
        # Create transaction record first
        transaction = Transaction(
            sender_id=self.id,
            receiver_id=recipient.id,
            amount=amount,
            transaction_type='transfer',
            timestamp=datetime.datetime.utcnow(),
            status='pending'
        )
        db.session.add(transaction)
        
        try:
            # Update balances
            self.balance -= amount
            recipient.balance += amount
            transaction.status = 'completed'
            db.session.commit()
            return True, "Transfer successful"
        except Exception as e:
            db.session.rollback()
            return False, f"Transfer failed: {str(e)}"
    
    def deposit(self, amount, admin_user):
        """Process an over-the-counter deposit with enhanced security"""
        if not self.is_active:
            return False, "Account is not active"
        
        if amount <= 0:
            return False, "Invalid amount"
        
        if not admin_user.is_admin:
            return False, "Only admins can process deposits"
        
        try:
            # Create transaction record
            transaction = Transaction(
                sender_id=admin_user.id,
                receiver_id=self.id,
                amount=amount,
                transaction_type='deposit',
                timestamp=datetime.datetime.utcnow(),
                status='pending'
            )
            db.session.add(transaction)
            
            # Update balance
            self.balance += amount
            transaction.status = 'completed'
            db.session.commit()
            return True, "Deposit successful"
        except Exception as e:
            db.session.rollback()
            return False, f"Deposit failed: {str(e)}"
    
    def get_recent_transactions(self, limit=10):
        """Get recent transactions with enhanced filtering"""
        sent = self.transactions_sent.filter(
            Transaction.transaction_type != 'user_edit',
            Transaction.status == 'completed'
        ).order_by(Transaction.timestamp.desc()).limit(limit).all()
        
        received = self.transactions_received.filter(
            Transaction.transaction_type != 'user_edit',
            Transaction.status == 'completed'
        ).order_by(Transaction.timestamp.desc()).limit(limit).all()
        
        all_transactions = sorted(sent + received, key=lambda x: x.timestamp, reverse=True)
        return all_transactions[:limit]
    
    def activate_account(self):
        """Activate a user account with verification"""
        if self.status == 'pending':
            self.status = 'active'
            self.email_verified = True
            db.session.commit()
            return True
        return False
    
    def deactivate_account(self):
        """Deactivate a user account with verification"""
        if self.status == 'active':
            self.status = 'deactivated'
            db.session.commit()
            return True
        return False
    
    def is_account_manager(self):
        """Check if user is a manager"""
        return self.is_manager
    
    def can_manage_user(self, user):
        """Enhanced role-based access control"""
        if self.is_manager:
            return not user.is_manager  # Managers can't manage other managers
        if self.is_admin:
            return not user.is_admin and not user.is_manager
        return False

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    transaction_type = db.Column(db.String(20), default='transfer')
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    details = db.Column(db.Text, nullable=True)
    reference_number = db.Column(db.String(50), unique=True)
    
    def __init__(self, **kwargs):
        super(Transaction, self).__init__(**kwargs)
        self.reference_number = self.generate_reference_number()
    
    def generate_reference_number(self):
        """Generate a unique reference number for the transaction"""
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"TRX-{timestamp}-{random_suffix}"
    
    def __repr__(self):
        return f'<Transaction {self.reference_number} - {self.amount}>'

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(256))
    success = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<LoginHistory {self.user_id} - {self.timestamp}>' 
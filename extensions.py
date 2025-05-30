# Developer: V.J. Ayuban
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_migrate import Migrate
from flask_session import Session
from flask_talisman import Talisman
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize SQLAlchemy
db = SQLAlchemy()

# Initialize Login Manager with enhanced security
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong'

# Initialize Bcrypt with enhanced security
bcrypt = Bcrypt()

# Initialize Flask-Mail
mail = Mail()

# Initialize Flask-Migrate for database migrations
migrate = Migrate()

# Initialize Flask-Session
session = Session()

# Initialize Flask-Talisman for security headers
talisman = Talisman(
    force_https=False,  # Set to True in production
    strict_transport_security=True,
    session_cookie_secure=False,  # Set to True in production
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline' 'unsafe-eval'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data:",
        'font-src': "'self'",
    }
)

# Helper function to check if user is exempt from rate limits
def is_rate_limit_exempt():
    if not current_user.is_authenticated:
        return False
    return current_user.is_admin or current_user.is_manager or current_user.status == 'active'

# Initialize rate limiter with enhanced security
storage_uri = os.environ.get('REDIS_URL', 'memory://')

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=storage_uri,
    strategy="fixed-window",
    default_limits_deduct_when=lambda response: response.status_code < 400,
    default_limits_exempt_when=is_rate_limit_exempt,
    headers_enabled=True,
    swallow_errors=True,
    enabled=True
) 
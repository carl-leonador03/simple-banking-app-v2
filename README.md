# Simple Banking App

A user-friendly and responsive Flask-based banking application designed for deployment on PythonAnywhere. This application allows users to create accounts, perform simulated money transfers between accounts, view transaction history, and securely manage their credentials.

# LINK
https://moxenel106.pythonanywhere.com/

## Features

- **User Authentication**
  - Secure login with username/password
  - Registration of new users
  - Password recovery mechanism (email-based)

- **Account Management**
  - Display of account balance
  - View recent transaction history (last 10 transactions)

- **Fund Transfer**
  - Transfer money to other registered users
  - Confirmation screen before completing transfers
  - Transaction history updated after transfers

- **User Role Management**
  - Regular user accounts
  - Admin users with account approval capabilities
  - Manager users who can manage admin accounts

- **Location Data Integration**
  - Philippine Standard Geographic Code (PSGC) API integration
  - Hierarchical location data selection (Region, Province, City, Barangay)
  - Form fields pre-populated with location data

- **Admin Features**
  - User account approval workflow
  - Account activation/deactivation
  - Deposit funds to user accounts
  - Create new accounts
  - Edit user information

- **Manager Features**
  - Create and manage admin accounts
  - View admin transaction logs
  - Monitor all system transfers

- **Security**
  - Password hashing with bcrypt for secure storage
  - Secure session management
  - Token-based password reset
  - API rate limiting to prevent abuse
  - CSRF protection for all forms

## New Features and Improvements

### Enhanced User Management
- **Advanced Role System**
  - Hierarchical permissions: Manager > Admin > Regular User
  - Clear role separation with visual indicators
  - Role-specific dashboards and interfaces

### Improved Security
- **Modern Password Handling**
  - Upgraded from SHA-256 to Bcrypt hashing
  - Automatic migration of old password hashes
  - Enhanced password reset functionality

### Transaction System
- **Enhanced Transfer Process**
  - Two-step verification for transfers
  - Detailed confirmation screen
  - Automatic reference number generation
  - Transaction status tracking (pending, completed, failed)

### Advanced Admin Features
- **User Management**
  - Detailed user profile editing
  - Address validation with PSGC API
  - Activity logging for user changes
  - Bulk user management capabilities

### New Manager Features
- **System Oversight**
  - Admin account creation and management
  - Admin activity monitoring
  - Transaction audit logs
  - System-wide transfer monitoring

### Location Management
- **PSGC Integration Improvements**
  - Real-time address validation
  - Hierarchical location selection
  - Address change tracking
  - Location data caching

### Security Enhancements
- **Rate Limiting**
  - Dynamic rate limiting based on endpoint sensitivity
  - IP-based throttling
  - Customizable limit configurations
  - Rate limit bypass for trusted users

### Audit System
- **Enhanced Logging**
  - Detailed transaction logs
  - Admin action tracking
  - Login history
  - Address change history

### Database Improvements
- **Data Integrity**
  - Transaction rollback protection
  - Automated backups
  - Data validation layers
  - Foreign key constraints

### User Interface
- **Enhanced Dashboard**
  - Role-specific views
  - Transaction summary cards
  - Quick action buttons
  - Status indicators

### Technical Improvements
- **Code Organization**
  - Modular structure
  - Improved error handling
  - Environment variable management
  - Comprehensive documentation

### New Environment Variables
```ini
SESSION_TIMEOUT=30
MAX_LOGIN_ATTEMPTS=3
LOGIN_ATTEMPT_TIMEOUT=300
```

### Rate Limiting Configuration
Updated rate limits for different operations:
- Login: 10 attempts per minute
- Registration: 5 attempts per minute
- API Endpoints: 30 requests per minute
- Admin Operations: Various limits based on operation type

These updates reflect:

The new security features
Enhanced role management
Improved transaction handling
Better audit capabilities
Updated configuration options
Technical improvements
All these changes make the system more robust, secure, and maintainable while providing better user experience across all roles.

## Getting Started

### Prerequisites
- Python 3.7+
- pip (Python package manager)
- MySQL Server 5.7+ or MariaDB 10.2+

### Database Setup

1. Install MySQL Server or MariaDB if you haven't already:
   ```
   # For Ubuntu/Debian
   sudo apt update
   sudo apt install mysql-server
   
   # For macOS with Homebrew
   brew install mysql
   
   # For Windows
   # Download and install from the official website
   ```

2. Create a database user and set privileges:
   ```
   mysql -u root -p
   
   # In MySQL prompt
   CREATE USER 'bankapp'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON *.* TO 'bankapp'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   ```

3. Update the `.env` file with your MySQL credentials:
   ```
   DATABASE_URL=mysql+pymysql://bankapp:your_password@localhost/simple_banking
   MYSQL_USER=bankapp
   MYSQL_PASSWORD=your_password
   MYSQL_HOST=localhost
   MYSQL_PORT=3306
   MYSQL_DATABASE=simple_banking
   ```

4. Initialize the database:
   ```
   python init_db.py
   ```

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/lanlanjr/simple-banking-app.git
   cd simple-banking-app
   
   # Set up your own repository
   # First, create a new repository named 'simple-banking-app-v2' on GitHub
   
   # Then configure your local repository
   git remote remove origin
   git remote add origin https://github.com/yourusername/simple-banking-app-v2.git
   git remote set-url origin https://yourusername@github.com/yourusername/simple-banking-app-v2.git
   git branch -M main
   git push -u origin main
   
   # Note: Replace 'yourusername' with your actual GitHub username
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python app.py
   ```

4. Access the application at `http://localhost:5000`

## Deploying to PythonAnywhere

1. Create a PythonAnywhere account at [www.pythonanywhere.com](https://www.pythonanywhere.com)

2. Upload your code using Git:
   ```
   git clone https://github.com/yourusername/simple-banking-app-v2.git
   ```

3. Install requirements:
   ```
   cd simple-banking-app-v2
   pip install -r requirements.txt
   ```

4. Set up MySQL database on PythonAnywhere:
   - Go to the Databases tab in your PythonAnywhere dashboard
   - Create a new MySQL database
   - Note the database name, username, and password
   - Update your .env file with these credentials

5. Initialize your database on PythonAnywhere:
   ```
   python init_db.py
   ```

6. Configure a new web app via the PythonAnywhere dashboard:
   - Select "Manual configuration"
   - Choose Python 3.8
   - Set source code directory to `/home/yourusername/simple-banking-app-v2`
   - Set working directory to `/home/yourusername/simple-banking-app-v2`
   - Set WSGI configuration file to point to your Flask app

7. Add environment variables in the PythonAnywhere dashboard for security

## Usage

### Registration
- Navigate to the registration page
- Enter username, email, and password
- Confirm your password
- Submit the form to create your account (pending admin approval)

### Login
- Enter your username and password
- Click "Sign In"

### Account Overview
- View your current balance
- See your recent transaction history

### Transfer Funds
- Navigate to the Transfer page
- Enter recipient's username or account number
- Enter the amount to transfer
- Confirm the transfer details on the confirmation screen
- Complete the transfer

### Password Reset
- Click "Forgot your password?" on the login page
- Enter your registered email address
- Follow the link in the email (simulated in this demo)
- Create a new password

### Admin Features
- Approve new user registrations
- Activate/deactivate user accounts
- Create new user accounts
- Make over-the-counter deposits to user accounts
- Edit user details including location information

### Manager Features
- Create new admin accounts
- Toggle admin status for users
- View all user transactions
- Monitor and audit admin activities

## User Roles

The system supports three types of user roles:

1. **Regular Users** - Can manage their own account, make transfers, and view their transaction history.

2. **Admin Users** - Have all regular user privileges plus:
   - Approve/reject new user registrations
   - Activate/deactivate user accounts
   - Create new user accounts
   - Make deposits to user accounts
   - Edit user information

3. **Manager Users** - Have all admin privileges plus:
   - Create and manage admin accounts
   - View admin transaction logs
   - Monitor all system transfers
   - System-wide oversight capabilities

## Address Management with PSGC API

The application integrates with the Philippine Standard Geographic Code (PSGC) API to provide standardized address selection for user profiles. The address system follows the Philippine geographical hierarchy:

- Region
- Province
- City/Municipality
- Barangay

This integration ensures addresses are standardized and validates location data according to the Philippine geographical structure.

## Technologies Used

- **Backend**: Python, Flask
- **Database**: MySQL (with SQLAlchemy ORM)
- **Frontend**: HTML, CSS, Bootstrap 5
- **Authentication**: Flask-Login, Werkzeug, Flask-Bcrypt
- **Forms**: Flask-WTF, WTForms
- **Security**: Flask-Limiter for API rate limiting, CSRF protection
- **External API**: PSGC API for Philippine geographic data

## Rate Limiting

The application uses Flask-Limiter to implement API rate limiting, which protects against potential DoS attacks and abusive bot activity. The rate limits are configured as follows:

- **Login**: 10 attempts per minute
- **Registration**: 5 attempts per minute
- **Password Reset**: 5 attempts per hour
- **Money Transfer**: 20 attempts per hour
- **API Endpoints**: 30 requests per minute
- **Admin Dashboard**: 60 requests per hour
- **Admin Account Creation**: 20 accounts per hour
- **Admin Deposits**: 30 deposits per hour
- **Manager Dashboard**: 60 requests per hour
- **Admin Creation**: 10 admin accounts per hour

By default, the rate limiting data is stored in memory. For production use, it's recommended to use Redis as a storage backend for persistence across application restarts. To enable Redis storage:

1. Install Redis server on your system
2. Update the `.env` file with your Redis URL:
   ```
   REDIS_URL=redis://localhost:6379/0
   ```

If Redis is not available, the application will automatically fall back to in-memory storage.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

**Developer:** 
Vohn Justin Ayuban
Carl Cyruz Leonador
Trixie Kathleen Zaballa

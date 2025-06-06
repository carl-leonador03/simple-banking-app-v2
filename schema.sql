-- Database schema for Simple Banking App

-- Drop database if it exists to avoid conflicts
DROP DATABASE IF EXISTS simple_banking;

-- Create database
CREATE DATABASE simple_banking CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Use the database
USE simple_banking;

-- Users table
CREATE TABLE user (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  email VARCHAR(120) NOT NULL UNIQUE,
  firstname VARCHAR(64),
  lastname VARCHAR(64),
  address_line VARCHAR(256),
  region_code VARCHAR(20),
  region_name VARCHAR(100),
  province_code VARCHAR(20),
  province_name VARCHAR(100),
  city_code VARCHAR(20),
  city_name VARCHAR(100),
  barangay_code VARCHAR(20),
  barangay_name VARCHAR(100),
  postal_code VARCHAR(10),
  phone VARCHAR(20),
  password_hash VARCHAR(128) NOT NULL,
  account_number VARCHAR(10) NOT NULL UNIQUE,
  balance FLOAT DEFAULT 1000.0,
  status VARCHAR(20) DEFAULT 'pending',
  is_admin BOOLEAN DEFAULT FALSE,
  is_manager BOOLEAN DEFAULT FALSE,
  date_registered DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME,
  failed_login_attempts INT DEFAULT 0,
  account_locked_until DATETIME,
  password_reset_token VARCHAR(100),
  password_reset_expires DATETIME,
  email_verified BOOLEAN DEFAULT FALSE,
  email_verification_token VARCHAR(100),
  two_factor_enabled BOOLEAN DEFAULT FALSE,
  two_factor_secret VARCHAR(32),
  INDEX idx_username (username),
  INDEX idx_email (email),
  INDEX idx_account_number (account_number)
) ENGINE=InnoDB;

-- Transactions table
CREATE TABLE transaction (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sender_id INT,
  receiver_id INT,
  amount FLOAT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  transaction_type VARCHAR(20) DEFAULT 'transfer',
  status VARCHAR(20) DEFAULT 'pending',
  details TEXT,
  reference_number VARCHAR(50) UNIQUE,
  FOREIGN KEY (sender_id) REFERENCES user (id),
  FOREIGN KEY (receiver_id) REFERENCES user (id),
  INDEX idx_sender (sender_id),
  INDEX idx_receiver (receiver_id),
  INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB;

-- Login History table
CREATE TABLE login_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip_address VARCHAR(45),
  user_agent VARCHAR(256),
  success BOOLEAN DEFAULT TRUE,
  FOREIGN KEY (user_id) REFERENCES user (id),
  INDEX idx_user_id (user_id),
  INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB; 
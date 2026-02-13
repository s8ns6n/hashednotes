"""
Secure Notes - Database Manager
Handles all database operations and user management.
"""

import sqlite3
import logging
import bcrypt
from typing import Optional
from datetime import datetime

from config import DB_PATH, CRYPTO_SETTINGS
from crypto_manager import CryptoManager
from models import User, Note, RegistrationResult, AuthenticationResult

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Raised when database operations fail."""
    pass


class DatabaseManager:
    """Manages all database operations for the application."""
    
    def __init__(self):
        """Initialize the database manager and create tables if needed."""
        self._init_connection()
        self._create_tables()
    
    def _init_connection(self) -> None:
        """Initialize the database connection."""
        try:
            self.connection = sqlite3.connect(DB_PATH)
            self.connection.row_factory = sqlite3.Row
            logger.info("Database connection established")
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise DatabaseError("Failed to connect to database") from e
    
    def _create_tables(self) -> None:
        """Create database tables if they don't exist."""
        try:
            cursor = self.connection.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    encrypted_private_key TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Notes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    encrypted_content TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            self.connection.commit()
            logger.info("Database tables initialized")
        except sqlite3.Error as e:
            logger.error(f"Failed to create tables: {e}")
            raise DatabaseError("Failed to create database tables") from e
    
    def close(self) -> None:
        """Close the database connection."""
        if hasattr(self, 'connection'):
            self.connection.close()
            logger.info("Database connection closed")
    
    def username_exists(self, username: str) -> bool:
        """Check if a username already exists.
        
        Args:
            username: The username to check
            
        Returns:
            True if username exists, False otherwise
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            return cursor.fetchone() is not None
        except sqlite3.Error as e:
            logger.error(f"Failed to check username existence: {e}")
            raise DatabaseError("Failed to check username") from e
    
    def _hash_password(self, password: str) -> bytes:
        """Hash a password using bcrypt.
        
        Args:
            password: The plaintext password
            
        Returns:
            Bcrypt hashed password
        """
        return bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt(rounds=CRYPTO_SETTINGS['bcrypt_rounds'])
        )
    
    def _verify_password(self, password: str, password_hash: bytes) -> bool:
        """Verify a password against its hash.
        
        Args:
            password: The plaintext password
            password_hash: The stored bcrypt hash
            
        Returns:
            True if password matches, False otherwise
        """
        return bcrypt.checkpw(password.encode('utf-8'), password_hash)
    
    def register_user(self, username: str, password: str) -> RegistrationResult:
        """Register a new user.
        
        Args:
            username: The desired username
            password: The user's password
            
        Returns:
            RegistrationResult indicating success/failure
        """
        try:
            # Check if username exists
            if self.username_exists(username):
                return RegistrationResult(
                    success=False,
                    message="Username already exists"
                )
            
            # Generate RSA key pair
            private_key, public_key = CryptoManager.generate_rsa_keypair()
            
            # Encrypt private key with password
            encrypted_private_key = CryptoManager.encrypt_private_key(
                private_key, password
            )
            
            # Serialize public key
            public_key_pem = CryptoManager.serialize_public_key(public_key)
            
            # Hash password
            password_hash = self._hash_password(password)
            
            # Insert into database
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, public_key, encrypted_private_key)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, public_key_pem, encrypted_private_key))
            
            self.connection.commit()
            user_id = cursor.lastrowid
            
            logger.info(f"User '{username}' registered successfully")
            return RegistrationResult(
                success=True,
                message="User registered successfully",
                user_id=user_id
            )
        
        except Exception as e:
            logger.error(f"Failed to register user: {e}")
            return RegistrationResult(
                success=False,
                message=f"Registration failed: {str(e)}"
            )
    
    def authenticate_user(self, username: str, password: str) -> AuthenticationResult:
        """Authenticate a user.
        
        Args:
            username: The username
            password: The password
            
        Returns:
            AuthenticationResult with user data or error
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT id, username, password_hash, public_key, encrypted_private_key
                FROM users WHERE username = ?
            ''', (username,))
            
            row = cursor.fetchone()
            if not row:
                logger.warning(f"Authentication failed: user '{username}' not found")
                return AuthenticationResult(
                    success=False,
                    error_message="Invalid username or password"
                )
            
            user_id, username, password_hash, public_key_pem, encrypted_private_key = row
            
            # Verify password
            if not self._verify_password(password, password_hash):
                logger.warning(f"Authentication failed: incorrect password for '{username}'")
                return AuthenticationResult(
                    success=False,
                    error_message="Invalid username or password"
                )
            
            # Decrypt private key
            try:
                private_key = CryptoManager.decrypt_private_key(
                    encrypted_private_key, password
                )
            except Exception as e:
                logger.error(f"Failed to decrypt private key for '{username}': {e}")
                return AuthenticationResult(
                    success=False,
                    error_message="Failed to decrypt private key"
                )
            
            # Deserialize public key
            public_key = CryptoManager.deserialize_public_key(public_key_pem)
            
            # Get creation timestamp
            created_at = None
            cursor.execute(
                'SELECT created_at FROM users WHERE id = ?',
                (user_id,)
            )
            timestamp_row = cursor.fetchone()
            if timestamp_row and timestamp_row[0]:
                created_at = datetime.fromisoformat(timestamp_row[0])
            
            user = User(
                id=user_id,
                username=username,
                private_key=private_key,
                public_key=public_key,
                created_at=created_at
            )
            
            logger.info(f"User '{username}' authenticated successfully")
            return AuthenticationResult(success=True, user=user)
        
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return AuthenticationResult(
                success=False,
                error_message="Authentication failed"
            )
    
    def get_user_notes(self, user_id: int) -> Optional[str]:
        """Get encrypted notes for a user.
        
        Args:
            user_id: The user's ID
            
        Returns:
            Encrypted notes content or None if not found
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                'SELECT encrypted_content FROM notes WHERE user_id = ?',
                (user_id,)
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except sqlite3.Error as e:
            logger.error(f"Failed to get notes for user {user_id}: {e}")
            raise DatabaseError("Failed to retrieve notes") from e
    
    def save_user_notes(self, user_id: int, encrypted_content: str) -> None:
        """Save or update encrypted notes for a user.
        
        Args:
            user_id: The user's ID
            encrypted_content: The encrypted note content
        """
        try:
            cursor = self.connection.cursor()
            
            # Check if notes exist
            cursor.execute('SELECT id FROM notes WHERE user_id = ?', (user_id,))
            
            if cursor.fetchone():
                # Update existing notes
                cursor.execute('''
                    UPDATE notes 
                    SET encrypted_content = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = ?
                ''', (encrypted_content, user_id))
                logger.info(f"Updated notes for user {user_id}")
            else:
                # Insert new notes
                cursor.execute('''
                    INSERT INTO notes (user_id, encrypted_content)
                    VALUES (?, ?)
                ''', (user_id, encrypted_content))
                logger.info(f"Created new notes for user {user_id}")
            
            self.connection.commit()
        
        except sqlite3.Error as e:
            logger.error(f"Failed to save notes for user {user_id}: {e}")
            raise DatabaseError("Failed to save notes") from e
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

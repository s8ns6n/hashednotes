"""
Secure Notes - Input Validators
Validates user input for security and correctness.
"""

import re
from typing import Tuple


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class InputValidator:
    """Validates user input for registration and login."""
    
    MIN_USERNAME_LENGTH = 3
    MAX_USERNAME_LENGTH = 50
    MIN_PASSWORD_LENGTH = 8
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """Validate a username.
        
        Args:
            username: The username to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not username:
            return False, "Username is required"
        
        username = username.strip()
        
        if len(username) < InputValidator.MIN_USERNAME_LENGTH:
            return False, f"Username must be at least {InputValidator.MIN_USERNAME_LENGTH} characters"
        
        if len(username) > InputValidator.MAX_USERNAME_LENGTH:
            return False, f"Username must be less than {InputValidator.MAX_USERNAME_LENGTH} characters"
        
        # Check for valid characters (alphanumeric, underscore, hyphen)
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        
        return True, ""
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """Validate a password.
        
        Args:
            password: The password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not password:
            return False, "Password is required"
        
        if len(password) < InputValidator.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {InputValidator.MIN_PASSWORD_LENGTH} characters"
        
        return True, ""
    
    @staticmethod
    def validate_passwords_match(password: str, confirm_password: str) -> Tuple[bool, str]:
        """Validate that two passwords match.
        
        Args:
            password: The original password
            confirm_password: The confirmation password
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if password != confirm_password:
            return False, "Passwords do not match"
        
        return True, ""
    
    @staticmethod
    def validate_registration(username: str, password: str, confirm_password: str) -> Tuple[bool, str]:
        """Validate all registration fields.
        
        Args:
            username: The username
            password: The password
            confirm_password: The confirmation password
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Validate username
        is_valid, error = InputValidator.validate_username(username)
        if not is_valid:
            return False, error
        
        # Validate password
        is_valid, error = InputValidator.validate_password(password)
        if not is_valid:
            return False, error
        
        # Validate passwords match
        is_valid, error = InputValidator.validate_passwords_match(password, confirm_password)
        if not is_valid:
            return False, error
        
        return True, ""
    
    @staticmethod
    def validate_login(username: str, password: str) -> Tuple[bool, str]:
        """Validate login fields.
        
        Args:
            username: The username
            password: The password
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not username.strip():
            return False, "Username is required"
        
        if not password:
            return False, "Password is required"
        
        return True, ""

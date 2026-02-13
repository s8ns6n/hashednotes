"""
Secure Notes - Data Models
Defines data structures used throughout the application.
"""

from dataclasses import dataclass
from typing import Optional
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class User:
    """Represents a user in the system."""
    id: int
    username: str
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    created_at: Optional[datetime] = None
    
    def __repr__(self) -> str:
        return f"User(id={self.id}, username='{self.username}')"


@dataclass
class Note:
    """Represents an encrypted note."""
    id: Optional[int]
    user_id: int
    encrypted_content: str
    updated_at: Optional[datetime] = None
    
    def __repr__(self) -> str:
        return f"Note(id={self.id}, user_id={self.user_id})"


@dataclass
class RegistrationResult:
    """Result of a registration attempt."""
    success: bool
    message: str
    user_id: Optional[int] = None
    
    def __repr__(self) -> str:
        return f"RegistrationResult(success={self.success}, message='{self.message}')"


@dataclass
class AuthenticationResult:
    """Result of an authentication attempt."""
    success: bool
    user: Optional[User] = None
    error_message: Optional[str] = None
    
    def __repr__(self) -> str:
        return f"AuthenticationResult(success={self.success}, error='{self.error_message}')"

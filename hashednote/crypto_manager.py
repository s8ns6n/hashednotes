"""
Secure Notes - Cryptography Manager
Handles all encryption, decryption, and key management operations.
"""

import os
import base64
import json
import logging
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from config import CRYPTO_SETTINGS

logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Raised when cryptographic operations fail."""
    pass


class CryptoManager:
    """Manages all cryptographic operations for the application."""
    
    @staticmethod
    def generate_rsa_keypair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate a new RSA key pair.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=CRYPTO_SETTINGS['rsa_key_size'],
                backend=default_backend()
            )
            public_key = private_key.public_key()
            logger.debug("Generated new RSA keypair")
            return private_key, public_key
        except Exception as e:
            logger.error(f"Failed to generate RSA keypair: {e}")
            raise CryptoError("Failed to generate encryption keys") from e
    
    @staticmethod
    def derive_key_from_password(password: str) -> bytes:
        """Derive an encryption key from a password using PBKDF2.
        
        Args:
            password: The user's password
            
        Returns:
            32-byte encryption key
        """
        try:
            # Generate a deterministic salt from the password
            salt_hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
            salt_hasher.update(password.encode('utf-8'))
            salt = salt_hasher.finalize()[:16]
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=CRYPTO_SETTINGS['pbkdf2_iterations'],
                backend=default_backend()
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to derive key from password: {e}")
            raise CryptoError("Failed to derive encryption key") from e
    
    @staticmethod
    def encrypt_private_key(private_key: rsa.RSAPrivateKey, password: str) -> str:
        """Encrypt a private key using password-derived key.
        
        Args:
            private_key: The RSA private key to encrypt
            password: The user's password
            
        Returns:
            Base64-encoded encrypted private key
        """
        try:
            # Serialize private key to PEM format
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Derive encryption key from password
            key = CryptoManager.derive_key_from_password(password)
            
            # Generate random nonce
            nonce = os.urandom(12)
            
            # Encrypt with AES-GCM
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, private_key_pem, None)
            
            # Combine nonce and ciphertext, encode to base64
            encrypted_data = nonce + ciphertext
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to encrypt private key: {e}")
            raise CryptoError("Failed to encrypt private key") from e
    
    @staticmethod
    def decrypt_private_key(encrypted_private_key: str, password: str) -> rsa.RSAPrivateKey:
        """Decrypt a private key using password.
        
        Args:
            encrypted_private_key: Base64-encoded encrypted private key
            password: The user's password
            
        Returns:
            Decrypted RSA private key
        """
        try:
            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_private_key.encode('utf-8'))
            
            # Extract nonce and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Derive key from password
            key = CryptoManager.derive_key_from_password(password)
            
            # Decrypt with AES-GCM
            aesgcm = AESGCM(key)
            private_key_pem = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Load private key from PEM
            return serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
        except Exception as e:
            logger.error(f"Failed to decrypt private key: {e}")
            raise CryptoError("Failed to decrypt private key - incorrect password?") from e
    
    @staticmethod
    def encrypt_note_content(content: str, public_key: rsa.RSAPublicKey) -> str:
        """Encrypt note content using hybrid encryption (RSA + AES).
        
        Uses AES-256-GCM for content encryption and RSA-2048 for key encryption.
        
        Args:
            content: The note content to encrypt
            public_key: The user's public key
            
        Returns:
            Base64-encoded encrypted package
        """
        try:
            # Generate random AES key
            aes_key = AESGCM.generate_key(bit_length=CRYPTO_SETTINGS['aes_key_size'])
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            
            # Encrypt content with AES
            ciphertext = aesgcm.encrypt(nonce, content.encode('utf-8'), None)
            
            # Encrypt AES key with RSA
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Create encrypted package
            encrypted_package = {
                'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
            }
            
            # Encode entire package to base64
            return base64.b64encode(
                json.dumps(encrypted_package).encode('utf-8')
            ).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to encrypt note content: {e}")
            raise CryptoError("Failed to encrypt note content") from e
    
    @staticmethod
    def decrypt_note_content(encrypted_package_b64: str, private_key: rsa.RSAPrivateKey) -> str:
        """Decrypt note content.
        
        Args:
            encrypted_package_b64: Base64-encoded encrypted package
            private_key: The user's private key
            
        Returns:
            Decrypted note content
        """
        try:
            # Decode package from base64
            encrypted_package = json.loads(
                base64.b64decode(encrypted_package_b64.encode('utf-8'))
            )
            
            # Decrypt AES key with RSA
            encrypted_key = base64.b64decode(
                encrypted_package['encrypted_key'].encode('utf-8')
            )
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt content with AES
            nonce = base64.b64decode(encrypted_package['nonce'].encode('utf-8'))
            ciphertext = base64.b64decode(encrypted_package['ciphertext'].encode('utf-8'))
            
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decrypt note content: {e}")
            raise CryptoError("Failed to decrypt note content") from e
    
    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
        """Serialize a public key to PEM format.
        
        Args:
            public_key: The RSA public key
            
        Returns:
            PEM-encoded public key string
        """
        try:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to serialize public key: {e}")
            raise CryptoError("Failed to serialize public key") from e
    
    @staticmethod
    def deserialize_public_key(pem_string: str) -> rsa.RSAPublicKey:
        """Deserialize a public key from PEM format.
        
        Args:
            pem_string: PEM-encoded public key
            
        Returns:
            RSA public key object
        """
        try:
            return serialization.load_pem_public_key(
                pem_string.encode('utf-8'),
                backend=default_backend()
            )
        except Exception as e:
            logger.error(f"Failed to deserialize public key: {e}")
            raise CryptoError("Failed to deserialize public key") from e

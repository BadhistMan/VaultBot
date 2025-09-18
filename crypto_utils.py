"""
Cryptographic utilities for VaultBot.
Handles key derivation, encryption, decryption, and password generation.
"""
import secrets
import string
import logging
from typing import Tuple, Optional

import argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
import pyotp

# Configure logging
logger = logging.getLogger(__name__)

# Constants for password generation
DEFAULT_PASSWORD_LENGTH = 16
PASSWORD_CHARS = {
    'lower': string.ascii_lowercase,
    'upper': string.ascii_uppercase,
    'digits': string.digits,
    'symbols': string.punctuation
}

class CryptoUtils:
    """Cryptographic utilities for secure password management."""
    
    def __init__(self, server_pepper: str):
        """
        Initialize crypto utilities with server pepper.
        
        Args:
            server_pepper: Server-wide secret pepper for additional security
        """
        self.server_pepper = server_pepper.encode()
        self.argon2_hasher = argon2.PasswordHasher(
            time_cost=2,  # Number of iterations
            memory_cost=102400,  # 100MB memory usage
            parallelism=8,  # Number of parallel threads
            hash_len=32,  # Output hash length
            salt_len=16  # Salt length
        )
    
    def derive_key(self, master_password: str, salt: bytes, 
                  use_argon2: bool = True) -> Tuple[bytes, dict]:
        """
        Derive encryption key from master password.
        
        Args:
            master_password: User's master password
            salt: Random salt for key derivation
            use_argon2: Whether to use Argon2 (preferred) or PBKDF2
            
        Returns:
            Tuple of (derived_key, params_dict) where params_dict contains
            the parameters used for key derivation
        """
        # Combine master password with server pepper
        password_with_pepper = master_password.encode() + self.server_pepper
        
        if use_argon2:
            # Use Argon2 for key derivation (more secure against GPU attacks)
            params = {
                'algorithm': 'argon2id',
                'salt': salt.hex(),
                'time_cost': 2,
                'memory_cost': 102400,
                'parallelism': 8
            }
            
            # Derive key using Argon2
            derived_key = self.argon2_hasher.hash(
                password_with_pepper, 
                salt=salt
            ).encode()
            
            # Return first 32 bytes of the hash as the key
            return derived_key[:32], params
        else:
            # Fallback to PBKDF2HMAC if Argon2 is not available
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200000,
            )
            derived_key = kdf.derive(password_with_pepper)
            
            params = {
                'algorithm': 'pbkdf2_sha256',
                'salt': salt.hex(),
                'iterations': 200000
            }
            
            return derived_key, params
    
    def encrypt_data(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-GCM.
        
        AES-GCM provides both confidentiality and authenticity, making it
        an excellent choice for encrypting sensitive data.
        
        Args:
            data: Data to encrypt
            key: Encryption key (must be 32 bytes for AES-256)
            
        Returns:
            Tuple of (nonce, ciphertext) where nonce is needed for decryption
        """
        # Generate a random nonce
        nonce = secrets.token_bytes(12)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Encrypt data
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        return nonce, ciphertext
    
    def decrypt_data(self, ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
        """
        Decrypt data using AES-GCM.
        
        Args:
            ciphertext: Encrypted data
            nonce: Nonce used during encryption
            key: Encryption key
            
        Returns:
            Decrypted data
            
        Raises:
            InvalidTag: If authentication fails (tampered data)
        """
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def generate_password(self, length: int = DEFAULT_PASSWORD_LENGTH, 
                         use_upper: bool = True, use_digits: bool = True,
                         use_symbols: bool = True) -> str:
        """
        Generate a secure random password.
        
        Args:
            length: Password length
            use_upper: Include uppercase letters
            use_digits: Include digits
            use_symbols: Include symbols
            
        Returns:
            Generated password
        """
        # Build character set based on options
        chars = string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += string.punctuation
        
        # Generate password using cryptographically secure random
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def estimate_password_strength(self, password: str) -> Tuple[int, str]:
        """
        Estimate password strength based on entropy.
        
        Args:
            password: Password to evaluate
            
        Returns:
            Tuple of (entropy_bits, strength_label)
        """
        # Calculate character set size
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_symbol = any(c in string.punctuation for c in password)
        
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_symbol:
            charset_size += 32  # Approximate common symbols
        
        # Calculate entropy
        entropy_bits = len(password) * (charset_size.bit_length() if charset_size > 0 else 1)
        
        # Classify strength
        if entropy_bits < 50:
            strength = "Very Weak"
        elif entropy_bits < 70:
            strength = "Weak"
        elif entropy_bits < 100:
            strength = "Moderate"
        elif entropy_bits < 120:
            strength = "Strong"
        else:
            strength = "Very Strong"
            
        return entropy_bits, strength
    
    def generate_totp(self, secret: str) -> pyotp.TOTP:
        """
        Generate TOTP object from secret.
        
        Args:
            secret: TOTP secret key
            
        Returns:
            pyotp.TOTP object
        """
        return pyotp.TOTP(secret)
    
    def generate_totp_secret(self) -> str:
        """
        Generate a new TOTP secret.
        
        Returns:
            Base32 encoded secret
        """
        return pyotp.random_base32()

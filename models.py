"""
Data models for VaultBot.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any

@dataclass
class User:
    """User model for vault owners."""
    id: int
    telegram_id: int
    salt: bytes
    kdf_params: Dict[str, Any]
    locked: bool = True
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

@dataclass
class Credential:
    """Credential model for stored passwords."""
    id: int
    user_id: int
    name: str
    username: str
    password: str
    tags: List[str]
    notes: str
    category: str
    created_at: datetime
    updated_at: datetime
    totp_secret: Optional[str] = None

@dataclass
class CredentialHistory:
    """Credential history model for versioning."""
    id: int
    credential_id: int
    password: str
    created_at: datetime

@dataclass
class ShareToken:
    """Share token model for credential sharing."""
    id: int
    credential_id: int
    token: str
    expires_at: datetime
    used: bool = False
    created_at: Optional[datetime] = None

@dataclass
class AuditLog:
    """Audit log model for security tracking."""
    id: int
    user_id: int
    action: str
    details: str
    ip_address: Optional[str] = None
    created_at: Optional[datetime] = None

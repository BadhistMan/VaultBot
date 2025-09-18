"""
Utility functions for VaultBot.
"""
import re
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

# Configure logging
logger = logging.getLogger(__name__)

def validate_password_strength(password: str) -> tuple:
    """
    Validate password strength.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

def format_credential_list(credentials: list) -> str:
    """
    Format credentials list for display.
    
    Args:
        credentials: List of credential dictionaries
        
    Returns:
        Formatted string
    """
    if not credentials:
        return "No credentials found."
    
    result = "Your credentials:\n\n"
    for cred in credentials:
        result += f"• {cred['name']} ({cred['category']})\n"
        result += f"  Username: {cred['username']}\n"
        if cred['tags']:
            result += f"  Tags: {', '.join(cred['tags'])}\n"
        result += f"  Last updated: {cred['updated_at'].strftime('%Y-%m-%d %H:%M')}\n\n"
    
    return result

def format_audit_logs(logs: list) -> str:
    """
    Format audit logs for display.
    
    Args:
        logs: List of audit log entries
        
    Returns:
        Formatted string
    """
    if not logs:
        return "No audit logs found."
    
    result = "Recent activity:\n\n"
    for log in logs:
        result += f"• {log.action} at {log.created_at.strftime('%Y-%m-%d %H:%M')}\n"
        if log.details:
            result += f"  Details: {log.details}\n"
        result += "\n"
    
    return result

class SessionManager:
    """Manage user sessions with automatic expiration."""
    
    def __init__(self, timeout_minutes: int = 10):
        """
        Initialize session manager.
        
        Args:
            timeout_minutes: Session timeout in minutes
        """
        self.sessions: Dict[int, Dict[str, Any]] = {}
        self.timeout_minutes = timeout_minutes
    
    def create_session(self, user_id: int, data: Dict[str, Any]) -> None:
        """
        Create a new session.
        
        Args:
            user_id: User ID
            data: Session data
        """
        self.sessions[user_id] = {
            'data': data,
            'expires_at': datetime.now() + timedelta(minutes=self.timeout_minutes)
        }
        logger.info("Created session for user %s", user_id)
    
    def get_session(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get session data if it exists and is not expired.
        
        Args:
            user_id: User ID
            
        Returns:
            Session data or None if expired or not found
        """
        session = self.sessions.get(user_id)
        if session and datetime.now() < session['expires_at']:
            # Update expiration time
            session['expires_at'] = datetime.now() + timedelta(minutes=self.timeout_minutes)
            return session['data']
        
        # Remove expired session
        if user_id in self.sessions:
            del self.sessions[user_id]
            logger.info("Session expired for user %s", user_id)
        
        return None
    
    def remove_session(self, user_id: int) -> None:
        """
        Remove a session.
        
        Args:
            user_id: User ID
        """
        if user_id in self.sessions:
            del self.sessions[user_id]
            logger.info("Removed session for user %s", user_id)
    
    async def cleanup_task(self) -> None:
        """Background task to clean up expired sessions."""
        while True:
            await asyncio.sleep(60)  # Run every minute
            now = datetime.now()
            expired_users = [
                user_id for user_id, session in self.sessions.items()
                if now >= session['expires_at']
            ]
            
            for user_id in expired_users:
                del self.sessions[user_id]
                logger.info("Cleaned up expired session for user %s", user_id)

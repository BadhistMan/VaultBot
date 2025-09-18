"""
Database storage layer for VaultBot.
Uses SQLite with encrypted credential storage.
"""
import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple

from models import User, Credential, CredentialHistory, ShareToken, AuditLog

# Configure logging
logger = logging.getLogger(__name__)

class Storage:
    """SQLite storage handler for VaultBot."""
    
    def __init__(self, db_path: str = "vaultbot.db"):
        """
        Initialize SQLite database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = None
    
    def connect(self) -> sqlite3.Connection:
        """Establish database connection."""
        if self.conn is None:
            self.conn = sqlite3.connect(
                self.db_path, 
                check_same_thread=False,
                isolation_level=None
            )
            self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def init_db(self):
        """Initialize database tables."""
        conn = self.connect()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                kdf_params TEXT NOT NULL,
                locked BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        
        # Credentials table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                nonce BLOB NOT NULL,
                tags TEXT DEFAULT '[]',
                notes TEXT DEFAULT '',
                category TEXT DEFAULT 'General',
                totp_secret BLOB,
                totp_nonce BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        
        # Credential history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credential_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id INTEGER NOT NULL,
                password BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE
            )
        """)
        
        # Share tokens table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS share_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE CASCADE
            )
        """)
        
        # Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_share_tokens_token ON share_tokens(token)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_share_tokens_expires ON share_tokens(expires_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)")
        
        conn.commit()
        logger.info("Database initialized successfully")
    
    def add_user(self, telegram_id: int, salt: bytes, kdf_params: Dict[str, Any]) -> int:
        """
        Add a new user to the database.
        
        Args:
            telegram_id: User's Telegram ID
            salt: Salt for key derivation
            kdf_params: Key derivation function parameters
            
        Returns:
            User ID
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (telegram_id, salt, kdf_params) VALUES (?, ?, ?)",
            (telegram_id, salt, json.dumps(kdf_params))
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        
        logger.info("Added new user with Telegram ID: %s", telegram_id)
        return user_id
    
    def get_user(self, telegram_id: int) -> Optional[User]:
        """
        Get user by Telegram ID.
        
        Args:
            telegram_id: User's Telegram ID
            
        Returns:
            User object or None if not found
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM users WHERE telegram_id = ?",
            (telegram_id,)
        )
        
        row = cursor.fetchone()
        if row:
            return User(
                id=row['id'],
                telegram_id=row['telegram_id'],
                salt=row['salt'],
                kdf_params=json.loads(row['kdf_params']),
                locked=bool(row['locked']),
                created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None
            )
        return None
    
    def update_user_lock_status(self, user_id: int, locked: bool):
        """
        Update user lock status.
        
        Args:
            user_id: User ID
            locked: Whether the vault is locked
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE users SET locked = ?, last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (locked, user_id)
        )
        
        conn.commit()
        logger.info("Updated lock status for user %s to %s", user_id, locked)
    
    def add_credential(self, user_id: int, name: str, username: str, 
                      encrypted_password: bytes, nonce: bytes, tags: List[str] = None,
                      notes: str = "", category: str = "General",
                      encrypted_totp_secret: bytes = None, totp_nonce: bytes = None) -> int:
        """
        Add a new credential to the database.
        
        Args:
            user_id: User ID
            name: Credential name
            username: Username
            encrypted_password: Encrypted password
            nonce: Nonce used for encryption
            tags: List of tags
            notes: Additional notes
            category: Category name
            encrypted_totp_secret: Encrypted TOTP secret
            totp_nonce: Nonce used for TOTP secret encryption
            
        Returns:
            Credential ID
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        tags_json = json.dumps(tags or [])
        
        cursor.execute(
            """INSERT INTO credentials 
            (user_id, name, username, password, nonce, tags, notes, category, totp_secret, totp_nonce) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, name, username, encrypted_password, nonce, tags_json, notes, 
             category, encrypted_totp_secret, totp_nonce)
        )
        
        credential_id = cursor.lastrowid
        conn.commit()
        
        logger.info("Added new credential for user %s: %s", user_id, name)
        return credential_id
    
    def get_credentials(self, user_id: int, category: str = None, 
                       search_query: str = None) -> List[Dict[str, Any]]:
        """
        Get credentials for a user with optional filtering.
        
        Args:
            user_id: User ID
            category: Filter by category
            search_query: Search in name and tags
            
        Returns:
            List of credential metadata (without encrypted data)
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        query = """
            SELECT id, name, username, tags, notes, category, created_at, updated_at
            FROM credentials 
            WHERE user_id = ?
        """
        params = [user_id]
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        if search_query:
            query += " AND (name LIKE ? OR tags LIKE ?)"
            params.extend([f"%{search_query}%", f"%{search_query}%"])
        
        query += " ORDER BY name"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        credentials = []
        for row in rows:
            credentials.append({
                'id': row['id'],
                'name': row['name'],
                'username': row['username'],
                'tags': json.loads(row['tags']),
                'notes': row['notes'],
                'category': row['category'],
                'created_at': datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                'updated_at': datetime.fromisoformat(row['updated_at']) if row['updated_at'] else None
            })
        
        return credentials
    
    def get_credential(self, credential_id: int, user_id: int = None) -> Optional[Credential]:
        """
        Get a specific credential with encrypted data.
        
        Args:
            credential_id: Credential ID
            user_id: Optional user ID for verification
            
        Returns:
            Credential object or None if not found
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        if user_id:
            cursor.execute(
                "SELECT * FROM credentials WHERE id = ? AND user_id = ?",
                (credential_id, user_id)
            )
        else:
            cursor.execute(
                "SELECT * FROM credentials WHERE id = ?",
                (credential_id,)
            )
        
        row = cursor.fetchone()
        if row:
            return Credential(
                id=row['id'],
                user_id=row['user_id'],
                name=row['name'],
                username=row['username'],
                password=row['password'],
                tags=json.loads(row['tags']),
                notes=row['notes'],
                category=row['category'],
                created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                updated_at=datetime.fromisoformat(row['updated_at']) if row['updated_at'] else None,
                totp_secret=row['totp_secret']
            )
        return None
    
    def update_credential(self, credential_id: int, name: str = None, username: str = None,
                         encrypted_password: bytes = None, nonce: bytes = None,
                         tags: List[str] = None, notes: str = None, category: str = None,
                         encrypted_totp_secret: bytes = None, totp_nonce: bytes = None):
        """
        Update a credential.
        
        Args:
            credential_id: Credential ID
            name: New name
            username: New username
            encrypted_password: New encrypted password
            nonce: New nonce
            tags: New tags
            notes: New notes
            category: New category
            encrypted_totp_secret: New encrypted TOTP secret
            totp_nonce: New TOTP nonce
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        # Build dynamic update query
        updates = []
        params = []
        
        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if username is not None:
            updates.append("username = ?")
            params.append(username)
        if encrypted_password is not None:
            updates.append("password = ?")
            params.append(encrypted_password)
        if nonce is not None:
            updates.append("nonce = ?")
            params.append(nonce)
        if tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(tags))
        if notes is not None:
            updates.append("notes = ?")
            params.append(notes)
        if category is not None:
            updates.append("category = ?")
            params.append(category)
        if encrypted_totp_secret is not None:
            updates.append("totp_secret = ?")
            params.append(encrypted_totp_secret)
        if totp_nonce is not None:
            updates.append("totp_nonce = ?")
            params.append(totp_nonce)
        
        # Always update the timestamp
        updates.append("updated_at = CURRENT_TIMESTAMP")
        
        if updates:
            query = f"UPDATE credentials SET {', '.join(updates)} WHERE id = ?"
            params.append(credential_id)
            
            cursor.execute(query, params)
            conn.commit()
            
            logger.info("Updated credential %s", credential_id)
    
    def delete_credential(self, credential_id: int):
        """
        Delete a credential.
        
        Args:
            credential_id: Credential ID
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
        conn.commit()
        
        logger.info("Deleted credential %s", credential_id)
    
    def add_credential_history(self, credential_id: int, encrypted_password: bytes, nonce: bytes):
        """
        Add a credential password to history.
        
        Args:
            credential_id: Credential ID
            encrypted_password: Encrypted password
            nonce: Nonce used for encryption
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO credential_history (credential_id, password, nonce) VALUES (?, ?, ?)",
            (credential_id, encrypted_password, nonce)
        )
        
        conn.commit()
    
    def get_credential_history(self, credential_id: int, limit: int = 5) -> List[CredentialHistory]:
        """
        Get credential password history.
        
        Args:
            credential_id: Credential ID
            limit: Maximum number of history entries to return
            
        Returns:
            List of credential history entries
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM credential_history WHERE credential_id = ? ORDER BY created_at DESC LIMIT ?",
            (credential_id, limit)
        )
        
        rows = cursor.fetchall()
        history = []
        
        for row in rows:
            history.append(CredentialHistory(
                id=row['id'],
                credential_id=row['credential_id'],
                password=row['password'],
                created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None
            ))
        
        return history
    
    def add_share_token(self, credential_id: int, token: str, expires_in: int = 3600) -> str:
        """
        Add a share token for a credential.
        
        Args:
            credential_id: Credential ID
            token: Share token
            expires_in: Token expiration time in seconds
            
        Returns:
            Share token
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        
        cursor.execute(
            "INSERT INTO share_tokens (credential_id, token, expires_at) VALUES (?, ?, ?)",
            (credential_id, token, expires_at)
        )
        
        conn.commit()
        logger.info("Added share token for credential %s", credential_id)
        
        return token
    
    def get_share_token(self, token: str) -> Optional[ShareToken]:
        """
        Get a share token and mark it as used.
        
        Args:
            token: Share token
            
        Returns:
            ShareToken object or None if not found or expired
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        # Clean up expired tokens first
        cursor.execute(
            "DELETE FROM share_tokens WHERE expires_at < ?",
            (datetime.now(),)
        )
        
        cursor.execute(
            "SELECT * FROM share_tokens WHERE token = ? AND used = 0 AND expires_at > ?",
            (token, datetime.now())
        )
        
        row = cursor.fetchone()
        if row:
            # Mark token as used
            cursor.execute(
                "UPDATE share_tokens SET used = 1 WHERE id = ?",
                (row['id'],)
            )
            
            conn.commit()
            
            return ShareToken(
                id=row['id'],
                credential_id=row['credential_id'],
                token=row['token'],
                expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
                used=True,
                created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None
            )
        
        return None
    
    def add_audit_log(self, user_id: int, action: str, details: str = None, ip_address: str = None):
        """
        Add an audit log entry.
        
        Args:
            user_id: User ID
            action: Action performed
            details: Additional details
            ip_address: IP address of the user
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
            (user_id, action, details, ip_address)
        )
        
        conn.commit()
        logger.info("Added audit log for user %s: %s", user_id, action)
    
    def get_audit_logs(self, user_id: int, limit: int = 50) -> List[AuditLog]:
        """
        Get audit logs for a user.
        
        Args:
            user_id: User ID
            limit: Maximum number of logs to return
            
        Returns:
            List of audit log entries
        """
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit)
        )
        
        rows = cursor.fetchall()
        logs = []
        
        for row in rows:
            logs.append(AuditLog(
                id=row['id'],
                user_id=row['user_id'],
                action=row['action'],
                details=row['details'],
                ip_address=row['ip_address'],
                created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None
            ))
        
        return logs

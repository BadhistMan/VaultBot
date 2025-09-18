"""
Telegram bot handlers for VaultBot.
"""
import logging
import json
import re
from typing import Dict, Any, Optional, List

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ContextTypes, 
    CommandHandler, 
    MessageHandler, 
    CallbackQueryHandler,
    ConversationHandler,
    filters
)
from telegram.constants import ParseMode

from crypto_utils import CryptoUtils
from storage import Storage
from utils import validate_password_strength, format_credential_list, format_audit_logs, SessionManager

# Configure logging
logger = logging.getLogger(__name__)

# Conversation states
SETUP_MASTER_PASSWORD, CONFIRM_MASTER_PASSWORD, UNLOCK_VAULT = range(3)
ADD_CREDENTIAL_NAME, ADD_CREDENTIAL_USERNAME, ADD_CREDENTIAL_PASSWORD = range(3, 6)
ADD_CREDENTIAL_TAGS, ADD_CREDENTIAL_NOTES, ADD_CREDENTIAL_CATEGORY = range(6, 9)
ADD_TOTP_SECRET = range(9, 10)

class VaultBotHandlers:
    """Handlers for VaultBot commands and conversations."""
    
    def __init__(self, crypto: CryptoUtils, storage: Storage, session_manager: SessionManager, admin_ids: List[int]):
        """
        Initialize handlers.
        
        Args:
            crypto: CryptoUtils instance
            storage: Storage instance
            session_manager: SessionManager instance
            admin_ids: List of admin user IDs
        """
        self.crypto = crypto
        self.storage = storage
        self.session_manager = session_manager
        self.admin_ids = admin_ids
        
        # In-memory state for conversations
        self.user_states: Dict[int, Dict[str, Any]] = {}
    
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /start command."""
        user = update.effective_user
        logger.info("User %s started the bot", user.id)
        
        # Check if user exists
        db_user = self.storage.get_user(user.id)
        
        if db_user:
            if db_user.locked:
                await update.message.reply_text(
                    "🔒 Your vault is locked. Use /unlock to access your passwords.",
                    parse_mode=ParseMode.MARKDOWN
                )
            else:
                await update.message.reply_text(
                    "🔓 Your vault is unlocked. Use /help to see available commands.",
                    parse_mode=ParseMode.MARKDOWN
                )
        else:
            # New user - start setup process
            await update.message.reply_text(
                "👋 Welcome to VaultBot!\n\n"
                "I'm your secure password manager. To get started, "
                "you need to set up a master password to encrypt your data.\n\n"
                "Please choose a strong master password:",
                parse_mode=ParseMode.MARKDOWN
            )
            
            # Set conversation state
            return SETUP_MASTER_PASSWORD
    
    async def setup_master_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle master password setup."""
        user = update.effective_user
        password = update.message.text
        
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            await update.message.reply_text(
                f"❌ {message}\n\nPlease choose a stronger password:"
            )
            return SETUP_MASTER_PASSWORD
        
        # Store password in user state for confirmation
        self.user_states[user.id] = {'master_password': password}
        
        await update.message.reply_text(
            "✅ Password is strong!\n\nPlease confirm your master password:"
        )
        
        return CONFIRM_MASTER_PASSWORD
    
    async def confirm_master_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Confirm master password setup."""
        user = update.effective_user
        password = update.message.text
        
        # Check if passwords match
        if user.id not in self.user_states or self.user_states[user.id].get('master_password') != password:
            await update.message.reply_text(
                "❌ Passwords don't match. Please start over with /start"
            )
            return ConversationHandler.END
        
        # Generate salt and derive key
        salt = secrets.token_bytes(16)
        key, kdf_params = self.crypto.derive_key(password, salt)
        
        # Store user in database
        user_id = self.storage.add_user(user.id, salt, kdf_params)
        
        # Unlock the vault
        self.storage.update_user_lock_status(user_id, False)
        
        # Create session
        self.session_manager.create_session(user.id, {'user_id': user_id, 'key': key})
        
        # Add audit log
        self.storage.add_audit_log(user_id, "user_registration", "New user registered")
        
        await update.message.reply_text(
            "✅ Vault setup complete! Your data is now securely encrypted.\n\n"
            "Use /add to store your first password or /help to see all commands.",
            parse_mode=ParseMode.MARKDOWN
        )
        
        # Clean up user state
        if user.id in self.user_states:
            del self.user_states[user.id]
        
        return ConversationHandler.END
    
    async def unlock(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle /unlock command."""
        user = update.effective_user
        db_user = self.storage.get_user(user.id)
        
        if not db_user:
            await update.message.reply_text(
                "You need to set up your vault first with /start"
            )
            return ConversationHandler.END
        
        if not db_user.locked:
            await update.message.reply_text(
                "Your vault is already unlocked!"
            )
            return ConversationHandler.END
        
        await update.message.reply_text(
            "Please enter your master password to unlock your vault:"
        )
        
        return UNLOCK_VAULT
    
    async def unlock_vault(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle vault unlocking."""
        user = update.effective_user
        password = update.message.text
        
        db_user = self.storage.get_user(user.id)
        if not db_user:
            await update.message.reply_text(
                "User not found. Please start with /start"
            )
            return ConversationHandler.END
        
        try:
            # Derive key using stored parameters
            key, _ = self.crypto.derive_key(
                password, 
                db_user.salt, 
                use_argon2=db_user.kdf_params.get('algorithm') == 'argon2id'
            )
            
            # Unlock the vault
            self.storage.update_user_lock_status(db_user.id, False)
            
            # Create session
            self.session_manager.create_session(user.id, {'user_id': db_user.id, 'key': key})
            
            # Add audit log
            self.storage.add_audit_log(db_user.id, "vault_unlocked", "User unlocked vault")
            
            await update.message.reply_text(
                "✅ Vault unlocked! You can now access your passwords."
            )
            
        except Exception as e:
            logger.error("Unlock failed for user %s: %s", user.id, e)
            await update.message.reply_text(
                "❌ Invalid password. Please try again or use /start to reset your vault."
            )
        
        return ConversationHandler.END
    
    async def lock(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /lock command."""
        user = update.effective_user
        db_user = self.storage.get_user(user.id)
        
        if not db_user:
            await update.message.reply_text(
                "You need to set up your vault first with /start"
            )
            return
        
        if db_user.locked:
            await update.message.reply_text(
                "Your vault is already locked!"
            )
            return
        
        # Lock the vault
        self.storage.update_user_lock_status(db_user.id, True)
        
        # Remove session
        self.session_manager.remove_session(user.id)
        
        # Add audit log
        self.storage.add_audit_log(db_user.id, "vault_locked", "User locked vault")
        
        await update.message.reply_text(
            "🔒 Vault locked! Your data is now secure."
        )
    
    async def add(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle /add command."""
        user = update.effective_user
        
        # Check if user has an active session
        session = self.session_manager.get_session(user.id)
        if not session:
            await update.message.reply_text(
                "Your vault is locked. Please /unlock first."
            )
            return ConversationHandler.END
        
        await update.message.reply_text(
            "Let's add a new credential.\n\nPlease enter the service name:"
        )
        
        return ADD_CREDENTIAL_NAME
    
    async def add_credential_name(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle credential name input."""
        user = update.effective_user
        name = update.message.text
        
        # Store in user state
        if user.id not in self.user_states:
            self.user_states[user.id] = {}
        self.user_states[user.id]['credential_name'] = name
        
        await update.message.reply_text(
            "Please enter the username:"
        )
        
        return ADD_CREDENTIAL_USERNAME
    
    async def add_credential_username(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle username input."""
        user = update.effective_user
        username = update.message.text
        
        # Store in user state
        self.user_states[user.id]['credential_username'] = username
        
        keyboard = [
            [InlineKeyboardButton("Generate strong password", callback_data="generate_password")],
            [InlineKeyboardButton("I'll enter my own", callback_data="enter_password")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "How would you like to handle the password?",
            reply_markup=reply_markup
        )
        
        return ADD_CREDENTIAL_PASSWORD
    
    async def handle_password_choice(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle password choice callback."""
        query = update.callback_query
        await query.answer()
        
        user = query.from_user
        
        if query.data == "generate_password":
            # Generate a strong password
            password = self.crypto.generate_password()
            
            # Store in user state
            self.user_states[user.id]['credential_password'] = password
            
            entropy_bits, strength = self.crypto.estimate_password_strength(password)
            
            await query.edit_message_text(
                f"Generated password: `{password}`\n\n"
                f"Strength: {strength} ({entropy_bits} bits)\n\n"
                "Would you like to use this password?",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("Yes", callback_data="use_generated")],
                    [InlineKeyboardButton("No, generate another", callback_data="generate_password")],
                    [InlineKeyboardButton("Enter my own", callback_data="enter_password")]
                ])
            )
            
            return ADD_CREDENTIAL_PASSWORD
        
        elif query.data == "use_generated":
            # Continue with the generated password
            await query.edit_message_text(
                "Please enter tags (comma-separated) or skip with /skip:"
            )
            
            return ADD_CREDENTIAL_TAGS
        
        elif query.data == "enter_password":
            await query.edit_message_text(
                "Please enter the password:"
            )
            
            return ADD_CREDENTIAL_PASSWORD
    
    async def add_credential_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle password input."""
        user = update.effective_user
        password = update.message.text
        
        # Store in user state
        self.user_states[user.id]['credential_password'] = password
        
        await update.message.reply_text(
            "Please enter tags (comma-separated) or skip with /skip:"
        )
        
        return ADD_CREDENTIAL_TAGS
    
    async def add_credential_tags(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle tags input."""
        user = update.effective_user
        tags_input = update.message.text
        
        # Parse tags
        tags = [tag.strip() for tag in tags_input.split(',')] if tags_input else []
        
        # Store in user state
        self.user_states[user.id]['credential_tags'] = tags
        
        await update.message.reply_text(
            "Please enter any notes or skip with /skip:"
        )
        
        return ADD_CREDENTIAL_NOTES
    
    async def add_credential_notes(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle notes input."""
        user = update.effective_user
        notes = update.message.text if update.message.text != "/skip" else ""
        
        # Store in user state
        self.user_states[user.id]['credential_notes'] = notes
        
        await update.message.reply_text(
            "Please enter a category or use 'General':"
        )
        
        return ADD_CREDENTIAL_CATEGORY
    
    async def add_credential_category(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle category input."""
        user = update.effective_user
        category = update.message.text
        
        # Store in user state
        self.user_states[user.id]['credential_category'] = category
        
        keyboard = [
            [InlineKeyboardButton("Yes", callback_data="add_totp")],
            [InlineKeyboardButton("No", callback_data="skip_totp")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "Would you like to add a TOTP secret for 2FA?",
            reply_markup=reply_markup
        )
        
        return ADD_TOTP_SECRET
    
    async def handle_totp_choice(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle TOTP choice callback."""
        query = update.callback_query
        await query.answer()
        
        user = query.from_user
        
        if query.data == "add_totp":
            await query.edit_message_text(
                "Please enter the TOTP secret:"
            )
            return ADD_TOTP_SECRET
        else:
            # Skip TOTP and save the credential
            return await self.save_credential(update, context, None)
    
    async def add_totp_secret(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle TOTP secret input."""
        user = update.effective_user
        totp_secret = update.message.text
        
        # Validate TOTP secret
        try:
            totp = self.crypto.generate_totp(totp_secret)
            # Test if the secret is valid by generating a code
            totp.now()
        except Exception as e:
            await update.message.reply_text(
                "Invalid TOTP secret. Please check and try again or /skip to continue without TOTP."
            )
            return ADD_TOTP_SECRET
        
        return await self.save_credential(update, context, totp_secret)
    
    async def save_credential(self, update: Update, context: ContextTypes.DEFAULT_TYPE, totp_secret: Optional[str] = None) -> int:
        """Save the credential to database."""
        user = update.effective_user
        
        # Get session
        session = self.session_manager.get_session(user.id)
        if not session:
            await update.message.reply_text(
                "Session expired. Please /unlock again."
            )
            return ConversationHandler.END
        
        # Get user state data
        user_state = self.user_states.get(user.id, {})
        
        name = user_state.get('credential_name')
        username = user_state.get('credential_username')
        password = user_state.get('credential_password')
        tags = user_state.get('credential_tags', [])
        notes = user_state.get('credential_notes', '')
        category = user_state.get('credential_category', 'General')
        
        if not all([name, username, password]):
            await update.message.reply_text(
                "Missing required fields. Please start over with /add"
            )
            return ConversationHandler.END
        
        try:
            # Encrypt password
            nonce, encrypted_password = self.crypto.encrypt_data(password.encode(), session['key'])
            
            # Encrypt TOTP secret if provided
            encrypted_totp = None
            totp_nonce = None
            if totp_secret:
                totp_nonce, encrypted_totp = self.crypto.encrypt_data(totp_secret.encode(), session['key'])
            
            # Save to database
            credential_id = self.storage.add_credential(
                session['user_id'], name, username, encrypted_password, nonce,
                tags, notes, category, encrypted_totp, totp_nonce
            )
            
            # Add audit log
            self.storage.add_audit_log(session['user_id'], "credential_added", f"Added credential: {name}")
            
            # Clean up user state
            if user.id in self.user_states:
                del self.user_states[user.id]
            
            await update.message.reply_text(
                f"✅ Credential '{name}' saved successfully!"
            )
            
        except Exception as e:
            logger.error("Error saving credential for user %s: %s", user.id, e)
            await update.message.reply_text(
                "❌ Error saving credential. Please try again."
            )
        
        return ConversationHandler.END
    
    async def list_credentials(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /list command."""
        user = update.effective_user
        
        # Check if user has an active session
        session = self.session_manager.get_session(user.id)
        if not session:
            await update.message.reply_text(
                "Your vault is locked. Please /unlock first."
            )
            return
        
        # Get search query from command args if provided
        search_query = ' '.join(context.args) if context.args else None
        
        # Get credentials from database
        credentials = self.storage.get_credentials(session['user_id'], search_query=search_query)
        
        if not credentials:
            await update.message.reply_text(
                "No credentials found." + (f" for search: '{search_query}'" if search_query else "")
            )
            return
        
        # Format and send response
        response = format_credential_list(credentials)
        await update.message.reply_text(response)
        
        # Add audit log
        self.storage.add_audit_log(session['user_id'], "credentials_listed", f"Listed {len(credentials)} credentials")
    
    async def cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Cancel the current conversation."""
        user = update.effective_user
        
        # Clean up user state
        if user.id in self.user_states:
            del self.user_states[user.id]
        
        await update.message.reply_text(
            "Operation cancelled."
        )
        
        return ConversationHandler.END
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /help command."""
        help_text = """
🔐 *VaultBot Help* 🔐

*Basic Commands:*
/start - Setup your vault
/unlock - Unlock your vault
/lock - Lock your vault
/add - Add a new credential
/list - List all credentials
/help - Show this help message

*Security Best Practices:*
• Use a strong, unique master password
• Enable 2FA on important accounts
• Regularly update your passwords
• Don't reuse passwords across sites
• Use the built-in password generator

Your data is encrypted with AES-256-GCM and can only be decrypted with your master password.
        """
        
        await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)
    
    async def error_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle errors in the telegram bot."""
        logger.error("Exception while handling an update:", exc_info=context.error)
        
        # Notify user of error
        if update and update.effective_message:
            await update.effective_message.reply_text(
                "An error occurred. Please try again later."
            )

# Export the conversation handler for use in main.py
def get_conversation_handler(handlers: VaultBotHandlers) -> ConversationHandler:
    """Create and return the conversation handler."""
    return ConversationHandler(
        entry_points=[
            CommandHandler('start', handlers.start),
            CommandHandler('unlock', handlers.unlock),
            CommandHandler('add', handlers.add)
        ],
        states={
            SETUP_MASTER_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.setup_master_password)
            ],
            CONFIRM_MASTER_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.confirm_master_password)
            ],
            UNLOCK_VAULT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.unlock_vault)
            ],
            ADD_CREDENTIAL_NAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.add_credential_name)
            ],
            ADD_CREDENTIAL_USERNAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.add_credential_username)
            ],
            ADD_CREDENTIAL_PASSWORD: [
                CallbackQueryHandler(handlers.handle_password_choice),
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.add_credential_password)
            ],
            ADD_CREDENTIAL_TAGS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.add_credential_tags)
            ],
            ADD_CREDENTIAL_NOTES: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.add_credential_notes)
            ],
            ADD_CREDENTIAL_CATEGORY: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.add_credential_category)
            ],
            ADD_TOTP_SECRET: [
                CallbackQueryHandler(handlers.handle_totp_choice),
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.add_totp_secret)
            ]
        },
        fallbacks=[CommandHandler('cancel', handlers.cancel)],
        per_user=True
    )

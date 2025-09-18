#!/usr/bin/env python3
"""
VaultBot - Secure Telegram Password Manager
Main entry point for the bot application.
"""
import os
import logging
import argparse
from dotenv import load_dotenv

from crypto_utils import CryptoUtils
from storage import Storage
from utils import SessionManager
from handlers import VaultBotHandlers, get_conversation_handler

# Telegram bot imports
from telegram.ext import Application, CommandHandler, MessageHandler, filters
from telegram.error import InvalidToken

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.FileHandler("vaultbot.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    """Main function to start the bot."""
    # Load environment variables
    load_dotenv()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='VaultBot - Secure Telegram Password Manager')
    parser.add_argument('--init-db', action='store_true', help='Initialize the database')
    args = parser.parse_args()
    
    # Get configuration from environment
    bot_token = os.getenv('BOT_TOKEN')
    server_pepper = os.getenv('SERVER_PEPPER')
    admin_ids = [int(id.strip()) for id in os.getenv('ADMIN_IDS', '').split(',') if id.strip()]
    session_timeout = int(os.getenv('SESSION_TIMEOUT', '600'))
    db_path = os.getenv('DB_PATH', './vaultbot.db')
    
    # Validate required environment variables
    if not bot_token:
        logger.error("BOT_TOKEN environment variable is required")
        return
    
    if not server_pepper:
        logger.error("SERVER_PEPPER environment variable is required")
        return
    
    # Initialize components
    crypto = CryptoUtils(server_pepper)
    storage = Storage(db_path)
    session_manager = SessionManager(session_timeout // 60)  # Convert to minutes
    
    # Initialize database if requested
    if args.init_db:
        storage.init_db()
        logger.info("Database initialized successfully")
        return
    
    # Create bot application
    try:
        application = Application.builder().token(bot_token).build()
    except InvalidToken:
        logger.error("Invalid bot token. Please check your BOT_TOKEN environment variable.")
        return
    
    # Initialize handlers
    handlers = VaultBotHandlers(crypto, storage, session_manager, admin_ids)
    
    # Add handlers to application
    application.add_handler(get_conversation_handler(handlers))
    application.add_handler(CommandHandler('lock', handlers.lock))
    application.add_handler(CommandHandler('list', handlers.list_credentials))
    application.add_handler(CommandHandler('help', handlers.help_command))
    
    # Add error handler
    application.add_error_handler(handlers.error_handler)
    
    # Start the bot
    logger.info("Starting VaultBot...")
    application.run_polling()

if __name__ == '__main__':
    main()

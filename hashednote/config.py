"""
Secure Notes - Configuration Module
Centralized configuration for the application.
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / 'data'
DB_PATH = DATA_DIR / 'secure_notes.db'
LOGS_DIR = BASE_DIR / 'logs'

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# Cryptography settings
CRYPTO_SETTINGS = {
    'rsa_key_size': 2048,
    'bcrypt_rounds': 12,
    'pbkdf2_iterations': 100000,
    'aes_key_size': 256,
}

# UI Settings
UI_SETTINGS = {
    'window_width': 900,
    'window_height': 700,
    'login_width': 450,
    'login_height': 550,
    'font_family': 'Segoe UI',
    'font_size': 11,
    'monospace_font': 'Consolas',
}

# Colors
COLORS = {
    'primary': '#2196F3',
    'primary_dark': '#1976D2',
    'primary_light': '#BBDEFB',
    'accent': '#FF4081',
    'text_primary': '#212121',
    'text_secondary': '#757575',
    'divider': '#BDBDBD',
    'background': '#FAFAFA',
    'surface': '#FFFFFF',
    'error': '#F44336',
    'success': '#4CAF50',
}

# Logging
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

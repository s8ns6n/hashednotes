# Secure Notes Application

A secure, multi-user note-taking application with end-to-end encryption.

## Features

- **Multi-user support**: Register and login with different accounts
- **Strong encryption**: RSA-2048 + AES-256-GCM for note encryption
- **Secure passwords**: bcrypt hashing with automatic salting
- **Modern UI**: Clean, styled interface with ttk themes
- **Auto-save**: Saves notes on Ctrl+S and application close
- **Logging**: Comprehensive logging for debugging and monitoring

## Security

- **Password Hashing**: bcrypt with 12 rounds and automatic salt
- **Asymmetric Encryption**: RSA-2048 for key exchange
- **Symmetric Encryption**: AES-256-GCM for note content
- **Key Protection**: Private keys encrypted with password-derived keys
- **Hybrid Encryption**: Combines RSA and AES for optimal security and performance

## Project Structure

```
hashednote/
├── main.py                 # Application entry point
├── config.py               # Configuration and constants
├── models.py               # Data models (User, Note, etc.)
├── database.py             # Database operations
├── crypto_manager.py       # Encryption/decryption operations
├── validators.py           # Input validation
├── requirements.txt        # Python dependencies
├── gui/                    # GUI package
│   ├── __init__.py
│   ├── styles.py          # UI styling and themes
│   ├── login_window.py    # Login/registration UI
│   └── notepad_window.py  # Note editor UI
├── data/                  # Database storage (created at runtime)
└── logs/                  # Application logs (created at runtime)
```

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python main.py
```

## Usage

1. **First Time**: Click "Register" to create a new account
   - Username: 3-50 characters, alphanumeric + underscore/hyphen
   - Password: Minimum 8 characters

2. **Login**: Enter your credentials and click "Login"

3. **Take Notes**: Type in the editor window
   - Use Ctrl+S or click "Save" to save
   - Notes are automatically encrypted
   - Click "Logout" or close to exit

4. **Logout/Exit**: If you have unsaved changes, you'll be prompted to save

## Architecture

### Single Responsibility Principle

Each file and function has a clear, single purpose:

- **config.py**: Centralized configuration
- **models.py**: Data structures
- **database.py**: Database operations only
- **crypto_manager.py**: Cryptographic operations only
- **validators.py**: Input validation only
- **gui/**: User interface components
  - **styles.py**: Visual styling
  - **login_window.py**: Authentication UI
  - **notepad_window.py**: Note editing UI

### Clean Code Practices

- **Descriptive Names**: Functions and variables clearly describe their purpose
- **Small Functions**: Each function does one thing and does it well
- **Type Hints**: Clear type annotations for better code understanding
- **Docstrings**: Comprehensive documentation for all public functions
- **Error Handling**: Proper exception handling with logging
- **Logging**: Detailed logging for debugging and monitoring

## License

This project is for educational purposes.

"""
Secure Notes - Login Window
Handles user login and registration interface.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import logging

from config import UI_SETTINGS, COLORS
from models import User
from database import DatabaseManager
from validators import InputValidator
from gui.styles import StyleManager, CenteredWindowMixin

logger = logging.getLogger(__name__)


class LoginWindow(CenteredWindowMixin):
    """Window for user authentication and registration."""
    
    def __init__(self, root: tk.Tk, db_manager: DatabaseManager, on_login_success) -> None:
        """Initialize the login window.
        
        Args:
            root: The root tkinter window
            db_manager: The database manager instance
            on_login_success: Callback function called on successful login
        """
        self.root = root
        self.db_manager = db_manager
        self.on_login_success = on_login_success
        
        self._setup_window()
        self._create_widgets()
        self._bind_events()
        
        # Initialize UI state
        self._on_mode_change()
    
    def _setup_window(self) -> None:
        """Configure the window properties."""
        self.root.title("Secure Notes - Login")
        self.root.geometry(f"{UI_SETTINGS['login_width']}x{UI_SETTINGS['login_height']}")
        self.root.resizable(False, False)
        self.root.configure(bg=COLORS['background'])
        
        # Apply styles
        StyleManager.setup_styles()
        
        # Center window
        self.center_window(self.root)
    
    def _create_widgets(self) -> None:
        """Create and layout all UI widgets."""
        # Main container
        self.main_frame = ttk.Frame(self.root, style='Main.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        # Title section
        self._create_title_section()
        
        # Form section
        self._create_form_section()
        
        # Button section
        self._create_button_section()
        
        # Footer section
        self._create_footer_section()
    
    def _create_title_section(self) -> None:
        """Create the title and subtitle labels."""
        # App icon/emoji
        icon_label = ttk.Label(
            self.main_frame,
            text="🔐",
            font=(UI_SETTINGS['font_family'], 48),
            background=COLORS['background']
        )
        icon_label.pack(pady=(0, 10))
        
        # Title
        self.title_label = ttk.Label(
            self.main_frame,
            text="Secure Notes",
            style='Title.TLabel'
        )
        self.title_label.pack()
        
        # Subtitle
        self.subtitle_label = ttk.Label(
            self.main_frame,
            text="Login or Create Account",
            style='Subtitle.TLabel'
        )
        self.subtitle_label.pack(pady=(0, 30))
    
    def _create_form_section(self) -> None:
        """Create the form input fields."""
        # Username
        self.username_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        self.username_frame.pack(fill=tk.X, pady=5)
        
        self.username_label = ttk.Label(
            self.username_frame,
            text="Username",
            style='Label.TLabel'
        )
        self.username_label.pack(anchor=tk.W)
        
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(
            self.username_frame,
            textvariable=self.username_var,
            style='Custom.TEntry',
            width=40
        )
        self.username_entry.pack(fill=tk.X, pady=(5, 0), ipady=5)
        
        # Password
        self.password_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        self.password_frame.pack(fill=tk.X, pady=5)
        
        self.password_label = ttk.Label(
            self.password_frame,
            text="Password",
            style='Label.TLabel'
        )
        self.password_label.pack(anchor=tk.W)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            self.password_frame,
            textvariable=self.password_var,
            style='Custom.TEntry',
            show="●",
            width=40
        )
        self.password_entry.pack(fill=tk.X, pady=(5, 0), ipady=5)
        
        # Confirm Password (for registration)
        self.confirm_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        self.confirm_frame.pack(fill=tk.X, pady=5)
        
        self.confirm_label = ttk.Label(
            self.confirm_frame,
            text="Confirm Password",
            style='Label.TLabel'
        )
        self.confirm_label.pack(anchor=tk.W)
        
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(
            self.confirm_frame,
            textvariable=self.confirm_var,
            style='Custom.TEntry',
            show="●",
            width=40
        )
        self.confirm_entry.pack(fill=tk.X, pady=(5, 0), ipady=5)
        
        # Mode indicator
        self.mode_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        self.mode_frame.pack(pady=(10, 0), fill=tk.X)
        
        self.mode_var = tk.StringVar(value="login")
        
        self.login_radio = ttk.Radiobutton(
            self.mode_frame,
            text="Login",
            variable=self.mode_var,
            value="login",
            command=self._on_mode_change
        )
        self.login_radio.pack(side=tk.LEFT, padx=(0, 20))
        
        self.register_radio = ttk.Radiobutton(
            self.mode_frame,
            text="Register New Account",
            variable=self.mode_var,
            value="register",
            command=self._on_mode_change
        )
        self.register_radio.pack(side=tk.LEFT)
    
    def _create_button_section(self) -> None:
        """Create the action buttons."""
        self.button_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        self.button_frame.pack(fill=tk.X, pady=30)
        
        self.login_button = ttk.Button(
            self.button_frame,
            text="Login",
            command=self._handle_submit,
            style='Primary.TButton'
        )
        self.login_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        
        self.register_button = ttk.Button(
            self.button_frame,
            text="Switch to Register",
            command=self._toggle_mode,
            style='Secondary.TButton'
        )
        self.register_button.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))
    
    def _create_footer_section(self) -> None:
        """Create the footer with security info."""
        self.footer_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        self.footer_frame.pack(fill=tk.X, pady=(20, 0))
        
        security_text = "🔒 RSA-2048 | AES-256-GCM | bcrypt"
        self.security_label = ttk.Label(
            self.footer_frame,
            text=security_text,
            font=(UI_SETTINGS['font_family'], 9),
            foreground=COLORS['text_secondary'],
            background=COLORS['background']
        )
        self.security_label.pack()
    
    def _on_mode_change(self) -> None:
        """Handle mode switch between login and register."""
        mode = self.mode_var.get()
        if mode == "login":
            self.confirm_frame.pack_forget()
            self.login_button.config(text="Login")
            self.register_button.config(text="Switch to Register")
            self.root.title("Secure Notes - Login")
        else:
            self.confirm_frame.pack(fill=tk.X, pady=5, after=self.password_frame)
            self.login_button.config(text="Create Account")
            self.register_button.config(text="Switch to Login")
            self.root.title("Secure Notes - Register")
        
        # Clear form fields when switching modes
        self.confirm_var.set("")
    
    def _toggle_mode(self) -> None:
        """Toggle between login and register modes."""
        current_mode = self.mode_var.get()
        if current_mode == "login":
            self.mode_var.set("register")
        else:
            self.mode_var.set("login")
        self._on_mode_change()
    
    def _bind_events(self) -> None:
        """Bind keyboard and other events."""
        self.root.bind('<Return>', lambda e: self._handle_submit())
    
    def _handle_submit(self) -> None:
        """Handle form submission based on current mode."""
        mode = self.mode_var.get()
        if mode == "login":
            self._handle_login()
        else:
            self._handle_register()
    
    def _get_form_data(self) -> tuple[str, str, str]:
        """Get and clean form data.
        
        Returns:
            Tuple of (username, password, confirm_password)
        """
        username = self.username_var.get().strip()
        password = self.password_var.get()
        confirm_password = self.confirm_var.get()
        return username, password, confirm_password
    
    def _handle_login(self) -> None:
        """Handle the login button click."""
        username, password, _ = self._get_form_data()
        
        # Validate input
        is_valid, error = InputValidator.validate_login(username, password)
        if not is_valid:
            messagebox.showerror("Validation Error", error)
            return
        
        # Attempt authentication
        result = self.db_manager.authenticate_user(username, password)
        
        if result.success:
            logger.info(f"User '{username}' logged in successfully")
            self.on_login_success(result.user)
        else:
            logger.warning(f"Login failed for user '{username}': {result.error_message}")
            messagebox.showerror("Login Failed", result.error_message)
    
    def _handle_register(self) -> None:
        """Handle the register button click."""
        username, password, confirm_password = self._get_form_data()
        
        # Debug logging
        logger.debug(f"Registration attempt - Username: {username}, Password length: {len(password)}, Confirm length: {len(confirm_password)}")
        
        # Validate input
        is_valid, error = InputValidator.validate_registration(
            username, password, confirm_password
        )
        if not is_valid:
            logger.warning(f"Registration validation failed: {error}")
            messagebox.showerror("Validation Error", error)
            return
        
        # Attempt registration
        logger.info(f"Attempting to register user: {username}")
        result = self.db_manager.register_user(username, password)
        
        if result.success:
            logger.info(f"User '{username}' registered successfully with ID: {result.user_id}")
            messagebox.showinfo("Success", f"User '{username}' registered successfully!\n\nYou can now login.")
            # Clear all fields after successful registration
            self.confirm_var.set("")
            self.password_var.set("")
            self.username_var.set("")
        else:
            logger.warning(f"Registration failed for '{username}': {result.message}")
            messagebox.showerror("Registration Failed", result.message)

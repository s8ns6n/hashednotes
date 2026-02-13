"""
Secure Notes - Notepad Window
Handles the note editing interface.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import logging

from config import UI_SETTINGS, COLORS
from models import User
from database import DatabaseManager
from crypto_manager import CryptoManager
from gui.styles import StyleManager, CenteredWindowMixin

logger = logging.getLogger(__name__)


class NotepadWindow(CenteredWindowMixin):
    """Window for editing encrypted notes."""
    
    def __init__(
        self,
        root: tk.Tk,
        db_manager: DatabaseManager,
        user: User,
        on_logout
    ) -> None:
        """Initialize the notepad window.
        
        Args:
            root: The root tkinter window
            db_manager: The database manager instance
            user: The authenticated user
            on_logout: Callback function called on logout
        """
        self.root = root
        self.db_manager = db_manager
        self.user = user
        self.on_logout = on_logout
        self.has_unsaved_changes = False
        
        self._setup_window()
        self._create_menu()
        self._create_widgets()
        self._bind_events()
        self._load_notes()
    
    def _setup_window(self) -> None:
        """Configure the window properties."""
        self.root.title(f"Secure Notes - {self.user.username}")
        self.root.geometry(
            f"{UI_SETTINGS['window_width']}x{UI_SETTINGS['window_height']}"
        )
        self.root.configure(bg=COLORS['surface'])
        
        # Apply styles
        StyleManager.setup_styles()
        
        # Center window
        self.center_window(self.root)
    
    def _create_menu(self) -> None:
        """Create the menu bar."""
        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)
        
        # File menu
        self.file_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(
            label="Save",
            command=self._save_notes,
            accelerator="Ctrl+S"
        )
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Logout", command=self._handle_logout)
        self.file_menu.add_command(label="Exit", command=self._handle_exit)
        
        # Edit menu
        self.edit_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Edit", menu=self.edit_menu)
        self.edit_menu.add_command(
            label="Cut",
            command=lambda: self.text_area.event_generate("<<Cut>>"),
            accelerator="Ctrl+X"
        )
        self.edit_menu.add_command(
            label="Copy",
            command=lambda: self.text_area.event_generate("<<Copy>>"),
            accelerator="Ctrl+C"
        )
        self.edit_menu.add_command(
            label="Paste",
            command=lambda: self.text_area.event_generate("<<Paste>>"),
            accelerator="Ctrl+V"
        )
        self.edit_menu.add_separator()
        self.edit_menu.add_command(
            label="Select All",
            command=lambda: self.text_area.event_generate("<<SelectAll>>"),
            accelerator="Ctrl+A"
        )
    
    def _create_widgets(self) -> None:
        """Create and layout all UI widgets."""
        # Main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create toolbar
        self._create_toolbar()
        
        # Create text area
        self._create_text_area()
        
        # Create status bar
        self._create_status_bar()
    
    def _create_toolbar(self) -> None:
        """Create the toolbar with action buttons."""
        self.toolbar = ttk.Frame(self.main_container)
        self.toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        # Save button
        self.save_btn = ttk.Button(
            self.toolbar,
            text="💾 Save",
            command=self._save_notes,
            style='Primary.TButton'
        )
        self.save_btn.pack(side=tk.LEFT, padx=2)
        
        # Separator
        ttk.Separator(self.toolbar, orient='vertical').pack(
            side=tk.LEFT, fill=tk.Y, padx=10, pady=5
        )
        
        # Logout button
        self.logout_btn = ttk.Button(
            self.toolbar,
            text="Logout",
            command=self._handle_logout,
            style='Secondary.TButton'
        )
        self.logout_btn.pack(side=tk.RIGHT, padx=2)
    
    def _create_text_area(self) -> None:
        """Create the main text editing area."""
        self.text_frame = ttk.Frame(self.main_container)
        self.text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.text_area = scrolledtext.ScrolledText(
            self.text_frame,
            wrap=tk.WORD,
            font=(UI_SETTINGS['monospace_font'], 12),
            padx=15,
            pady=15,
            undo=True,
            maxundo=-1,
            bg=COLORS['surface'],
            fg=COLORS['text_primary'],
            insertbackground=COLORS['primary'],
            selectbackground=COLORS['primary_light'],
            selectforeground=COLORS['text_primary']
        )
        self.text_area.pack(fill=tk.BOTH, expand=True)
    
    def _create_status_bar(self) -> None:
        """Create the status bar."""
        self.status_frame = ttk.Frame(self.main_container)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(
            self.status_frame,
            text="Ready",
            style='StatusBar.TLabel'
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.user_label = ttk.Label(
            self.status_frame,
            text=f"👤 {self.user.username}",
            style='StatusBar.TLabel'
        )
        self.user_label.pack(side=tk.RIGHT)
    
    def _bind_events(self) -> None:
        """Bind keyboard and window events."""
        # Text change detection
        self.text_area.bind('<KeyRelease>', self._on_text_modified)
        self.text_area.bind('<ButtonRelease>', self._on_text_modified)
        
        # Save shortcuts
        self.root.bind('<Control-s>', lambda e: self._save_notes())
        self.root.bind('<Control-S>', lambda e: self._save_notes())
        
        # Window close
        self.root.protocol("WM_DELETE_WINDOW", self._handle_exit)
    
    def _on_text_modified(self, event=None) -> None:
        """Handle text modifications."""
        if not self.has_unsaved_changes:
            self.has_unsaved_changes = True
            self._update_title()
    
    def _update_title(self) -> None:
        """Update the window title to show unsaved changes."""
        title = f"Secure Notes - {self.user.username}"
        if self.has_unsaved_changes:
            title += " ●"
        self.root.title(title)
    
    def _load_notes(self) -> None:
        """Load and decrypt notes from the database."""
        try:
            encrypted_content = self.db_manager.get_user_notes(self.user.id)
            
            if encrypted_content:
                # Decrypt notes
                decrypted_content = CryptoManager.decrypt_note_content(
                    encrypted_content,
                    self.user.private_key
                )
                
                self.text_area.delete('1.0', tk.END)
                self.text_area.insert('1.0', decrypted_content)
                
                # Reset modification flag
                self.has_unsaved_changes = False
                self._update_title()
                
                self._update_status("Notes loaded successfully")
                logger.info(f"Loaded notes for user '{self.user.username}'")
            else:
                self._update_status("No existing notes found")
                logger.info(f"No notes found for user '{self.user.username}'")
        
        except Exception as e:
            logger.error(f"Failed to load notes: {e}")
            messagebox.showerror("Error", f"Failed to load notes: {str(e)}")
            self._update_status("Error loading notes")
    
    def _save_notes(self) -> None:
        """Encrypt and save notes to the database."""
        try:
            content = self.text_area.get('1.0', tk.END)
            
            # Encrypt notes
            encrypted_content = CryptoManager.encrypt_note_content(
                content,
                self.user.public_key
            )
            
            # Save to database
            self.db_manager.save_user_notes(self.user.id, encrypted_content)
            
            # Update state
            self.has_unsaved_changes = False
            self._update_title()
            
            timestamp = datetime.now().strftime('%H:%M:%S')
            self._update_status(f"Saved at {timestamp}")
            logger.info(f"Saved notes for user '{self.user.username}'")
        
        except Exception as e:
            logger.error(f"Failed to save notes: {e}")
            messagebox.showerror("Error", f"Failed to save notes: {str(e)}")
            self._update_status("Error saving notes")
    
    def _update_status(self, message: str) -> None:
        """Update the status bar message.
        
        Args:
            message: The status message to display
        """
        self.status_label.config(text=message)
    
    def _confirm_save(self, action: str) -> bool | None:
        """Ask user if they want to save unsaved changes.
        
        Args:
            action: The action being performed (e.g., "logout", "exit")
            
        Returns:
            True if should proceed, False if should cancel, None if dialog dismissed
        """
        if not self.has_unsaved_changes:
            return True
        
        response = messagebox.askyesnocancel(
            "Unsaved Changes",
            f"You have unsaved changes. Save before {action}?"
        )
        
        if response is True:
            self._save_notes()
            return True
        elif response is False:
            return True
        else:  # Cancel
            return None
    
    def _handle_logout(self) -> None:
        """Handle logout with unsaved changes check."""
        should_proceed = self._confirm_save("logout")
        
        if should_proceed is None:
            return
        
        logger.info(f"User '{self.user.username}' logged out")
        
        # Clear sensitive data
        self.user = None
        
        # Trigger logout callback
        self.on_logout()
    
    def _handle_exit(self) -> None:
        """Handle application exit with unsaved changes check."""
        should_proceed = self._confirm_save("exit")
        
        if should_proceed is None:
            return
        
        logger.info("Application closing")
        self.root.destroy()

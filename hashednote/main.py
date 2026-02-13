"""
Secure Notes - Main Application Entry Point
Secure note-taking application with asymmetric encryption.
"""

import tkinter as tk
import logging
import sys
from pathlib import Path

# Add the project directory to the path
project_dir = Path(__file__).parent
if str(project_dir) not in sys.path:
    sys.path.insert(0, str(project_dir))

from config import LOGS_DIR, LOG_LEVEL, LOG_FORMAT
from database import DatabaseManager
from models import User
from gui import LoginWindow, NotepadWindow


def setup_logging() -> None:
    """Configure application logging."""
    log_file = LOGS_DIR / 'secure_notes.log'
    
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format=LOG_FORMAT,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )


class SecureNotesApp:
    """Main application controller."""
    
    def __init__(self) -> None:
        """Initialize the application."""
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting Secure Notes application")
        
        # Initialize main window
        self.root = tk.Tk()
        self.db_manager = DatabaseManager()
        self.current_user: User | None = None
        
        # Show login screen
        self._show_login_screen()
    
    def _show_login_screen(self) -> None:
        """Display the login window."""
        self.logger.debug("Showing login screen")
        
        # Clear existing widgets
        self._clear_window()
        
        # Create login window
        LoginWindow(
            root=self.root,
            db_manager=self.db_manager,
            on_login_success=self._on_login_success
        )
    
    def _show_notepad_screen(self) -> None:
        """Display the notepad window."""
        if not self.current_user:
            self.logger.error("Attempted to show notepad without logged in user")
            self._show_login_screen()
            return
        
        self.logger.debug(f"Showing notepad screen for user '{self.current_user.username}'")
        
        # Clear existing widgets
        self._clear_window()
        
        # Create notepad window
        NotepadWindow(
            root=self.root,
            db_manager=self.db_manager,
            user=self.current_user,
            on_logout=self._on_logout
        )
    
    def _clear_window(self) -> None:
        """Remove all widgets from the root window."""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def _on_login_success(self, user: User) -> None:
        """Handle successful user login.
        
        Args:
            user: The authenticated user
        """
        self.logger.info(f"User '{user.username}' logged in successfully")
        self.current_user = user
        self._show_notepad_screen()
    
    def _on_logout(self) -> None:
        """Handle user logout."""
        if self.current_user:
            self.logger.info(f"User '{self.current_user.username}' logged out")
        
        self.current_user = None
        self._show_login_screen()
    
    def run(self) -> None:
        """Start the application main loop."""
        try:
            self.logger.info("Application running")
            self.root.mainloop()
        except Exception as e:
            self.logger.exception("Application error")
            raise
        finally:
            self.logger.info("Application shutting down")
            self.db_manager.close()


def main() -> None:
    """Application entry point."""
    setup_logging()
    
    try:
        app = SecureNotesApp()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()

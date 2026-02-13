"""
Secure Notes - GUI Styles
Defines visual styles and themes for the application.
"""

import tkinter as tk
from tkinter import ttk
from config import COLORS, UI_SETTINGS


class StyleManager:
    """Manages application-wide visual styles."""
    
    @staticmethod
    def setup_styles() -> None:
        """Configure ttk styles for the entire application."""
        style = ttk.Style()
        
        # Configure the main theme
        style.theme_use('clam')
        
        # Frame styles
        style.configure(
            'Main.TFrame',
            background=COLORS['background']
        )
        
        # Label styles
        style.configure(
            'Title.TLabel',
            font=(UI_SETTINGS['font_family'], 24, 'bold'),
            foreground=COLORS['primary'],
            background=COLORS['background']
        )
        
        style.configure(
            'Subtitle.TLabel',
            font=(UI_SETTINGS['font_family'], 12),
            foreground=COLORS['text_secondary'],
            background=COLORS['background']
        )
        
        style.configure(
            'Label.TLabel',
            font=(UI_SETTINGS['font_family'], UI_SETTINGS['font_size']),
            foreground=COLORS['text_primary'],
            background=COLORS['background']
        )
        
        style.configure(
            'Error.TLabel',
            font=(UI_SETTINGS['font_family'], 10),
            foreground=COLORS['error'],
            background=COLORS['background']
        )
        
        style.configure(
            'Success.TLabel',
            font=(UI_SETTINGS['font_family'], 10),
            foreground=COLORS['success'],
            background=COLORS['background']
        )
        
        # Entry styles
        style.configure(
            'Custom.TEntry',
            font=(UI_SETTINGS['font_family'], UI_SETTINGS['font_size']),
            fieldbackground=COLORS['surface'],
            foreground=COLORS['text_primary']
        )
        
        # Button styles
        style.configure(
            'Primary.TButton',
            font=(UI_SETTINGS['font_family'], UI_SETTINGS['font_size'], 'bold'),
            background=COLORS['primary'],
            foreground='white',
            padding=(20, 10)
        )
        style.map(
            'Primary.TButton',
            background=[('active', COLORS['primary_dark']), ('pressed', COLORS['primary_dark'])],
            foreground=[('active', 'white'), ('pressed', 'white')]
        )
        
        style.configure(
            'Secondary.TButton',
            font=(UI_SETTINGS['font_family'], UI_SETTINGS['font_size']),
            background=COLORS['surface'],
            foreground=COLORS['primary'],
            padding=(20, 10)
        )
        style.map(
            'Secondary.TButton',
            background=[('active', COLORS['primary_light'])],
            foreground=[('active', COLORS['primary_dark'])]
        )
        
        # Status bar style
        style.configure(
            'StatusBar.TLabel',
            font=(UI_SETTINGS['font_family'], 9),
            foreground=COLORS['text_secondary'],
            background=COLORS['surface'],
            relief='sunken',
            padding=(10, 5)
        )


class CenteredWindowMixin:
    """Mixin to center windows on screen."""
    
    def center_window(self, window: tk.Tk | tk.Toplevel) -> None:
        """Center a window on the screen.
        
        Args:
            window: The window to center
        """
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')

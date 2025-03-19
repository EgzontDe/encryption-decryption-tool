#!/usr/bin/env python3
"""
Launcher module for the encryption toolkit.
"""
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import importlib


def launch_launcher():
    """Launch the main launcher application"""
    # Import the root launcher and run it
    # Get the project root directory (3 levels up from this file)
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Add the root directory to sys.path temporarily
    sys.path.insert(0, root_dir)
    
    try:
        # Import the launcher module from the root directory
        import launcher
        launcher.main()
    except ImportError as e:
        messagebox.showerror("Error", f"Failed to import launcher module: {str(e)}")
    finally:
        # Remove the root directory from sys.path
        if root_dir in sys.path:
            sys.path.remove(root_dir)
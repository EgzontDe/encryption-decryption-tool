#!/usr/bin/env python3
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
from src.utils import file_manager
from ttkbootstrap import Style

class LauncherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Toolkit Launcher")
        self.root.geometry("900x600")
        
        style = Style(theme='superhero')
        
        # Main frame
        main_frame = ttk.Frame(root, padding=20)
        main_frame.pack(fill="both", expand=True)
        
        # Title and description
        title_label = ttk.Label(
            main_frame, 
            text="Advanced Encryption Toolkit", 
            font=("", 16, "bold")
        )
        title_label.pack(pady=10)
        
        description = (
            "A comprehensive toolkit for secure encryption, decryption, "
            "and file management with advanced security features."
        )
        desc_label = ttk.Label(main_frame, text=description, wraplength=500)
        desc_label.pack(pady=10)
        
        # Applications frame
        apps_frame = ttk.LabelFrame(main_frame, text="Applications", padding=10)
        apps_frame.pack(fill="x", padx=20, pady=10)
        
        # Application buttons
        self.create_app_button(
            apps_frame, 
            "Symmetric Encryption", 
            "AES encryption with multiple modes (ECB, CTR, CBC, GCM)",
            self.launch_symmetric_encryption
        )
        
        self.create_app_button(
            apps_frame, 
            "Asymmetric Encryption", 
            "RSA encryption with digital signatures and key management",
            self.launch_asymmetric_encryption
        )
        
        self.create_app_button(
            apps_frame, 
            "File Browser", 
            "Manage encrypted files, keys, and signatures",
            self.launch_file_browser
        )
        
        self.create_app_button(
            apps_frame, 
            "Tampering Tool", 
            "Educational tool for demonstrating encryption vulnerabilities",
            self.launch_tampering_tool
        )
        
        # System status frame
        status_frame = ttk.LabelFrame(main_frame, text="System Status", padding=10)
        status_frame.pack(fill="x", padx=20, pady=10)
        
        # Check system status
        self.update_system_status(status_frame)
        
        # Status bar
        status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(root, textvariable=status_var, relief="sunken", anchor="w")
        status_bar.pack(side="bottom", fill="x")
    
    def create_app_button(self, parent, title, description, command):
        """Create a button for launching an application"""
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=5)
        
        ttk.Label(frame, text=title, font=("", 12, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(frame, text=description, wraplength=400).grid(row=1, column=0, sticky="w")
        
        launch_button = ttk.Button(frame, text="Launch", command=command, style="primary.TButton")
        launch_button.grid(row=0, column=1, rowspan=2, padx=10, sticky="e")
        
        # Configure grid to expand properly
        frame.columnconfigure(0, weight=1)
    
    def update_system_status(self, parent):
        """Check and display system status"""
        # Clear the frame
        for widget in parent.winfo_children():
            widget.destroy()
        
        # Check directories
        file_manager.ensure_directories()
        
        # Get files counts
        encrypted_files = len(file_manager.list_files(category="encrypted"))
        decrypted_files = len(file_manager.list_files(category="decrypted"))
        keys = len(file_manager.list_files(category="private_key")) + len(file_manager.list_files(category="public_key"))
        signatures = len(file_manager.list_files(category="signature"))
        
        # Display status
        status_items = [
            ("Encrypted Files:", f"{encrypted_files} files"),
            ("Decrypted Files:", f"{decrypted_files} files"),
            ("Keys:", f"{keys} keys"),
            ("Signatures:", f"{signatures} signatures"),
        ]
        
        for row, (label, value) in enumerate(status_items):
            ttk.Label(parent, text=label, font=("", 10, "bold")).grid(row=row, column=0, sticky="w", padx=5, pady=3)
            ttk.Label(parent, text=value).grid(row=row, column=1, sticky="w", padx=5, pady=3)
        
        # Add refresh button
        ttk.Button(
            parent, 
            text="Refresh", 
            command=lambda: self.update_system_status(parent),
            style="info.Outline.TButton"
        ).grid(row=len(status_items), column=0, columnspan=2, pady=5)
    
    def launch_symmetric_encryption(self):
        """Launch the symmetric encryption application"""
        try:
            subprocess.Popen([sys.executable, "-m", "src.core.main"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch symmetric encryption app: {str(e)}")
    
    def launch_asymmetric_encryption(self):
        """Launch the asymmetric encryption application"""
        try:
            subprocess.Popen([sys.executable, "-m", "src.core.asym"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch asymmetric encryption app: {str(e)}")
    
    def launch_file_browser(self):
        """Launch the file browser application"""
        try:
            subprocess.Popen([sys.executable, "-m", "src.gui.file_browser"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch file browser app: {str(e)}")
    
    def launch_tampering_tool(self):
        """Launch the tampering tool"""
        try:
            subprocess.Popen([sys.executable, "-m", "src.utils.tamper_with_encryption", "--gui"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch tampering tool: {str(e)}")


def main():
    # Make sure directories exist
    file_manager.ensure_directories()
    
    # Create the root window
    root = tk.Tk()
    app = LauncherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
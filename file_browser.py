import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import file_manager
import datetime
import shutil
from ttkbootstrap import Style

class FileBrowserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption File Browser")
        self.root.geometry("900x600")
        
        # Create the main frame with tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both", padx=5, pady=5)
        
        # Create tabs for different file categories
        self.create_file_browser_tab("All Files", None)
        self.create_file_browser_tab("Encrypted Files", "encrypted")
        self.create_file_browser_tab("Decrypted Files", "decrypted")
        self.create_file_browser_tab("Keys", "private_key")
        self.create_file_browser_tab("Signatures", "signature")
        self.create_file_browser_tab("Logs", "log")
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.pack(side="bottom", fill="x")
        
        # Initialize directory structure
        file_manager.ensure_directories()
        
        # Refresh all tabs
        self.refresh_all_tabs()
    
    def create_file_browser_tab(self, tab_name, category):
        """Create a tab with file browser for the given category"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=tab_name)
        
        # Top frame with controls
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        # Search entry
        ttk.Label(control_frame, text="Search:").pack(side="left", padx=5)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(control_frame, textvariable=search_var, width=30)
        search_entry.pack(side="left", padx=5)
        
        # Search button
        search_button = ttk.Button(
            control_frame, 
            text="Search", 
            command=lambda: self.refresh_file_list(tab, category, search_var.get())
        )
        search_button.pack(side="left", padx=5)
        
        # Refresh button
        refresh_button = ttk.Button(
            control_frame, 
            text="Refresh", 
            command=lambda: self.refresh_file_list(tab, category)
        )
        refresh_button.pack(side="left", padx=5)
        
        # Import button
        import_button = ttk.Button(
            control_frame, 
            text="Import File", 
            command=lambda: self.import_file(category)
        )
        import_button.pack(side="right", padx=5)
        
        # File list with scrollbar
        list_frame = ttk.Frame(tab)
        list_frame.pack(expand=True, fill="both", padx=5, pady=5)
        
        columns = ("Filename", "Size", "Modified", "Category", "Path")
        file_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20)
        file_tree.tag_configure("encrypted", background="#e6f7ff")
        file_tree.tag_configure("decrypted", background="#e6ffe6")
        file_tree.tag_configure("private_key", background="#fff2e6")
        file_tree.tag_configure("public_key", background="#fff2e6")
        file_tree.tag_configure("signature", background="#f7e6ff")
        file_tree.tag_configure("log", background="#f2f2f2")
        
        # Define column headings and widths
        file_tree.heading("Filename", text="Filename")
        file_tree.heading("Size", text="Size")
        file_tree.heading("Modified", text="Modified")
        file_tree.heading("Category", text="Type")
        file_tree.heading("Path", text="Path")
        
        file_tree.column("Filename", width=200)
        file_tree.column("Size", width=80)
        file_tree.column("Modified", width=150)
        file_tree.column("Category", width=100)
        file_tree.column("Path", width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=file_tree.yview)
        file_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        file_tree.pack(side="left", expand=True, fill="both")
        
        # Store references to the tree view for refreshing
        tab.file_tree = file_tree
        tab.search_var = search_var
        tab.category = category
        
        # Add right-click menu
        self.create_context_menu(tab, file_tree)
        
        # Add double-click action
        file_tree.bind("<Double-1>", lambda event: self.view_file_details(tab))
        
        return tab
    
    def create_context_menu(self, tab, tree):
        """Create right-click context menu for file operations"""
        menu = tk.Menu(tree, tearoff=0)
        
        # Add menu items
        menu.add_command(label="View Details", command=lambda: self.view_file_details(tab))
        menu.add_command(label="Open File", command=lambda: self.open_file(tab))
        menu.add_command(label="Export File", command=lambda: self.export_file(tab))
        menu.add_separator()
        menu.add_command(label="Move File", command=lambda: self.move_file(tab))
        menu.add_command(label="Delete File", command=lambda: self.delete_file(tab))
        
        # Bind the menu to right-click
        tree.bind("<Button-3>", lambda event: self.show_context_menu(event, menu))
    
    def show_context_menu(self, event, menu):
        """Display the context menu on right-click"""
        menu.post(event.x_root, event.y_root)
    
    def refresh_file_list(self, tab, category, search_pattern=None):
        """Refresh the file list in the given tab"""
        try:
            # Clear the current list
            file_tree = tab.file_tree
            for item in file_tree.get_children():
                file_tree.delete(item)
            
            # Get the list of files
            files = file_manager.list_files(category=category, pattern=search_pattern)
            
            # Add files to the tree
            for file_path in files:
                try:
                    file_info = file_manager.get_file_info(file_path)
                    
                    # Format size
                    size_kb = file_info["size"] / 1024
                    if size_kb < 1024:
                        size_str = f"{size_kb:.1f} KB"
                    else:
                        size_str = f"{size_kb/1024:.1f} MB"
                    
                    # Format date
                    try:
                        mod_time = datetime.datetime.fromisoformat(file_info["modified"])
                        mod_str = mod_time.strftime("%Y-%m-%d %H:%M")
                    except:
                        mod_str = "Unknown"
                    
                    # Add to tree
                    file_tree.insert(
                        "", 
                        "end", 
                        values=(
                            file_info["filename"], 
                            size_str, 
                            mod_str, 
                            file_info["category"],
                            file_info["path"]
                        ),
                        tags=(file_info["category"],)
                    )
                except Exception as e:
                    # Skip any files that cause errors
                    print(f"Error processing file {file_path}: {str(e)}")
            
            # Update status
            self.status_var.set(f"Found {len(files)} files")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error refreshing file list: {str(e)}")
    
    def refresh_all_tabs(self):
        """Refresh all file browser tabs"""
        for tab_id in range(self.notebook.index("end")):
            tab = self.notebook.winfo_children()[tab_id]
            if hasattr(tab, 'file_tree') and hasattr(tab, 'category'):
                self.refresh_file_list(tab, tab.category, tab.search_var.get())
    
    def get_selected_file_path(self, tab):
        """Get the file path of the selected item in the tree"""
        file_tree = tab.file_tree
        selection = file_tree.selection()
        
        if not selection:
            messagebox.showinfo("No Selection", "Please select a file first")
            return None
        
        item = selection[0]
        file_path = file_tree.item(item, "values")[4]  # Path is the 5th column
        
        if not os.path.exists(file_path):
            messagebox.showerror("File Not Found", f"The file {file_path} no longer exists")
            return None
        
        return file_path
    
    def import_file(self, category):
        """Import a file into the managed directory structure"""
        try:
            # Ask for file to import
            file_types = []
            if category == "encrypted":
                file_types = [("Encrypted files", "*.enc"), ("All files", "*.*")]
            elif category == "decrypted":
                file_types = [("All files", "*.*")]
            elif category in ("private_key", "public_key"):
                file_types = [("PEM files", "*.pem"), ("All files", "*.*")]
            elif category == "signature":
                file_types = [("Signature files", "*.sig"), ("All files", "*.*")]
            else:
                file_types = [("All files", "*.*")]
            
            file_path = filedialog.askopenfilename(
                title="Select file to import",
                filetypes=file_types
            )
            
            if not file_path:
                return
            
            # Read the file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Save to managed location
            if category is None:
                # Try to detect category
                ext = os.path.splitext(file_path)[1].lower()
                if ext == ".enc":
                    category = "encrypted"
                elif ext == ".pem":
                    category = "private_key"  # Will be refined during save
                elif ext == ".sig":
                    category = "signature"
                elif ext == ".log":
                    category = "log"
                else:
                    category = "unknown"
            
            # Use the original filename
            filename = os.path.basename(file_path)
            
            # Save the file
            new_path, _ = file_manager.save_file(data, filename=filename, category=category)
            
            # Refresh the file list
            self.refresh_all_tabs()
            
            messagebox.showinfo("Import Successful", f"File imported successfully to {new_path}")
            
        except Exception as e:
            messagebox.showerror("Import Error", f"Error importing file: {str(e)}")
    
    def view_file_details(self, tab):
        """View detailed information about the selected file"""
        file_path = self.get_selected_file_path(tab)
        if not file_path:
            return
        
        try:
            # Get file info
            file_info = file_manager.get_file_info(file_path)
            
            # Create a details window
            details_window = tk.Toplevel(self.root)
            details_window.title(f"File Details: {file_info['filename']}")
            details_window.geometry("500x400")
            
            # Create a frame with padding
            frame = ttk.Frame(details_window, padding=10)
            frame.pack(fill="both", expand=True)
            
            # Add fields
            row = 0
            for key, value in file_info.items():
                # Skip some technical fields
                if key in ["checksum"]:
                    continue
                
                # Format some values for better display
                if key == "size":
                    size_kb = value / 1024
                    if size_kb < 1024:
                        value = f"{size_kb:.1f} KB"
                    else:
                        value = f"{size_kb/1024:.1f} MB"
                
                # Display the field
                ttk.Label(frame, text=key.capitalize() + ":", font=("", 10, "bold"), anchor="e").grid(
                    row=row, column=0, sticky="e", padx=5, pady=3
                )
                
                # For paths, create a scrollable text widget
                if key in ["path", "checksum"]:
                    value_widget = tk.Text(frame, height=2, width=40, wrap="word")
                    value_widget.insert("1.0", str(value))
                    value_widget.config(state="disabled")
                    value_widget.grid(row=row, column=1, sticky="w", padx=5, pady=3)
                else:
                    ttk.Label(frame, text=str(value), wraplength=350, justify="left").grid(
                        row=row, column=1, sticky="w", padx=5, pady=3
                    )
                
                row += 1
            
            # Add checksum at the bottom with copy button
            if "checksum" in file_info:
                ttk.Label(frame, text="Checksum:", font=("", 10, "bold"), anchor="e").grid(
                    row=row, column=0, sticky="e", padx=5, pady=3
                )
                
                checksum_frame = ttk.Frame(frame)
                checksum_frame.grid(row=row, column=1, sticky="w", padx=5, pady=3)
                
                checksum_entry = ttk.Entry(checksum_frame, width=40)
                checksum_entry.insert(0, file_info["checksum"])
                checksum_entry.config(state="readonly")
                checksum_entry.pack(side="left", padx=2)
                
                def copy_checksum():
                    self.root.clipboard_clear()
                    self.root.clipboard_append(file_info["checksum"])
                    self.status_var.set("Checksum copied to clipboard")
                
                copy_button = ttk.Button(checksum_frame, text="Copy", command=copy_checksum, width=5)
                copy_button.pack(side="left", padx=2)
                
                row += 1
            
            # Add buttons at the bottom
            button_frame = ttk.Frame(frame)
            button_frame.grid(row=row, column=0, columnspan=2, pady=10)
            
            ttk.Button(button_frame, text="Open File", command=lambda: self.open_file(tab)).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Export File", command=lambda: self.export_file(tab)).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Close", command=details_window.destroy).pack(side="left", padx=5)
            
            # Make the window modal
            details_window.transient(self.root)
            details_window.grab_set()
            details_window.wait_window()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error viewing file details: {str(e)}")
    
    def open_file(self, tab):
        """Open the selected file with the default application"""
        file_path = self.get_selected_file_path(tab)
        if not file_path:
            return
        
        try:
            # Use the appropriate method based on platform
            import platform
            import subprocess
            
            system = platform.system()
            
            if system == "Windows":
                os.startfile(file_path)
            elif system == "Darwin":  # macOS
                subprocess.call(["open", file_path])
            else:  # Linux and other Unix-like systems
                subprocess.call(["xdg-open", file_path])
            
            self.status_var.set(f"Opened {os.path.basename(file_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error opening file: {str(e)}")
    
    def export_file(self, tab):
        """Export the selected file to another location"""
        file_path = self.get_selected_file_path(tab)
        if not file_path:
            return
        
        try:
            # Ask for the destination
            filename = os.path.basename(file_path)
            destination = filedialog.asksaveasfilename(
                title="Export file to...",
                initialfile=filename
            )
            
            if not destination:
                return
            
            # Copy the file
            shutil.copy2(file_path, destination)
            
            # Copy metadata if available
            meta_path = f"{file_path}.meta"
            if os.path.exists(meta_path):
                shutil.copy2(meta_path, f"{destination}.meta")
            
            self.status_var.set(f"Exported {filename} to {destination}")
            messagebox.showinfo("Export Successful", f"File exported successfully to {destination}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting file: {str(e)}")
    
    def move_file(self, tab):
        """Move the selected file to another managed directory"""
        file_path = self.get_selected_file_path(tab)
        if not file_path:
            return
        
        try:
            # Create a dialog to select destination
            dialog = tk.Toplevel(self.root)
            dialog.title("Move File")
            dialog.geometry("400x200")
            dialog.transient(self.root)
            dialog.grab_set()
            
            ttk.Label(dialog, text="Select destination directory:").pack(pady=10)
            
            # Create radio buttons for destinations
            destination_var = tk.StringVar(value="data")
            destinations = [
                ("Data directory", "data"),
                ("Encrypted files", "encrypted"),
                ("Decrypted files", "decrypted"),
                ("Keys", "keys"),
                ("Signatures", "signatures"),
                ("Logs", "logs")
            ]
            
            for text, value in destinations:
                ttk.Radiobutton(dialog, text=text, value=value, variable=destination_var).pack(anchor="w", padx=20)
            
            def do_move():
                dest = destination_var.get()
                
                # Convert to full path
                if dest == "data":
                    dest_dir = file_manager.DATA_DIR
                elif dest == "encrypted":
                    dest_dir = file_manager.ENCRYPTED_DIR
                elif dest == "decrypted":
                    dest_dir = file_manager.DECRYPTED_DIR
                elif dest == "keys":
                    dest_dir = file_manager.KEYS_DIR
                elif dest == "signatures":
                    dest_dir = file_manager.SIGNATURES_DIR
                elif dest == "logs":
                    dest_dir = file_manager.LOGS_DIR
                else:
                    dest_dir = file_manager.DATA_DIR
                
                # Move the file
                new_path = file_manager.move_file(file_path, dest_dir)
                
                # Refresh the file lists
                self.refresh_all_tabs()
                
                dialog.destroy()
                self.status_var.set(f"Moved {os.path.basename(file_path)} to {dest_dir}")
                messagebox.showinfo("Move Successful", f"File moved successfully to {new_path}")
            
            # Buttons
            button_frame = ttk.Frame(dialog)
            button_frame.pack(pady=10)
            
            ttk.Button(button_frame, text="Move", command=do_move).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side="left", padx=5)
            
            dialog.wait_window()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error moving file: {str(e)}")
    
    def delete_file(self, tab):
        """Delete the selected file"""
        file_path = self.get_selected_file_path(tab)
        if not file_path:
            return
        
        try:
            # Ask for confirmation
            filename = os.path.basename(file_path)
            if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {filename}?"):
                return
            
            # Delete the file
            file_manager.delete_file(file_path)
            
            # Refresh the file lists
            self.refresh_all_tabs()
            
            self.status_var.set(f"Deleted {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error deleting file: {str(e)}")


def main():
    root = tk.Tk()
    style = Style(theme='superhero')
    app = FileBrowserApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
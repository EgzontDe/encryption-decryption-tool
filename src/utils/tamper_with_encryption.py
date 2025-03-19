import sys
import os
import argparse
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from ttkbootstrap import Style
import hashlib

def calculate_checksum(file_path):
    """Calculate SHA-256 checksum of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.digest()

def tamper_file(file_path, position=None, method="flip", offset=None, backup=True):
    """
    Tamper with an encrypted file by modifying specific bytes
    
    Parameters:
    - file_path: Path to the encrypted file
    - position: Position to tamper with relative to the offset (default: random)
    - method: Tampering method: "flip", "zero", "increment", "random"
    - offset: Byte offset where the data part begins (default: auto-detect)
    - backup: Whether to create a backup of the original file
    """
    import random
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Create backup if requested
    if backup:
        backup_path = f"{file_path}.backup"
        with open(file_path, 'rb') as src:
            with open(backup_path, 'wb') as dst:
                dst.write(src.read())
    
    # Read file
    with open(file_path, 'rb') as file:
        data = bytearray(file.read())
    
    # Calculate original checksum
    original_checksum = calculate_checksum(file_path)
    
    # Get file size
    file_size = len(data)
    
    # Auto-detect offset based on file type
    if offset is None:
        # Check if it's a BMP file
        if len(data) > 2 and data[:2] == b'BM':
            # BMP file with 54-byte header + 8-byte metadata
            offset = 62
        else:
            # For other files, assume 8-byte metadata block only
            offset = 8
            
            # Additional detection: look for 'ENCV2' marker for asymmetric encryption
            if len(data) > 5 and data[:5] == b'ENCV2':
                # Skip the marker, metadata length (4 bytes), and metadata
                offset = 5
                if len(data) > 9:
                    metadata_len = int.from_bytes(data[5:9], byteorder='big')
                    offset = 9 + metadata_len
    
    # Check if the file is large enough to tamper with
    if file_size <= offset:
        raise ValueError(f"File is too small ({file_size} bytes) for tampering with offset {offset}")
    
    # Determine tampering position
    if position is None:
        # Try to target the encrypted data, not headers or metadata
        # For symmetric encryption: target after offset
        # For asymmetric encryption with GCM: try to target after the tag
        
        # Look for likely positions of actual encrypted data
        if offset + 32 < file_size:  # If we have space for nonce + tag
            # Target data section, assuming metadata, nonce, and possibly tag
            safe_offset = offset + 32
        else:
            safe_offset = offset
            
        # Random position within the data section
        position = random.randint(safe_offset, file_size - 1)
    else:
        position = offset + position
        
    # Ensure position is within file bounds
    if position >= file_size:
        position = file_size - 1
    
    # Store original byte value
    original_value = data[position]
    
    # Perform tampering based on selected method
    if method == "flip":
        # Flip a random bit in the byte
        bit_position = random.randint(0, 7)
        data[position] = data[position] ^ (1 << bit_position)
    elif method == "zero":
        # Set byte to zero
        data[position] = 0
    elif method == "increment":
        # Increment byte value
        data[position] = (data[position] + 1) % 256
    elif method == "random":
        # Replace with random byte
        new_byte = random.randint(0, 255)
        while new_byte == original_value:  # Ensure it's different
            new_byte = random.randint(0, 255)
        data[position] = new_byte
    else:
        raise ValueError(f"Unknown tampering method: {method}")
    
    # Write tampered data
    with open(file_path, 'wb') as file:
        file.write(data)
    
    # Calculate new checksum
    new_checksum = calculate_checksum(file_path)
    
    return {
        "position": position,
        "offset": offset,
        "original_value": original_value,
        "new_value": data[position],
        "method": method,
        "file_size": file_size,
        "original_checksum": original_checksum.hex(),
        "new_checksum": new_checksum.hex(),
        "backup_path": backup_path if backup else None
    }

def restore_backup(file_path):
    """Restore file from backup"""
    backup_path = f"{file_path}.backup"
    if not os.path.exists(backup_path):
        raise FileNotFoundError(f"Backup file not found: {backup_path}")
    
    with open(backup_path, 'rb') as src:
        with open(file_path, 'wb') as dst:
            dst.write(src.read())
    
    return True

def tamper_gui():
    def on_select_file():
        file_path = filedialog.askopenfilename(
            title="Select encrypted file to tamper with",
            filetypes=[("All Files", "*.*"), ("Encrypted Files", "*.enc")]
        )
        if file_path:
            file_entry.delete(0, tk.END)
            file_entry.insert(0, file_path)
    
    def on_tamper():
        file_path = file_entry.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a file first")
            return
        
        try:
            # Get parameters from GUI
            method = method_var.get()
            
            # Get offset if specified
            offset_str = offset_entry.get()
            offset = int(offset_str) if offset_str else None
            
            # Get position if specified
            position_str = position_entry.get()
            position = int(position_str) if position_str else None
            
            # Create backup
            backup = backup_var.get()
            
            # Perform tampering
            result = tamper_file(file_path, position, method, offset, backup)
            
            # Show detailed result
            result_text = (
                f"File tampered successfully: {os.path.basename(file_path)}\n\n"
                f"Tampering Details:\n"
                f"- Method: {result['method']}\n"
                f"- Position: {result['position']} (offset + {result['position'] - result['offset']})\n"
                f"- Original value: 0x{result['original_value']:02X}\n"
                f"- New value: 0x{result['new_value']:02X}\n"
                f"- File size: {result['file_size']} bytes\n\n"
                f"Checksum Information:\n"
                f"- Original: {result['original_checksum'][:16]}...\n"
                f"- Modified: {result['new_checksum'][:16]}...\n"
            )
            
            if backup:
                result_text += f"\nBackup created at: {result['backup_path']}"
            
            messagebox.showinfo("Tampering Successful", result_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def on_restore():
        file_path = file_entry.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a file first")
            return
        
        try:
            if restore_backup(file_path):
                messagebox.showinfo("Success", f"File restored from backup successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during restoration: {str(e)}")
    
    # Create GUI window
    root = tk.Tk()
    root.title("Advanced File Tampering Tool")
    root.geometry("500x400")
    style = Style(theme='superhero')
    
    main_frame = ttk.Frame(root, padding=20)
    main_frame.pack(fill="both", expand=True)
    
    # File selection
    file_frame = ttk.LabelFrame(main_frame, text="File Selection")
    file_frame.pack(fill="x", padx=5, pady=5)
    
    file_entry = ttk.Entry(file_frame, width=50)
    file_entry.pack(side="left", padx=5, pady=10, fill="x", expand=True)
    
    file_button = ttk.Button(file_frame, text="Browse", command=on_select_file)
    file_button.pack(side="right", padx=5, pady=10)
    
    # Tampering options
    options_frame = ttk.LabelFrame(main_frame, text="Tampering Options")
    options_frame.pack(fill="x", padx=5, pady=5)
    
    # Method selection
    ttk.Label(options_frame, text="Tampering Method:").grid(column=0, row=0, sticky="w", padx=5, pady=5)
    method_var = tk.StringVar(value="flip")
    method_combobox = ttk.Combobox(options_frame, textvariable=method_var, 
                                 values=["flip", "zero", "increment", "random"],
                                 state="readonly")
    method_combobox.grid(column=1, row=0, padx=5, pady=5, sticky="ew")
    
    # Offset
    ttk.Label(options_frame, text="Header Offset (blank for auto-detect):").grid(column=0, row=1, sticky="w", padx=5, pady=5)
    offset_entry = ttk.Entry(options_frame)
    offset_entry.grid(column=1, row=1, padx=5, pady=5, sticky="ew")
    
    # Position
    ttk.Label(options_frame, text="Position (relative to offset, blank for random):").grid(column=0, row=2, sticky="w", padx=5, pady=5)
    position_entry = ttk.Entry(options_frame)
    position_entry.grid(column=1, row=2, padx=5, pady=5, sticky="ew")
    
    # Backup option
    backup_var = tk.BooleanVar(value=True)
    backup_check = ttk.Checkbutton(options_frame, text="Create backup file", variable=backup_var)
    backup_check.grid(column=0, row=3, columnspan=2, sticky="w", padx=5, pady=5)
    
    # Make sure the grid expands properly
    options_frame.columnconfigure(1, weight=1)
    
    # Action buttons
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(fill="x", padx=5, pady=15)
    
    tamper_button = ttk.Button(button_frame, text="Tamper File", command=on_tamper, style="danger.TButton")
    tamper_button.pack(side="left", padx=5, fill="x", expand=True)
    
    restore_button = ttk.Button(button_frame, text="Restore from Backup", command=on_restore)
    restore_button.pack(side="right", padx=5, fill="x", expand=True)
    
    # Security warning
    warning_text = (
        "⚠️ WARNING: This tool is for educational purposes only. Tampering with files\n"
        "can lead to permanent data loss or security vulnerabilities. Always use responsibly."
    )
    warning_label = ttk.Label(main_frame, text=warning_text, foreground="red", justify="center")
    warning_label.pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced tool for tampering with encrypted files")
    parser.add_argument("--gui", action="store_true", help="Launch the graphical user interface")
    parser.add_argument("--file", help="Path to the encrypted file to tamper with")
    parser.add_argument("--method", choices=["flip", "zero", "increment", "random"], default="flip",
                      help="Tampering method to use")
    parser.add_argument("--position", type=int, help="Position to tamper with (relative to offset)")
    parser.add_argument("--offset", type=int, help="Byte offset where the data part begins (auto-detect if not specified)")
    parser.add_argument("--no-backup", action="store_true", help="Disable backup creation")
    parser.add_argument("--restore", action="store_true", help="Restore file from backup")
    
    args = parser.parse_args()
    
    if args.gui:
        tamper_gui()
    elif args.restore and args.file:
        try:
            if restore_backup(args.file):
                print(f"File restored successfully: {args.file}")
        except Exception as e:
            print(f"Error restoring file: {str(e)}")
    elif args.file:
        try:
            result = tamper_file(
                args.file,
                position=args.position,
                method=args.method,
                offset=args.offset,
                backup=not args.no_backup
            )
            print(f"File tampered successfully: {args.file}")
            print(f"- Method: {result['method']}")
            print(f"- Position: {result['position']} (offset + {result['position'] - result['offset']})")
            print(f"- Original value: 0x{result['original_value']:02X}")
            print(f"- New value: 0x{result['new_value']:02X}")
            print(f"- File size: {result['file_size']} bytes")
            
            if not args.no_backup:
                print(f"Backup created at: {result['backup_path']}")
                
        except Exception as e:
            print(f"An error occurred: {str(e)}")
    else:
        parser.print_help()

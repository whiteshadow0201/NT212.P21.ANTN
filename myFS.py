import os
import json
import hashlib
import platform
import subprocess
import re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys
import pyotp
import qrcode
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from PIL import Image, ImageTk
from io import BytesIO
from os import urandom
from argon2.low_level import hash_secret_raw, Type
# Constant for AES-GCM nonce size
NONCE_SIZE = 12  # Recommended nonce size for AES-GCM in bytes
SALT_LENGTH = 16


def aes_encrypt(data_bytes, key):
    """
    Encrypts data using AES-GCM with a given key.

    Args:
        data_bytes (bytes): Data to encrypt.
        key (bytes): 32-byte key for AES encryption.

    Returns:
        bytes: Concatenated nonce, ciphertext, and authentication tag.
    """
    nonce = get_random_bytes(NONCE_SIZE)  # Generate random nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # Initialize AES-GCM cipher
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)  # Encrypt and generate tag
    return nonce + ciphertext + tag  # Combine nonce, ciphertext, and tag


def aes_decrypt(enc_bytes, key):
    """
    Decrypts data encrypted with AES-GCM.

    Args:
        enc_bytes (bytes): Encrypted data (nonce + ciphertext + tag).
        key (bytes): 32-byte key for AES decryption.

    Returns:
        bytes: Decrypted data.

    Raises:
        Exception: If decryption or verification fails.
    """
    nonce = enc_bytes[:NONCE_SIZE]  # Extract nonce
    tag = enc_bytes[-16:]  # Extract authentication tag
    ciphertext = enc_bytes[NONCE_SIZE:-16]  # Extract ciphertext
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)  # Initialize AES-GCM cipher
    return cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify tag


def get_bios_uuid():
    """
    Retrieves the system's BIOS UUID for device-specific locking.

    Returns:
        str or None: The BIOS UUID if available, else None.
    """
    system = platform.system().lower()  # Get operating system type

    try:
        if system == "windows":
            # Query BIOS UUID using WMIC on Windows
            output = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID"],
                text=True
            )
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            if len(lines) >= 2:
                uuid = lines[1]
                # Check for valid UUID
                if uuid.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                    return uuid

        elif system == "linux":
            # Query system UUID using dmidecode on Linux
            output = subprocess.check_output(
                ["dmidecode", "-s", "system-uuid"],
                text=True,
                stderr=subprocess.DEVNULL
            ).strip()
            if output and output.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                return output

        elif system == "darwin":
            # Query hardware UUID on macOS
            output = subprocess.check_output(
                ["system_profiler", "SPHardwareDataType"],
                text=True
            )
            match = re.search(r"Hardware UUID:\s*([0-9A-Fa-f\-]+)", output)
            if match:
                uuid = match.group(1)
                if uuid.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                    return uuid

    except (subprocess.CalledProcessError, FileNotFoundError, Exception):
        # Return None if UUID retrieval fails
        return None

    return None


class MyFS:
    """
    A class for managing an encrypted file system volume with GUI interface.
    """

    def __init__(self, root, volume_path, mode='open'):
        """
        Initializes the MyFS instance.

        Args:
            root (tk.Tk): The Tkinter root window.
            volume_path (str): Path to the volume file.
            mode (str): 'open' for existing volume, 'create' for new volume.
        """
        self.root = root  # Tkinter root window
        self.volume_path = volume_path  # Path to volume file
        self.volume_password = None  # Volume password
        self.key = None  # Derived encryption key
        self.superblock_key = None  # Key for superblock encryption
        self.superblock = None  # Volume metadata (file list)
        self.metadata = None  # Key file
        self.salt = None
        if mode == 'create' or not os.path.isfile(self.volume_path):
            self.format_volume()  # Create new volume
        else:
            self.load_volume()  # Load existing volume

    def create_key(self, password):
        """
        Create a 32-byte encryption key from a password using Argon2id.

        Args:
            password (str): The input password to derive the key from.

        Returns:
            bytes: The derived 32-byte key.

        Raises:
            ValueError: If key derivation fails due to Argon2 error.
        """
        salt = urandom(SALT_LENGTH)
        self.salt = salt

        try:
            key = hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=3,  # Iterations
                memory_cost=65536,  # 64 MiB
                parallelism=4,
                hash_len=32,  # Key length 32 bytes
                type=Type.ID  # Argon2id
            )
            return key
        except Exception as e:
            raise ValueError(f"Key derivation failed: {e}")


    def derive_key(self, password):
        """
        Derives a 32-byte encryption key from a password using Argon2id.

        Args:
            password (str): The input password to derive the key from.

        Returns:
            bytes: The derived 32-byte key.

        Raises:
            ValueError: If key derivation fails due to Argon2 error.
        """
        try:
            key = hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=self.salt,
                time_cost=3,  # Iterations
                memory_cost=65536,  # 64 MiB
                parallelism=4,
                hash_len=32,  # Key length 32 bytes
                type=Type.ID  # Argon2id
            )
            return key
        except Exception as e:
            raise ValueError(f"Key derivation failed: {e}")

    def format_volume(self):
        """
        Formats a new volume, setting up encryption and TOTP authentication.
        """
        # Create dialog for volume creation
        dialog = tk.Toplevel(self.root)
        dialog.title("Format Volume")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()

        # GUI elements for password and key file input
        tk.Label(dialog, text="Set volume password:", font=("Arial", 12)).pack(pady=10)
        pwd1_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd1_entry.pack(pady=5)
        tk.Label(dialog, text="Confirm volume password:", font=("Arial", 12)).pack(pady=10)
        pwd2_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd2_entry.pack(pady=5)
        tk.Label(dialog, text="Key file name (without extension):", font=("Arial", 12)).pack(pady=10)
        key_name_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        key_name_entry.pack(pady=5)

        def submit():
            """Handles submission of volume creation form."""
            pwd1 = pwd1_entry.get()
            pwd2 = pwd2_entry.get()
            key_name = key_name_entry.get().strip()
            # Validate passwords and key name
            if pwd1 != pwd2 or pwd1 == '':
                messagebox.showerror("Error", "Passwords do not match or are empty.")
                return
            if not key_name:
                messagebox.showerror("Error", "Key file name cannot be empty.")
                return

            self.volume_password = pwd1
            password_key = self.create_key(self.volume_password)  # Derive key from password
            self.superblock_key = get_random_bytes(32)  # Generate superblock key

            # Store metadata and superblock_key in key file
            totp_secret = pyotp.random_base32()  # Generate TOTP secret
            metadata_dict = {
                'bios_uuid': get_bios_uuid(),  # Store device UUID
                'totp_secret': totp_secret,  # Store TOTP secret
                'superblock_key': self.superblock_key.hex(),  # Store superblock key
            }

            # Convert dictionary to JSON string, then to bytes
            metadata_json_bytes = json.dumps(metadata_dict).encode('utf-8')

            # Encrypt the JSON bytes
            encrypted_metadata = aes_encrypt(metadata_json_bytes, password_key)

            # Build the final metadata structure
            real_metadata = {
                'encrypted_metadata': encrypted_metadata.hex(),  # Convert to hex for JSON compatibility
                'salt': self.salt.hex()  # Optional: hex for consistency if self.salt is bytes
            }

            # Serialize the final structure to bytes for storage
            encrypted_metadata_bytes = json.dumps(real_metadata).encode('utf-8')

            key_path = f"{key_name}.key"
            try:
                # Save encrypted metadata to key file
                with open(key_path, 'wb') as f:
                    f.write(encrypted_metadata_bytes)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key file: {e}")
                return

            # Initialize superblock with empty file list
            self.superblock = {'files': []}
            volume_name = os.path.basename(self.volume_path)
            # Generate TOTP URI for QR code
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=volume_name,
                issuer_name=volume_name
            )
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")

            def on_qr_ok():
                """Handles QR code confirmation."""
                qr_window.destroy()
                self.write_superblock()  # Save superblock
                messagebox.showinfo("Success", "Volume formatted and encrypted.")
                dialog.destroy()
                self.root.geometry("800x600+100+100")
                self.root.deiconify()
                self.root.lift()
                self.root.focus_force()
                self.show_main_menu()  # Show main menu

            try:
                # Display QR code for TOTP setup
                qr_window = tk.Toplevel(dialog)
                qr_window.title("Scan QR Code for MyFS TOTP")
                qr_window.geometry("900x900")
                qr_window.transient(dialog)
                qr_window.grab_set()

                bio = BytesIO()
                qr_image.save(bio, format="PNG")
                photo = ImageTk.PhotoImage(Image.open(bio))
                tk.Label(
                    qr_window,
                    text="Scan this QR code with Microsoft Authenticator\nor manually enter the secret: " + totp_secret,
                    wraplength=350,
                    justify="center",
                    font=("Arial", 12)
                ).pack(pady=10)
                qr_label = tk.Label(qr_window, image=photo)
                qr_label.pack(pady=10)
                qr_label.image = photo
                tk.Button(qr_window, text="OK", command=on_qr_ok, font=("Arial", 12), width=10, height=1).pack(pady=10)

            except tk.TclError as e:
                # Fallback if GUI is unavailable
                qr_path = "totp_qr.png"
                qr_image.save(qr_path)
                messagebox.showinfo("Info",
                                    f"GUI not available. QR code saved to '{qr_path}'. Scan it with Microsoft Authenticator.\nOr manually enter this secret: {totp_secret}")
                input("Press Enter after scanning the QR code or entering the secret...")
                self.write_superblock()
                messagebox.showinfo("Success", "Volume formatted and encrypted.")
                dialog.destroy()
                self.root.geometry("800x600+100+100")
                self.root.deiconify()
                self.root.lift()
                self.root.focus_force()
                self.show_main_menu()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)
        dialog.protocol("WM_DELETE_WINDOW", lambda: dialog.destroy())

    def write_superblock(self):
        """
        Writes the encrypted superblock to the volume file with an integrity hash.
        """
        sb_bytes = json.dumps(self.superblock).encode('utf-8')
        encrypted = aes_encrypt(sb_bytes, self.superblock_key)  # Encrypt superblock
        sb_hash = hashlib.sha256(encrypted).hexdigest()  # Compute hash for integrity
        with open(self.volume_path, 'wb') as f:
            f.write(sb_hash.encode('utf-8'))  # Write hash
            f.write(encrypted)  # Write encrypted superblock

    def load_volume(self):
        """
        Loads and decrypts an existing volume, verifying integrity and TOTP.
        """
        dialog = tk.Toplevel(self.root)
        dialog.title("Unlock Volume")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()
        attempts = [0]  # Track password attempts

        # GUI elements for password, key file, and TOTP input
        tk.Label(dialog, text="Enter volume password:", font=("Arial", 12)).pack(pady=10)
        pwd_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd_entry.pack(pady=5)
        tk.Label(dialog, text="Select MyFS.key file:", font=("Arial", 12)).pack(pady=10)
        key_path_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        key_path_entry.pack(pady=5)
        tk.Button(
            dialog,
            text="Browse",
            width=10,
            height=1,
            font=("Arial", 12),
            command=lambda: (
                key_path_entry.delete(0, tk.END),
                key_path_entry.insert(0, filedialog.askopenfilename(filetypes=[("Key files", "*.key")]))
            )
        ).pack(pady=5)
        tk.Label(dialog, text="Enter TOTP code:", font=("Arial", 12)).pack(pady=10)
        totp_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        totp_entry.pack(pady=5)

        def submit():
            """Handles volume unlock submission."""
            pwd = pwd_entry.get()
            key_path = key_path_entry.get()
            totp_code = totp_entry.get()
            attempts[0] += 1

            # Validate key file existence
            if not os.path.isfile(key_path):
                messagebox.showerror("Error", "MyFS.key not found.")
                return
            try:
                # Read and decrypt metadata from key file
                with open(key_path, 'rb') as f:
                    file_content = f.read()

                # Decode JSON từ bytes -> dict
                real_metadata = json.loads(file_content.decode('utf-8'))

                # Tách salt và encrypted metadata
                self.salt = bytes.fromhex(real_metadata['salt'])
                encrypted_metadata = bytes.fromhex(real_metadata['encrypted_metadata'])
                metadata_bytes = aes_decrypt(encrypted_metadata, self.derive_key(pwd))
                self.metadata = json.loads(metadata_bytes.decode('utf-8'))
                if 'superblock_key' not in self.metadata:
                    messagebox.showerror("Error", "Superblock key not found in key file.")
                    return
                self.superblock_key = bytes.fromhex(self.metadata['superblock_key'])
            except Exception:
                messagebox.showerror("Error", "Wrong password or corrupted key file.")
                return

            try:
                # Read and verify volume integrity
                with open(self.volume_path, 'rb') as f:
                    sb_hash = f.read(64).decode('utf-8')
                    encrypted = f.read()
                check_hash = hashlib.sha256(encrypted).hexdigest()
                if check_hash != sb_hash:
                    messagebox.showerror("Error", "Volume corrupted or integrity check failed.")
                    dialog.destroy()
                    self.root.quit()
                    return
                # Decrypt superblock
                decrypted = aes_decrypt(encrypted, self.superblock_key)
                self.superblock = json.loads(decrypted.decode('utf-8'))
                current_bios_uuid = get_bios_uuid()

                # Verify BIOS UUID for device locking
                if 'bios_uuid' not in self.metadata or self.metadata['bios_uuid'] != current_bios_uuid:
                    messagebox.showerror("Error",
                                         "This volume can only be accessed on the machine where it was created.")
                    dialog.destroy()
                    self.root.quit()
                    return
                # Verify TOTP code
                if 'totp_secret' in self.metadata:
                    totp = pyotp.TOTP(self.metadata['totp_secret'])
                    if not totp.verify(totp_code):
                        messagebox.showerror("Error", "Invalid TOTP code.")
                        return
                else:
                    messagebox.showerror("Error", "TOTP secret not found in metadata. Key file may be corrupted.")
                    dialog.destroy()
                    self.root.quit()
                    return
                self.volume_password = pwd
                self.key = self.derive_key(pwd)  # Derive volume key
                messagebox.showinfo("Success", "Welcome to MyFS.")
                dialog.destroy()
                self.root.geometry("800x600+100+100")
                self.root.deiconify()
                self.root.lift()
                self.root.focus_force()
                self.show_main_menu()  # Show main menu
            except Exception:
                messagebox.showerror("Error", "Decryption failed or invalid TOTP code.")
                # Enforce maximum password attempts
                if attempts[0] >= 3:
                    messagebox.showerror("Error", "Too many wrong password attempts.")
                    dialog.destroy()
                    self.root.quit()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)
        dialog.protocol("WM_DELETE_WINDOW", lambda: sys.exit())

    def encrypt_file_content(self, data_bytes, file_password):
        """
        Encrypts file content using AES-GCM with a derived key.

        Args:
            data_bytes (bytes): File content to encrypt.
            file_password (str): Password for file encryption.

        Returns:
            str: Hex-encoded encrypted data (nonce + ciphertext + tag).
        """
        key = self.derive_key(file_password)
        encrypted = aes_encrypt(data_bytes, key)
        return encrypted.hex()  # Store as hex string

    def decrypt_file_content(self, encrypted_hex, file_password):
        """
        Decrypts file content encrypted with AES-GCM.

        Args:
            encrypted_hex (str): Hex-encoded encrypted data.
            file_password (str): Password for decryption.

        Returns:
            bytes or None: Decrypted data, or None if decryption fails.
        """
        key = self.derive_key(file_password)
        try:
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            return aes_decrypt(encrypted_bytes, key)
        except Exception:
            return None

    def show_main_menu(self):
        """
        Displays the main menu with file management options.
        """
        for widget in self.root.winfo_children():
            widget.destroy()  # Clear existing widgets
        self.root.title("Encrypted Volume Manager")
        self.root.geometry("600x500")
        tk.Label(self.root, text="Encrypted Volume Manager", font=("Arial", 14, "bold")).pack(pady=20)
        # Define menu buttons
        buttons = [
            ("List Files", self.list_files),
            ("Import File", self.import_file),
            ("Export File", self.export_file),
            ("Delete File", self.delete_file),
            ("Permanently Delete File", self.permanently_delete_file),
            ("Restore File", self.restore_file),
            ("Change Volume Password", self.set_volume_password),
            ("Change File Password", self.change_file_password),
            ("Exit", self.root.quit)
        ]
        for text, command in buttons:
            tk.Button(self.root, text=text, command=command, font=("Arial", 12), width=20, height=1).pack(pady=5)

    def list_files(self):
        """
        Displays a list of non-deleted files in the volume.
        """
        files = [f for f in self.superblock['files'] if not f['deleted']]
        dialog = tk.Toplevel(self.root)
        dialog.title("List Files")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()
        if not files:
            tk.Label(dialog, text="No files in volume.", font=("Arial", 12)).pack(pady=20)
        else:
            # Display file list in a text widget
            text = tk.Text(dialog, height=10, width=70, font=("Arial", 12))
            text.pack(pady=10)
            for f in files:
                text.insert(tk.END, f"ID:{f['id']} Name:{f['name']} Deleted:{f['deleted']}\n")
            text.config(state='disabled')
        tk.Button(dialog, text="Close", command=dialog.destroy, font=("Arial", 12), width=10, height=1).pack(pady=10)

    def import_file(self):
        """
        Imports a file into the volume with encryption.
        """
        dialog = tk.Toplevel(self.root)
        dialog.title("Import File")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()

        # GUI elements for file selection and password
        tk.Label(dialog, text="Select file to import:", font=("Arial", 12)).pack(pady=10)
        file_path_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        file_path_entry.pack(pady=5)
        tk.Button(
            dialog,
            text="Browse",
            width=10,
            height=1,
            font=("Arial", 12),
            command=lambda: (
                file_path_entry.delete(0, tk.END),
                file_path_entry.insert(0, filedialog.askopenfilename())
            )
        ).pack(pady=5)
        tk.Label(dialog, text="Set file password:", font=("Arial", 12)).pack(pady=10)
        pwd1_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd1_entry.pack(pady=5)
        tk.Label(dialog, text="Confirm file password:", font=("Arial", 12)).pack(pady=10)
        pwd2_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd2_entry.pack(pady=5)

        def submit():
            """Handles file import submission."""
            path = file_path_entry.get()
            file_pass = pwd1_entry.get()
            file_pass2 = pwd2_entry.get()
            # Validate inputs
            if not os.path.isfile(path):
                messagebox.showerror("Error", "File not found.")
                return
            if file_pass != file_pass2 or file_pass == '':
                messagebox.showerror("Error", "Passwords do not match or are empty.")
                return
            try:
                # Read file content
                with open(path, 'rb') as f:
                    data = f.read()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")
                return
            # Encrypt and store file metadata
            encrypted_content = self.encrypt_file_content(data, file_pass)
            file_id = 1 + max([f['id'] for f in self.superblock['files']] or [0])
            file_entry = {
                'id': file_id,
                'name': os.path.basename(path),
                'deleted': False,
                'file_pass_hash': hashlib.sha256(file_pass.encode()).hexdigest(),
                'content': encrypted_content
            }
            self.superblock['files'].append(file_entry)
            self.write_superblock()
            messagebox.showinfo("Success", "File imported.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def export_file(self):
        """
        Exports a file from the volume after decryption.
        """
        dialog = tk.Toplevel(self.root)
        dialog.title("Export File")
        dialog.geometry("700x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Display available files
        files = [f for f in self.superblock['files'] if not f['deleted']]
        tk.Label(dialog, text="Available Files:", font=("Arial", 12, "bold")).pack(pady=5)
        if not files:
            tk.Label(dialog, text="No files to export.", font=("Arial", 12)).pack(pady=5)
        else:
            text = tk.Text(dialog, height=10, width=70, font=("Arial", 11))
            text.pack(pady=5)
            for f in files:
                text.insert(tk.END, f"ID:{f['id']} Name:{f['name']} Deleted:{f['deleted']}\n")
            text.config(state='disabled')

        # GUI elements for file ID, password, and output path
        tk.Label(dialog, text="File ID to export:", font=("Arial", 12)).pack(pady=10)
        fid_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        fid_entry.pack(pady=5)
        tk.Label(dialog, text="Enter file password:", font=("Arial", 12)).pack(pady=10)
        pwd_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd_entry.pack(pady=5)
        tk.Label(dialog, text="Export file path:", font=("Arial", 12)).pack(pady=10)
        out_path_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        out_path_entry.pack(pady=5)
        tk.Button(
            dialog,
            text="Browse",
            width=10,
            height=1,
            font=("Arial", 12),
            command=lambda: (
                out_path_entry.delete(0, tk.END),
                out_path_entry.insert(0, filedialog.asksaveasfilename())
            )
        ).pack(pady=5)

        def submit():
            """Handles file export submission."""
            try:
                fid = int(fid_entry.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid ID")
                return
            f = next((f for f in self.superblock['files'] if f['id'] == fid and not f['deleted']), None)
            if not f:
                messagebox.showerror("Error", "File not found or deleted.")
                return
            file_pass = pwd_entry.get()
            if hashlib.sha256(file_pass.encode()).hexdigest() != f['file_pass_hash']:
                messagebox.showerror("Error", "Wrong file password.")
                return
            data = self.decrypt_file_content(f['content'], file_pass)
            if data is None:
                messagebox.showerror("Error", "Decryption failed, wrong password or corrupted file.")
                return
            out_path = out_path_entry.get()
            try:
                # Write decrypted file to output path
                with open(out_path, 'wb') as f:
                    f.write(data)
                messagebox.showinfo("Success", "File exported.")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to write exported file: {e}")

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def delete_file(self):
        """
        Marks a file as deleted in the volume (soft delete).
        """
        dialog = tk.Toplevel(self.root)
        dialog.title("Delete File")
        dialog.geometry("600x500")
        dialog.transient(self.root)
        dialog.grab_set()

        # Display available files
        files = [f for f in self.superblock['files'] if not f['deleted']]
        tk.Label(dialog, text="Available Files:", font=("Arial", 12, "bold")).pack(pady=5)
        if not files:
            tk.Label(dialog, text="No files to delete.", font=("Arial", 12)).pack(pady=5)
        else:
            text = tk.Text(dialog, height=10, width=70, font=("Arial", 11))
            text.pack(pady=5)
            for f in files:
                text.insert(tk.END, f"ID:{f['id']} Name:{f['name']} Deleted:{f['deleted']}\n")
            text.config(state='disabled')

        # GUI elements for file ID and password
        tk.Label(dialog, text="File ID to delete:", font=("Arial", 12)).pack(pady=10)
        fid_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        fid_entry.pack(pady=5)
        tk.Label(dialog, text="Enter file password:", font=("Arial", 12)).pack(pady=10)
        pwd_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd_entry.pack(pady=5)

        def submit():
            """Handles file deletion submission."""
            try:
                fid = int(fid_entry.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid ID")
                return
            f = next((f for f in self.superblock['files'] if f['id'] == fid and not f['deleted']), None)
            if not f:
                messagebox.showerror("Error", "File not found or already deleted.")
                return
            file_pass = pwd_entry.get()
            if hashlib.sha256(file_pass.encode()).hexdigest() != f['file_pass_hash']:
                messagebox.showerror("Error", "Wrong file password.")
                return
            f['deleted'] = True  # Mark file as deleted
            self.write_superblock()
            messagebox.showinfo("Success", "File deleted.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def permanently_delete_file(self):
        """
        Permanently deletes a file by overwriting its data and removing it.
        """
        dialog = tk.Toplevel(self.root)
        dialog.title("Permanently Delete File")
        dialog.geometry("600x500")
        dialog.transient(self.root)
        dialog.grab_set()

        # Display available files
        files = [f for f in self.superblock['files'] if not f['deleted']]
        tk.Label(dialog, text="Available Files:", font=("Arial", 12, "bold")).pack(pady=5)
        if not files:
            tk.Label(dialog, text="No files to delete permanently.", font=("Arial", 12)).pack(pady=5)
        else:
            text = tk.Text(dialog, height=10, width=70, font=("Arial", 11))
            text.pack(pady=5)
            for f in files:
                text.insert(tk.END, f"ID:{f['id']} Name:{f['name']} Deleted:{f['deleted']}\n")
            text.config(state='disabled')

        # GUI elements for file ID and password
        tk.Label(dialog, text="File ID to permanently delete:", font=("Arial", 12)).pack(pady=10)
        fid_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        fid_entry.pack(pady=5)
        tk.Label(dialog, text="Enter file password:", font=("Arial", 12)).pack(pady=10)
        pwd_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd_entry.pack(pady=5)

        def submit():
            """Handles permanent file deletion submission."""
            try:
                fid = int(fid_entry.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid ID")
                return
            f = next((f for f in self.superblock['files'] if f['id'] == fid), None)
            if not f:
                messagebox.showerror("Error", "File not found.")
                return
            file_pass = pwd_entry.get()
            if hashlib.sha256(file_pass.encode()).hexdigest() != f['file_pass_hash']:
                messagebox.showerror("Error", "Wrong file password.")
                return
            # Overwrite file content with zeros
            f['content'] = '00' * (len(f['content']) // 2)
            f['file_pass_hash'] = '0' * 64
            # Remove file from superblock
            self.superblock['files'] = [file for file in self.superblock['files'] if file['id'] != fid]
            self.write_superblock()
            messagebox.showinfo("Success", "File permanently deleted and data overwritten with null bytes.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def restore_file(self):
        """
        Restores a previously soft-deleted file.
        """
        deleted_files = [f for f in self.superblock['files'] if f['deleted']]
        if not deleted_files:
            messagebox.showinfo("Info", "No deleted files available to restore.")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Restore File")
        dialog.geometry("700x500")
        dialog.transient(self.root)
        dialog.grab_set()

        # Display deleted files
        tk.Label(dialog, text="Deleted files available for restoration:", font=("Arial", 12)).pack(pady=10)
        text = tk.Text(dialog, height=10, width=70, font=("Arial", 12))
        text.pack(pady=10)
        for f in deleted_files:
            text.insert(tk.END, f"ID:{f['id']} Name:{f['name']} Deleted:{f['deleted']}\n")
        text.config(state='disabled')
        tk.Label(dialog, text="File ID to restore:", font=("Arial", 12)).pack(pady=10)
        fid_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        fid_entry.pack(pady=5)
        tk.Label(dialog, text="Enter file password:", font=("Arial", 12)).pack(pady=10)
        pwd_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd_entry.pack(pady=5)

        def submit():
            """Handles file restoration submission."""
            try:
                fid = int(fid_entry.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid ID")
                return
            f = next((f for f in self.superblock['files'] if f['id'] == fid and f['deleted']), None)
            if not f:
                messagebox.showerror("Error", "File not found or not deleted.")
                return
            file_pass = pwd_entry.get()
            if hashlib.sha256(file_pass.encode()).hexdigest() != f['file_pass_hash']:
                messagebox.showerror("Error", "Wrong file password.")
                return
            # Verify file content integrity
            data = self.decrypt_file_content(f['content'], file_pass)
            if data is None:
                messagebox.showerror("Error", "Cannot decrypt file, content may be corrupted.")
                return
            f['deleted'] = False  # Restore file
            self.write_superblock()
            messagebox.showinfo("Success", "File restored.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def set_volume_password(self):
        """
        Changes the volume password and updates the key file.
        """
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Volume Password")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()

        # GUI elements for password change
        tk.Label(dialog, text="Enter current volume password:", font=("Arial", 12)).pack(pady=10)
        old_pass_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        old_pass_entry.pack(pady=5)
        tk.Label(dialog, text="Enter new volume password:", font=("Arial", 12)).pack(pady=10)
        new_pass1_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        new_pass1_entry.pack(pady=5)
        tk.Label(dialog, text="Confirm new volume password:", font=("Arial", 12)).pack(pady=10)
        new_pass2_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        new_pass2_entry.pack(pady=5)
        tk.Label(dialog, text="Select MyFS.key file:", font=("Arial", 12)).pack(pady=10)
        key_path_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        key_path_entry.pack(pady=5)
        tk.Button(
            dialog,
            text="Browse",
            width=10,
            height=1,
            font=("Arial", 12),
            command=lambda: (
                key_path_entry.delete(0, tk.END),
                key_path_entry.insert(0, filedialog.asksaveasfilename(filetypes=[("Key files", "*.key")]))
            )
        ).pack(pady=5)

        def submit():
            """Handles volume password change submission."""
            old_pass = old_pass_entry.get()
            if old_pass != self.volume_password:
                messagebox.showerror("Error", "Wrong password.")
                return
            new_pass1 = new_pass1_entry.get()
            new_pass2 = new_pass2_entry.get()
            key_path = key_path_entry.get()
            if new_pass1 != new_pass2 or new_pass1 == '':
                messagebox.showerror("Error", "Passwords do not match or are empty.")
                return
            # Encrypt metadata with new password
            new_password_key = self.derive_key(new_pass1)
            metadata_bytes = json.dumps(self.metadata).encode('utf-8')
            encrypted_metadata = aes_encrypt(metadata_bytes, new_password_key)
            try:
                # Save updated key file
                with open(key_path, 'wb') as f:
                    f.write(encrypted_metadata)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key file: {e}")
                return
            self.volume_password = new_pass1
            self.key = new_password_key
            messagebox.showinfo("Success", "Volume password changed.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def change_file_password(self):
        """
        Changes the password for a specific file in the volume.
        """
        dialog = tk.Toplevel(self.root)
        dialog.title("Change File Password")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()

        # GUI elements for file ID and password change
        tk.Label(dialog, text="File ID to change password:", font=("Arial", 12)).pack(pady=10)
        fid_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        fid_entry.pack(pady=5)
        tk.Label(dialog, text="Enter old file password:", font=("Arial", 12)).pack(pady=10)
        old_pass_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        old_pass_entry.pack(pady=5)
        tk.Label(dialog, text="Enter new file password:", font=("Arial", 12)).pack(pady=10)
        new_pass1_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        new_pass1_entry.pack(pady=5)
        tk.Label(dialog, text="Confirm new file password:", font=("Arial", 12)).pack(pady=10)
        new_pass2_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        new_pass2_entry.pack(pady=5)

        def submit():
            """Handles file password change submission."""
            try:
                fid = int(fid_entry.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid ID")
                return
            f = next((f for f in self.superblock['files'] if f['id'] == fid and not f['deleted']), None)
            if not f:
                messagebox.showerror("Error", "File not found or deleted.")
                return
            old_pass = old_pass_entry.get()
            if hashlib.sha256(old_pass.encode()).hexdigest() != f['file_pass_hash']:
                messagebox.showerror("Error", "Wrong file password.")
                return
            new_pass1 = new_pass1_entry.get()
            new_pass2 = new_pass2_entry.get()
            if new_pass1 != new_pass2 or new_pass1 == '':
                messagebox.showerror("Error", "Passwords do not match or are empty.")
                return
            # Decrypt and re-encrypt file with new password
            data = self.decrypt_file_content(f['content'], old_pass)
            if data is None:
                messagebox.showerror("Error", "Cannot decrypt file with old password.")
                return
            new_encrypted = self.encrypt_file_content(data, new_pass1)
            f['content'] = new_encrypted
            f['file_pass_hash'] = hashlib.sha256(new_pass1.encode()).hexdigest()
            self.write_superblock()
            messagebox.showinfo("Success", "File password changed.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)


def choose_or_create_volume():
    """
    Prompts user to choose between opening or creating a volume.

    Returns:
        tuple: (Tk root, volume path, mode).
    """
    root = tk.Tk()
    root.withdraw()  # Hide root window

    choice = show_choice_window(root)  # Show choice dialog

    if choice == 'open':
        # Prompt for existing volume file
        volume_path = filedialog.askopenfilename(
            title="Select existing DRI Volume",
            defaultextension=".DRI",
            filetypes=[("MyFS Volume", "*.DRI")]
        )
        if not volume_path:
            messagebox.showerror("Error", "No volume file selected for opening.")
            sys.exit()
        mode = 'open'

    elif choice == 'create':
        # Prompt for new volume file creation
        volume_path = filedialog.asksaveasfilename(
            title="Create new DRI Volume File",
            defaultextension=".DRI",
            filetypes=[("MyFS Volume", "*.DRI")],
            initialfile="MyVolume"
        )
        if not volume_path:
            messagebox.showerror("Error", "No volume file selected for creation.")
            sys.exit()
        mode = 'create'

    else:
        messagebox.showinfo("Exit", "Operation cancelled. Exiting.")
        sys.exit()

    return root, volume_path, mode


def show_choice_window(parent):
    """
    Displays a dialog for choosing to open or create a volume.

    Args:
        parent (tk.Tk): Parent Tkinter window.

    Returns:
        str: User's choice ('open', 'create', or 'cancel').
    """
    choice_window = tk.Toplevel(parent)
    choice_window.title("Choose Action")
    choice_window.geometry("300x130")
    choice_window.resizable(False, False)
    choice_window.grab_set()

    choice = {'value': None}

    def select_open():
        choice['value'] = 'open'
        choice_window.destroy()

    def select_create():
        choice['value'] = 'create'
        choice_window.destroy()

    def select_cancel():
        choice['value'] = 'cancel'
        choice_window.destroy()

    # GUI elements for choice selection
    label = tk.Label(choice_window, text="Do you want to open or create a volume?")
    label.pack(pady=10)
    btn_open = tk.Button(choice_window, text="Open existing volume", width=25, command=select_open)
    btn_open.pack(pady=2)
    btn_create = tk.Button(choice_window, text="Create new volume", width=25, command=select_create)
    btn_create.pack(pady=2)
    btn_cancel = tk.Button(choice_window, text="Cancel", width=25, command=select_cancel)
    btn_cancel.pack(pady=2)

    choice_window.wait_window()

    return choice['value']


def main():
    root, volume_path, mode = choose_or_create_volume()  # Get volume details
    root.geometry("1x1+3000+3000")  # Minimize window initially
    app = MyFS(root, volume_path, mode)  # Initialize MyFS
    root.deiconify()  # Show window
    root.mainloop()  # Start Tkinter event loop


if __name__ == "__main__":
    main()
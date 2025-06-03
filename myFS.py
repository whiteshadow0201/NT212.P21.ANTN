import os
import json
import hashlib
import platform
import subprocess
import re
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys
import pyotp
import qrcode
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from PIL import Image, ImageTk
from io import BytesIO

# MYFS_FILE = 'MyFS.DRI'
BLOCK_SIZE = 16  # AES block size

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def derive_key(password):
    return hashlib.sha256(password.encode('utf-8')).digest()

def aes_encrypt(data_bytes, key):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_bytes))
    return iv + ciphertext

def aes_decrypt(enc_bytes, key):
    iv = enc_bytes[:BLOCK_SIZE]
    ciphertext = enc_bytes[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded)

def get_bios_uuid():
    system = platform.system().lower()

    try:
        if system == "windows":
            output = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID"],
                text=True
            )
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            if len(lines) >= 2:
                uuid = lines[1]
                if uuid.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                    return uuid

        elif system == "linux":
            output = subprocess.check_output(
                ["dmidecode", "-s", "system-uuid"],
                text=True,
                stderr=subprocess.DEVNULL
            ).strip()
            if output and output.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                return output

        elif system == "darwin":
            output = subprocess.check_output(
                ["system_profiler", "SPHardwareDataType"],
                text=True
            )
            match = re.search(r"Hardware UUID:\s*([0-9A-Fa-f\-]+)", output)
            if match:
                uuid = match.group(1)
                if uuid.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                    return uuid

    except subprocess.CalledProcessError as e:
        pass
    except FileNotFoundError as e:
        pass
    except Exception as e:
        pass

    return None


class MyFS:
    def __init__(self, root, volume_path, mode='open'):
        self.root = root
        self.volume_path = volume_path
        self.volume_password = None
        self.key = None
        self.superblock_key = None
        self.superblock = None
        if mode == 'create' or not os.path.isfile(self.volume_path):
            self.format_volume()
        else:
            self.load_volume()

    def format_volume(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Format Volume")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Set volume password:", font=("Arial", 12)).pack(pady=10)
        pwd1_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        pwd1_entry.pack(pady=5)
        tk.Label(dialog, text="Confirm volume password:", font=("Arial", 12)).pack(pady=10)
        pwd2_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        pwd2_entry.pack(pady=5)
        tk.Label(dialog, text="Key file name (without extension):", font=("Arial", 12)).pack(pady=10)
        key_name_entry = tk.Entry(dialog,  width=30, font=("Arial", 14))
        key_name_entry.pack(pady=5)

        def submit():
            pwd1 = pwd1_entry.get()
            pwd2 = pwd2_entry.get()
            key_name = key_name_entry.get().strip()
            if pwd1 != pwd2 or pwd1 == '':
                messagebox.showerror("Error", "Passwords do not match or are empty.")
                return
            if not key_name:
                messagebox.showerror("Error", "Key file name cannot be empty.")
                return

            self.volume_password = pwd1
            password_key = derive_key(self.volume_password)
            self.superblock_key = get_random_bytes(32)
            encrypted_key = aes_encrypt(self.superblock_key, password_key)

            key_path = f"{key_name}.key"
            try:
                with open(key_path, 'wb') as f:
                    f.write(encrypted_key)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key file: {e}")
                return

            totp_secret = pyotp.random_base32()
            self.superblock = {
                'bios_uuid': get_bios_uuid(),
                'totp_secret': totp_secret,
                'files': []
            }
            volume_name = os.path.basename(self.volume_path)
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=volume_name,
                issuer_name=volume_name
            )
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")

            def on_qr_ok():
                qr_window.destroy()
                self.write_superblock()
                messagebox.showinfo("Success", "Volume formatted and encrypted.")
                dialog.destroy()
                self.root.geometry("800x600+100+100")
                self.root.deiconify()
                self.root.lift()
                self.root.focus_force()
                self.show_main_menu()

            try:
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
        sb_bytes = json.dumps(self.superblock).encode('utf-8')
        encrypted = aes_encrypt(sb_bytes, self.superblock_key)
        sb_hash = hashlib.sha256(encrypted).hexdigest()
        with open(self.volume_path, 'wb') as f:
            f.write(sb_hash.encode('utf-8'))
            f.write(encrypted)

    def load_volume(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Unlock Volume")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()
        attempts = [0]

        tk.Label(dialog, text="Enter volume password:", font=("Arial", 12)).pack(pady=10)
        pwd_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        pwd_entry.pack(pady=5)
        tk.Label(dialog, text="Select MyFS.key file:", font=("Arial", 12)).pack(pady=10)
        key_path_entry = tk.Entry(dialog,  width=30, font=("Arial", 14))
        key_path_entry.pack(pady=5)
        tk.Button(
            dialog,
            text="Browse",
            width=10,  # Chiều rộng (số ký tự)
            height=1,  # Chiều cao (số dòng)
            font=("Arial", 12),  # Kiểu chữ và cỡ chữ
            command=lambda: (
                key_path_entry.delete(0, tk.END),
                key_path_entry.insert(0, filedialog.askopenfilename(filetypes=[("Key files", "*.key")]))
            )
        ).pack(pady=5)
        tk.Label(dialog, text="Enter TOTP code:", font=("Arial", 12)).pack(pady=10)
        totp_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        totp_entry.pack(pady=5)

        def submit():
            pwd = pwd_entry.get()
            key_path = key_path_entry.get()
            totp_code = totp_entry.get()
            attempts[0] += 1

            if not os.path.isfile(key_path):
                messagebox.showerror("Error", "MyFS.key not found.")
                return
            try:
                with open(key_path, 'rb') as f:
                    encrypted_key = f.read()
                self.superblock_key = aes_decrypt(encrypted_key, derive_key(pwd))
            except Exception:
                messagebox.showerror("Error", "Wrong password or corrupted key file.")
                return

            try:
                with open(self.volume_path, 'rb') as f:
                    sb_hash = f.read(64).decode('utf-8')
                    encrypted = f.read()
                check_hash = hashlib.sha256(encrypted).hexdigest()
                if check_hash != sb_hash:
                    messagebox.showerror("Error", "Volume corrupted or integrity check failed.")
                    dialog.destroy()
                    self.root.quit()
                    return
                decrypted = aes_decrypt(encrypted, self.superblock_key)
                sb = json.loads(decrypted.decode('utf-8'))
                current_bios_uuid = get_bios_uuid()


                if 'bios_uuid' not in sb or sb['bios_uuid'] != current_bios_uuid:
                    messagebox.showerror("Error", "This volume can only be accessed on the machine where it was created.")
                    dialog.destroy()
                    self.root.quit()
                    return
                if 'totp_secret' in sb:
                    totp = pyotp.TOTP(sb['totp_secret'])
                    if not totp.verify(totp_code):
                        messagebox.showerror("Error", "Invalid TOTP code.")
                        return
                else:
                    messagebox.showerror("Error", "TOTP secret not found in superblock. Volume may be corrupted.")
                    dialog.destroy()
                    self.root.quit()
                    return
                self.volume_password = pwd
                self.key = derive_key(pwd)
                self.superblock = sb
                messagebox.showinfo("Success", "Welcome to MyFS.")
                dialog.destroy()
                self.root.geometry("800x600+100+100")
                self.root.deiconify()
                self.root.lift()
                self.root.focus_force()
                self.show_main_menu()
            except Exception:
                messagebox.showerror("Error", "Decryption failed or invalid TOTP code.")
                if attempts[0] >= 3:
                    messagebox.showerror("Error", "Too many wrong password attempts.")
                    dialog.destroy()
                    self.root.quit()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)
        dialog.protocol("WM_DELETE_WINDOW", lambda: sys.exit())

    def encrypt_file_content(self, data_bytes, file_password):
        key = derive_key(file_password)
        return aes_encrypt(data_bytes, key).hex()

    def decrypt_file_content(self, encrypted_hex, file_password):
        key = derive_key(file_password)
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        try:
            return aes_decrypt(encrypted_bytes, key)
        except Exception:
            return None

    def show_main_menu(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.root.title("Encrypted Volume Manager")
        self.root.geometry("600x500")
        tk.Label(self.root, text="Encrypted Volume Manager", font=("Arial", 14, "bold")).pack(pady=20)
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
        files = [f for f in self.superblock['files'] if not f['deleted']]
        dialog = tk.Toplevel(self.root)
        dialog.title("List Files")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()
        if not files:
            tk.Label(dialog, text="No files in volume.", font=("Arial", 12)).pack(pady=20)
        else:
            text = tk.Text(dialog, height=10, width=70, font=("Arial", 12))
            text.pack(pady=10)
            for f in files:
                text.insert(tk.END, f"ID:{f['id']} Name:{f['name']} Deleted:{f['deleted']}\n")
            text.config(state='disabled')
        tk.Button(dialog, text="Close", command=dialog.destroy, font=("Arial", 12), width=10, height=1).pack(pady=10)

    def import_file(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Import File")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Select file to import:", font=("Arial", 12)).pack(pady=10)
        file_path_entry = tk.Entry(dialog,  width=30, font=("Arial", 14))
        file_path_entry.pack(pady=5)
        tk.Button(
            dialog,
            text="Browse",
            width=10,  # Chiều rộng (số ký tự)
            height=1,  # Chiều cao (số dòng)
            font=("Arial", 12),  # Kiểu chữ và cỡ chữ
            command=lambda: (
                file_path_entry.delete(0, tk.END),
                file_path_entry.insert(0, filedialog.askopenfilename())
            )
        ).pack(pady=5)
        tk.Label(dialog, text="Set file password:", font=("Arial", 12)).pack(pady=10)
        pwd1_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        pwd1_entry.pack(pady=5)
        tk.Label(dialog, text="Confirm file password:", font=("Arial", 12)).pack(pady=10)
        pwd2_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        pwd2_entry.pack(pady=5)

        def submit():
            path = file_path_entry.get()
            file_pass = pwd1_entry.get()
            file_pass2 = pwd2_entry.get()
            if not os.path.isfile(path):
                messagebox.showerror("Error", "File not found.")
                return
            if file_pass != file_pass2 or file_pass == '':
                messagebox.showerror("Error", "Passwords do not match or are empty.")
                return
            try:
                with open(path, 'rb') as f:
                    data = f.read()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {e}")
                return
            encrypted_content = self.encrypt_file_content(data, file_pass)
            file_id = 1 + max([f['id'] for f in self.superblock['files']] or [0])
            file_entry = {
                'id': file_id,
                'name': os.path.basename(path),
                'deleted': False,
                'content': encrypted_content,
                'file_pass_hash': hashlib.sha256(file_pass.encode()).hexdigest()
            }
            self.superblock['files'].append(file_entry)
            self.write_superblock()
            messagebox.showinfo("Success", "File imported.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def export_file(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Export File")
        dialog.geometry("700x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Hiển thị danh sách file chưa bị xóa
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

        # Các trường nhập dữ liệu
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
            width=10,  # Chiều rộng (số ký tự)
            height=1,  # Chiều cao (số dòng)
            font=("Arial", 12),  # Kiểu chữ và cỡ chữ
            command=lambda: (
                out_path_entry.delete(0, tk.END),
                out_path_entry.insert(0, filedialog.asksaveasfilename())
            )
        ).pack(pady=5)

        def submit():
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
                with open(out_path, 'wb') as f:
                    f.write(data)
                messagebox.showinfo("Success", "File exported.")
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to write exported file: {e}")

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def delete_file(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Delete File")
        dialog.geometry("600x500")
        dialog.transient(self.root)
        dialog.grab_set()

        # Hiển thị danh sách file chưa bị xóa
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

        # Nhập ID và mật khẩu
        tk.Label(dialog, text="File ID to delete:", font=("Arial", 12)).pack(pady=10)
        fid_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        fid_entry.pack(pady=5)

        tk.Label(dialog, text="Enter file password:", font=("Arial", 12)).pack(pady=10)
        pwd_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd_entry.pack(pady=5)

        def submit():
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
            f['deleted'] = True
            self.write_superblock()
            messagebox.showinfo("Success", "File deleted.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def permanently_delete_file(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Permanently Delete File")
        dialog.geometry("600x500")
        dialog.transient(self.root)
        dialog.grab_set()

        # Hiển thị danh sách file chưa bị xóa
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

        # Nhập ID và mật khẩu
        tk.Label(dialog, text="File ID to permanently delete:", font=("Arial", 12)).pack(pady=10)
        fid_entry = tk.Entry(dialog, width=30, font=("Arial", 14))
        fid_entry.pack(pady=5)

        tk.Label(dialog, text="Enter file password:", font=("Arial", 12)).pack(pady=10)
        pwd_entry = tk.Entry(dialog, show="*", width=30, font=("Arial", 14))
        pwd_entry.pack(pady=5)

        def submit():
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
            f['content'] = '00' * (len(f['content']) // 2)
            f['file_pass_hash'] = '0' * 64
            self.superblock['files'] = [file for file in self.superblock['files'] if file['id'] != fid]
            self.write_superblock()
            messagebox.showinfo("Success", "File permanently deleted and data overwritten with null bytes.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def restore_file(self):
        deleted_files = [f for f in self.superblock['files'] if f['deleted']]
        if not deleted_files:
            messagebox.showinfo("Info", "No deleted files available to restore.")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Restore File")
        dialog.geometry("700x500")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Deleted files available for restoration:", font=("Arial", 12)).pack(pady=10)
        text = tk.Text(dialog, height=10, width=70, font=("Arial", 12))
        text.pack(pady=10)
        for f in deleted_files:
            text.insert(tk.END, f"ID:{f['id']} Name:{f['name']} Deleted:{f['deleted']}\n")
        text.config(state='disabled')
        tk.Label(dialog, text="File ID to restore:", font=("Arial", 12)).pack(pady=10)
        fid_entry = tk.Entry(dialog,  width=30, font=("Arial", 14))
        fid_entry.pack(pady=5)
        tk.Label(dialog, text="Enter file password:", font=("Arial", 12)).pack(pady=10)
        pwd_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        pwd_entry.pack(pady=5)

        def submit():
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
            data = self.decrypt_file_content(f['content'], file_pass)
            if data is None:
                messagebox.showerror("Error", "Cannot decrypt file, content may be corrupted.")
                return
            f['deleted'] = False
            self.write_superblock()
            messagebox.showinfo("Success", "File restored.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def set_volume_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Volume Password")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Enter current volume password:", font=("Arial", 12)).pack(pady=10)
        old_pass_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        old_pass_entry.pack(pady=5)
        tk.Label(dialog, text="Enter new volume password:", font=("Arial", 12)).pack(pady=10)
        new_pass1_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        new_pass1_entry.pack(pady=5)
        tk.Label(dialog, text="Confirm new volume password:", font=("Arial", 12)).pack(pady=10)
        new_pass2_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        new_pass2_entry.pack(pady=5)
        tk.Label(dialog, text="Select MyFS.key file:", font=("Arial", 12)).pack(pady=10)
        key_path_entry = tk.Entry(dialog,  width=30, font=("Arial", 14))
        key_path_entry.pack(pady=5)
        tk.Button(
            dialog,
            text="Browse",
            width=10,  # Chiều rộng (số ký tự)
            height=1,  # Chiều cao (số dòng)
            font=("Arial", 12),  # Kiểu chữ và cỡ chữ
            command=lambda: (
                key_path_entry.delete(0, tk.END),
                key_path_entry.insert(0, filedialog.asksaveasfilename(filetypes=[("Key files", "*.key")]))
            )
        ).pack(pady=5)

        def submit():
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
            new_password_key = derive_key(new_pass1)
            encrypted_key = aes_encrypt(self.superblock_key, new_password_key)
            try:
                with open(key_path, 'wb') as f:
                    f.write(encrypted_key)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key file: {e}")
                return
            self.volume_password = new_pass1
            self.key = new_password_key
            messagebox.showinfo("Success", "Volume password changed.")
            dialog.destroy()

        tk.Button(dialog, text="Submit", command=submit, font=("Arial", 12), width=10, height=1).pack(pady=20)

    def change_file_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Change File Password")
        dialog.geometry("400x400")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="File ID to change password:", font=("Arial", 12)).pack(pady=10)
        fid_entry = tk.Entry(dialog,  width=30, font=("Arial", 14))
        fid_entry.pack(pady=5)
        tk.Label(dialog, text="Enter old file password:", font=("Arial", 12)).pack(pady=10)
        old_pass_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        old_pass_entry.pack(pady=5)
        tk.Label(dialog, text="Enter new file password:", font=("Arial", 12)).pack(pady=10)
        new_pass1_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        new_pass1_entry.pack(pady=5)
        tk.Label(dialog, text="Confirm new file password:", font=("Arial", 12)).pack(pady=10)
        new_pass2_entry = tk.Entry(dialog, show="*",  width=30, font=("Arial", 14))
        new_pass2_entry.pack(pady=5)

        def submit():
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
    root = tk.Tk()
    root.withdraw()

    choice = show_choice_window(root)

    if choice == 'open':
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
    choice_window = tk.Toplevel(parent)
    choice_window.title("Choose Action")
    choice_window.geometry("300x130")
    choice_window.resizable(False, False)
    choice_window.grab_set()  # khóa focus ở cửa sổ này

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

    label = tk.Label(choice_window, text="Do you want to open or create a volume?")
    label.pack(pady=10)

    btn_open = tk.Button(choice_window, text="Open existing volume", width=25, command=select_open)
    btn_open.pack(pady=2)

    btn_create = tk.Button(choice_window, text="Create new volume", width=25, command=select_create)
    btn_create.pack(pady=2)

    btn_cancel = tk.Button(choice_window, text="Cancel", width=25, command=select_cancel)
    btn_cancel.pack(pady=2)

    choice_window.wait_window()  # đợi cửa sổ đóng lại

    return choice['value']


def main():
    root, volume_path, mode = choose_or_create_volume()
    root.geometry("1x1+3000+3000")
    app = MyFS(root, volume_path, mode)
    root.deiconify()
    root.mainloop()

if __name__ == "__main__":
    main()
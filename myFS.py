import os
import json
import hashlib
import uuid
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
from PIL import Image, ImageTk
from io import BytesIO
import random

ascii_arts = [
    r"""$$\      $$\           $$$$$$$$\  $$$$$$\  
$$$\    $$$ |          $$  _____|$$  __$$\ 
$$$$\  $$$$ |$$\   $$\ $$ |      $$ /  \__|
$$\$$\$$ $$ |$$ |  $$ |$$$$$\    \$$$$$$\  
$$ \$$$  $$ |$$ |  $$ |$$  __|    \____$$\ 
$$ |\$  /$$ |$$ |  $$ |$$ |      $$\   $$ |
$$ | \_/ $$ |\$$$$$$$ |$$ |      \$$$$$$  |
\__|     \__| \____$$ |\__|       \______/ 
             $$\   $$ |                    
             \$$$$$$  |                    
              \______/                      """,

    r"""    __  __                ____     ___   
   F  \/  ]    _    _    F ___J   F __". 
  J |\__/| L  J |  | L  J |___:  J (___| 
  | |`--'| |  | |  | |  | _____| J\___ \ 
  F L    J J  F L__J J  F |____J.--___) \
 J__L    J__L )-____  LJ__F     J\______J
 |__L    J__|J\______/F|__|      J______F
              J______F                   """,
    """
                 ___   ___  
|\ /|  \ /  |     |     
| + |   +   |-+-   -+-  
|   |  /    |         | 
                   ---  
                        
    """,
    """
                                                   
    _/      _/            _/_/_/_/    _/_/_/   
   _/_/  _/_/  _/    _/  _/        _/          
  _/  _/  _/  _/    _/  _/_/_/      _/_/       
 _/      _/  _/    _/  _/              _/      
_/      _/    _/_/_/  _/        _/_/_/         
                 _/                            
            _/_/                               
    """
]

def print_random_ascii_art():
    art = random.choice(ascii_arts)
    print("\n" + art + "\n")


MYFS_FILE = 'MyFS.DRI'
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
    # Derive 32 bytes key from password with SHA256
    return hashlib.sha256(password.encode('utf-8')).digest()


def aes_encrypt(data_bytes, key):
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_bytes))
    return iv + ciphertext  # prepend IV


def aes_decrypt(enc_bytes, key):
    iv = enc_bytes[:BLOCK_SIZE]
    ciphertext = enc_bytes[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded)


def get_machine_uuid():
    """Retrieve a stable machine UUID without using MAC address."""
    system = platform.system().lower()
    print(f"[DEBUG] Detecting system: {system}")

    if system == "windows":
        try:
            import winreg
            reg_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography"
            )
            machine_guid = winreg.QueryValueEx(reg_key, "MachineGuid")[0]
            winreg.CloseKey(reg_key)
            print(f"[DEBUG] Using Windows MachineGuid: {machine_guid}")
            return machine_guid
        except Exception as e:
            print(f"[DEBUG] Failed to get Windows MachineGuid: {e}")

    elif system == "linux":
        try:
            for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        machine_id = f.read().strip()
                        if machine_id:
                            print(f"[DEBUG] Using Linux machine-id from {path}: {machine_id}")
                            return machine_id
        except Exception as e:
            print(f"[DEBUG] Failed to get Linux machine-id: {e}")

    elif system == "darwin":  # macOS
        try:
            output = subprocess.check_output(
                ["system_profiler", "SPHardwareDataType"],
                text=True
            )
            match = re.search(r"Hardware UUID:\s*([0-9a-fA-F-]+)", output)
            if match:
                machine_uuid = match.group(1)
                print(f"[DEBUG] Using macOS IOPlatformUUID: {machine_uuid}")
                return machine_uuid
        except Exception as e:
            print(f"[DEBUG] Failed to get macOS IOPlatformUUID: {e}")

    # Fallback: Hash system-specific info (hostname, platform, and disk info if available)
    try:
        system_info = f"{platform.node()}{platform.platform()}"
        # Add disk serial number if available
        if system == "windows":
            try:
                output = subprocess.check_output(
                    ["wmic", "diskdrive", "get", "serialnumber"],
                    text=True
                )
                serial = output.split('\n')[1].strip()
                system_info += serial
            except Exception:
                pass
        elif system == "linux":
            try:
                output = subprocess.check_output(
                    ["lsblk", "-d", "-o", "SERIAL"],
                    text=True
                )
                serial = output.split('\n')[1].strip()
                system_info += serial
            except Exception:
                pass
        elif system == "darwin":
            try:
                output = subprocess.check_output(
                    ["diskutil", "info", "/"],
                    text=True
                )
                match = re.search(r"Volume UUID:\s*([0-9a-fA-F-]+)", output)
                if match:
                    system_info += match.group(1)
            except Exception:
                pass
        machine_uuid = hashlib.sha256(system_info.encode('utf-8')).hexdigest()
        print(f"[DEBUG] Using fallback hashed system info: {machine_uuid}")
        return machine_uuid
    except Exception as e:
        print(f"[DEBUG] Fallback failed: {e}")
        # Raise an error instead of using a random UUID
        raise RuntimeError("Unable to generate a reliable machine UUID")

class MyFS:
    def __init__(self):
        self.volume_password = None
        self.key = None
        self.superblock_key = None
        self.superblock = None
        if not os.path.isfile(MYFS_FILE):
            print("[!] Volume not found. Creating new volume...")
            self.format_volume()
        else:
            self.load_volume()

    def format_volume(self):
        while True:
            pwd1 = getpass("Set volume password: ")
            pwd2 = getpass("Confirm volume password: ")
            if pwd1 == pwd2 and pwd1 != '':
                self.volume_password = pwd1
                break
            print("Passwords do not match or empty. Try again.")

        password_key = derive_key(self.volume_password)
        self.superblock_key = get_random_bytes(32)  # Khóa ngẫu nhiên để mã hóa siêu khối
        encrypted_key = aes_encrypt(self.superblock_key, password_key)

        key_path = input("Enter filename to store MyFS key on removable disk (without extension): ").strip()
        with open(key_path+ ".key", 'wb') as f:
            f.write(encrypted_key )

        # Tạo khóa bí mật TOTP
        totp_secret = pyotp.random_base32()
        self.superblock = {
            'files': [],
            'machine_uuid': get_machine_uuid(),
            'totp_secret': totp_secret  # Lưu khóa TOTP vào siêu khối
        }

        # Tạo URI cho TOTP
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name="MyFS Volume",
            issuer_name="MyFS"
        )

        # Tạo hình ảnh QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")

        try:
            # Khởi tạo cửa sổ tkinter trước
            window = tk.Tk()
            window.title("Scan QR Code for MyFS TOTP")
            window.geometry("500x600")  # Kích thước cửa sổ

            # Chuyển đổi hình ảnh QR thành định dạng hiển thị trong tkinter
            bio = BytesIO()
            qr_image.save(bio, format="PNG")
            photo = ImageTk.PhotoImage(Image.open(bio))

            # Hiển thị hướng dẫn
            label = tk.Label(
                window,
                text="Scan this QR code with Microsoft Authenticator\nor manually enter the secret: " + totp_secret,
                wraplength=350,
                justify="center",
                font=("Arial", 12)
            )
            label.pack(pady=10)

            # Hiển thị hình ảnh QR code
            qr_label = tk.Label(window, image=photo)
            qr_label.pack(pady=10)

            # Nút đóng cửa sổ
            button = tk.Button(window, text="OK", command=window.destroy, font=("Arial", 12))
            button.pack(pady=10)

            # Giữ tham chiếu đến ảnh để tránh bị garbage collected
            qr_label.image = photo

            # Chạy vòng lặp chính của tkinter để hiển thị cửa sổ
            window.mainloop()

        except tk.TclError as e:
            # Nếu GUI không khả dụng, lưu QR code thành file
            print(f"[!] GUI not available: {e}")
            qr_path = "totp_qr.png"
            qr_image.save(qr_path)
            print(f"[*] QR code saved to '{qr_path}'. Scan it with Microsoft Authenticator.")
            print(f"[*] Or manually enter this secret: {totp_secret}")
            input("Press Enter after scanning the QR code or entering the secret...")

        self.write_superblock()
        print("[+] Volume formatted and encrypted.")

    def write_superblock(self):
        sb_bytes = json.dumps(self.superblock).encode('utf-8')
        encrypted = aes_encrypt(sb_bytes, self.superblock_key)
        sb_hash = hashlib.sha256(encrypted).hexdigest()
        with open(MYFS_FILE, 'wb') as f:
            f.write(sb_hash.encode('utf-8'))
            f.write(encrypted)

    def load_volume(self):
        for attempt in range(3):
            pwd = getpass("Enter volume password: ")
            password_key = derive_key(pwd)
            key_path = input("Enter path to MyFS.key on removable disk: ").strip()
            if not os.path.isfile(key_path):
                print("[!] MyFS.key not found on removable disk.")
                continue
            with open(key_path, 'rb') as f:
                encrypted_key = f.read()
            try:
                self.superblock_key = aes_decrypt(encrypted_key, password_key)
            except Exception:
                print("[!] Wrong password or corrupted key file.")
                continue

            with open(MYFS_FILE, 'rb') as f:
                sb_hash = f.read(64).decode('utf-8')
                encrypted = f.read()
            check_hash = hashlib.sha256(encrypted).hexdigest()
            if check_hash != sb_hash:
                print("[!] Volume corrupted or integrity check failed.")
                sys.exit(1)
            try:
                decrypted = aes_decrypt(encrypted, self.superblock_key)
                sb = json.loads(decrypted.decode('utf-8'))
                current_machine_uuid = get_machine_uuid()
                if 'machine_uuid' not in sb or sb['machine_uuid'] != current_machine_uuid:
                    print("[!] This volume can only be accessed on the machine where it was created.")
                    sys.exit(1)

                # Kiểm tra mã TOTP
                if 'totp_secret' in sb:
                    totp = pyotp.TOTP(sb['totp_secret'])
                    totp_code = input("Enter TOTP code from Microsoft Authenticator: ")
                    if not totp.verify(totp_code):
                        print("[!] Invalid TOTP code.")
                        continue
                else:
                    print("[!] TOTP secret not found in superblock. Volume may be corrupted.")
                    sys.exit(1)

                self.volume_password = pwd
                self.key = password_key
                self.superblock = sb
                print("Welcome to MyFS.")
                return
            except Exception:
                print("[!] Decryption failed or invalid TOTP code.")
                continue
        print("[!] Too many wrong password attempts.")
        sys.exit(1)

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

    def list_files(self):
        files = [f for f in self.superblock['files'] if not f['deleted']]
        if not files:
            print("[*] No files in volume.")
            return
        for f in files:
            print(f"ID:{f['id']} Name:{f['name']} Deleted:{f['deleted']}")

    def import_file(self):
        path = input("File path to import: ").strip()
        if not os.path.isfile(path):
            print("[!] File not found.")
            return
        while True:
            file_pass = getpass("Set file password: ")
            file_pass2 = getpass("Confirm file password: ")
            if file_pass == file_pass2 and file_pass != '':
                break
            print("[!] Passwords do not match or empty. Try again.")
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except Exception as e:
            print("[!] Failed to read file:", e)
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
        print("[+] File imported")

    def export_file(self):
        try:
            fid = int(input("File ID to export: "))
        except ValueError:
            print("[!] Invalid ID")
            return
        f = next((f for f in self.superblock['files'] if f['id'] == fid and not f['deleted']), None)
        if not f:
            print("[!] File not found or deleted.")
            return
        file_pass = getpass("Enter file password: ")
        if hashlib.sha256(file_pass.encode()).hexdigest() != f['file_pass_hash']:
            print("[!] Wrong file password.")
            return
        data = self.decrypt_file_content(f['content'], file_pass)
        if data is None:
            print("[!] Decryption failed, wrong password or corrupted file.")
            return
        out_path = input("Export file path: ").strip()
        try:
            with open(out_path, 'wb') as f:
                f.write(data)
            print("[+] File exported.")
        except Exception as e:
            print("[!] Failed to write exported file:", e)

    def delete_file(self):
        try:
            fid = int(input("File ID to delete: "))
        except ValueError:
            print("[!] Invalid ID")
            return
        f = next((f for f in self.superblock['files'] if f['id'] == fid and not f['deleted']), None)
        if not f:
            print("[!] File not found or already deleted.")
            return
        file_pass = getpass("Enter file password: ")
        if hashlib.sha256(file_pass.encode()).hexdigest() != f['file_pass_hash']:
            print("[!] Wrong file password.")
            return
        f['deleted'] = True
        self.write_superblock()
        print("[+] File deleted.")

    def permanently_delete_file(self):
        try:
            fid = int(input("File ID to permanently delete: "))
        except ValueError:
            print("[!] Invalid ID")
            return
        f = next((f for f in self.superblock['files'] if f['id'] == fid), None)
        if not f:
            print("[!] File not found.")
            return
        file_pass = getpass("Enter file password: ")
        if hashlib.sha256(file_pass.encode()).hexdigest() != f['file_pass_hash']:
            print("[!] Wrong file password.")
            return
        # Overwrite content with null bytes
        f['content'] = '00' * (len(f['content']) // 2)  # Hex string of null bytes
        f['file_pass_hash'] = '0' * 64  # Overwrite password hash
        # Remove the file entry from superblock
        self.superblock['files'] = [file for file in self.superblock['files'] if file['id'] != fid]
        self.write_superblock()
        print("[+] File permanently deleted and data overwritten with null bytes.")

    def restore_file(self):
        # List soft-deleted files
        deleted_files = [f for f in self.superblock['files'] if f['deleted']]
        if not deleted_files:
            print("[*] No deleted files available to restore.")
            return
        print("[*] Deleted files available for restoration:")
        for f in deleted_files:
            print(f"ID:{f['id']} Name:{f['name']} Deleted:{f['deleted']}")

        # Proceed with restoration
        try:
            fid = int(input("File ID to restore: "))
        except ValueError:
            print("[!] Invalid ID")
            return
        f = next((f for f in self.superblock['files'] if f['id'] == fid and f['deleted']), None)
        if not f:
            print("[!] File not found or not deleted.")
            return
        file_pass = getpass("Enter file password: ")
        if hashlib.sha256(file_pass.encode()).hexdigest() != f['file_pass_hash']:
            print("[!] Wrong file password.")
            return
        # Verify file content integrity by attempting decryption
        data = self.decrypt_file_content(f['content'], file_pass)
        if data is None:
            print("[!] Cannot decrypt file, content may be corrupted.")
            return
        f['deleted'] = False
        self.write_superblock()
        print("[+] File restored.")

    def set_volume_password(self):
        old_pass = getpass("Enter current volume password: ")
        if old_pass != self.volume_password:
            print("[!] Wrong password.")
            return
        while True:
            new_pass1 = getpass("Enter new volume password: ")
            new_pass2 = getpass("Confirm new volume password: ")
            if new_pass1 == new_pass2 and new_pass1 != '':
                break
            print("Passwords do not match or empty. Try again.")

        new_password_key = derive_key(new_pass1)
        encrypted_key = aes_encrypt(self.superblock_key, new_password_key)

        key_path = input("Enter path to MyFS.key on removable disk: ").strip()
        with open(key_path, 'wb') as f:
            f.write(encrypted_key)

        self.volume_password = new_pass1
        self.key = new_password_key
        print("[+] Volume password changed.")

    def change_file_password(self):
        try:
            fid = int(input("File ID to change password: "))
        except ValueError:
            print("[!] Invalid ID")
            return
        f = next((f for f in self.superblock['files'] if f['id'] == fid and not f['deleted']), None)
        if not f:
            print("[!] File not found or deleted.")
            return
        old_pass = getpass("Enter old file password: ")
        if hashlib.sha256(old_pass.encode()).hexdigest() != f['file_pass_hash']:
            print("[!] Wrong file password.")
            return
        new_pass1 = getpass("Enter new file password: ")
        new_pass2 = getpass("Confirm new file password: ")
        if new_pass1 != new_pass2 or new_pass1 == '':
            print("[!] Passwords do not match or empty.")
            return
        # Decrypt content with old pass
        data = self.decrypt_file_content(f['content'], old_pass)
        if data is None:
            print("[!] Cannot decrypt file with old password. Abort.")
            return
        # Encrypt with new pass
        new_encrypted = self.encrypt_file_content(data, new_pass1)
        f['content'] = new_encrypted
        f['file_pass_hash'] = hashlib.sha256(new_pass1.encode()).hexdigest()
        self.write_superblock()
        print("[+] File password changed.")

    def run(self):
        cmds = {
            'list': self.list_files,
            'import': self.import_file,
            'export': self.export_file,
            'delete': self.delete_file,
            'pdelete': self.permanently_delete_file,
            'restore': self.restore_file,
            'setpass': self.set_volume_password,
            'chpass': self.change_file_password,
            'exit': sys.exit
        }
        while True:
            cmd = input(
                "\n"
                "+--------------------------------------------------------------------+\n"
                "|                        ENCRYPTED VOLUME MANAGER                    |\n"
                "+--------------------------------------------------------------------+\n"
                "| Available commands:                                                |\n"
                "|  list        - List all non-deleted files in the volume            |\n"
                "|  import      - Import a file into the volume with encryption       |\n"
                "|  export      - Export a file from the volume to the filesystem     |\n"
                "|  delete      - Soft delete a file (recoverable)                    |\n"
                "|  pdelete     - Permanently delete a file and overwrite its data    |\n"
                "|  restore     - Restore a soft-deleted file                         |\n"
                "|  setpass     - Change the volume's password                        |\n"
                "|  chpass      - Change the password of a specific file              |\n"
                "|  exit        - Exit the program                                    |\n"
                "+--------------------------------------------------------------------+\n"
                "\n"
                "> Enter command: "
            ).strip().lower()

            if cmd in cmds:
                cmds[cmd]()
            else:
                print("[!] Unknown command.")


def main():
    print_random_ascii_art()
    fs = MyFS()
    fs.run()



if __name__ == "__main__":
    main()
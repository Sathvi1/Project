import os
import hashlib
import base64
import platform
import threading
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QLabel, QLineEdit, QDialogButtonBox, QComboBox, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal
import time

# Password for encryption/decryption
PASSWORD = "securepassword"

class USBWatcherThread(QThread):
    """
    Background thread to monitor USB events.
    """
    usb_detected = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        """
        Continuously monitor USB devices and emit a signal when a new USB is detected.
        """
        system = platform.system()
        drive_list = set()

        if system == "Windows":
            import win32file
            while self.running:
                drives = win32file.GetLogicalDrives()
                for drive in range(26):
                    mask = 1 << drive
                    if drives & mask:
                        drive_letter = f"{chr(65 + drive)}:\\"
                        if win32file.GetDriveType(drive_letter) == win32file.DRIVE_REMOVABLE:
                            if drive_letter not in drive_list:
                                drive_list.add(drive_letter)
                                self.usb_detected.emit({"path": drive_letter})
                time.sleep(1)
        elif system == "Linux":
            import pyudev
            context = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(context)
            monitor.filter_by(subsystem="block", device_type="disk")
            for device in iter(monitor.poll, None):
                if device.action == "add":
                    self.usb_detected.emit({"path": device.device_node})


class PasswordDialog(QDialog):
    """
    Custom password dialog with action selection.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("USB Authentication")
        self.setFixedSize(300, 200)

        # Layout
        layout = QVBoxLayout(self)

        # Password input
        self.label = QLabel("Enter Password:")
        layout.addWidget(self.label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        # Action dropdown
        self.action_label = QLabel("Select Action:")
        layout.addWidget(self.action_label)
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Encrypt", "Decrypt"])
        layout.addWidget(self.action_combo)

        # Dialog buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    @staticmethod
    def get_password_and_action(parent=None):
        dialog = PasswordDialog(parent)
        result = dialog.exec_()
        password = dialog.password_input.text()
        action = dialog.action_combo.currentText()
        return password, action, result == QDialog.Accepted


class USBEncryptionApp:
    """
    Main application class to handle USB encryption and decryption.
    """
    def __init__(self):
        self.thread = USBWatcherThread()
        self.thread.usb_detected.connect(self.handle_usb_detection)
        self.thread.start()

    def handle_usb_detection(self, drive_info):
        """
        Handle USB detection and prompt for password and action.
        """
        print(f"USB drive detected: {drive_info['path']}")
        password, action, ok = PasswordDialog.get_password_and_action()
        if ok:
            if password == PASSWORD:
                if action == "Encrypt":
                    self.encrypt_usb_drive(drive_info["path"], password)
                elif action == "Decrypt":
                    self.decrypt_usb_drive(drive_info["path"], password)
            else:
                QMessageBox.critical(None, "Access Denied", "Incorrect password!")

    def encrypt_usb_drive(self, drive_path, password):
        """
        Encrypt all files on the USB drive and remove the originals.
        """
        key = self.generate_key(password)
        fernet = Fernet(key)

        for root, _, files in os.walk(drive_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Read and encrypt the file
                    with open(file_path, "rb") as f:
                        data = f.read()
                    encrypted_data = fernet.encrypt(data)

                    # Write the encrypted data to a new file and delete the original
                    encrypted_file_path = file_path + ".enc"
                    with open(encrypted_file_path, "wb") as f:
                        f.write(encrypted_data)
                    os.remove(file_path)
                    print(f"Encrypted and replaced: {file_path}")
                except Exception as e:
                    print(f"Failed to encrypt {file_path}: {e}")

    def decrypt_usb_drive(self, drive_path, password):
        """
        Decrypt all files on the USB drive and remove the encrypted files.
        """
        key = self.generate_key(password)
        fernet = Fernet(key)

        for root, _, files in os.walk(drive_path):
            for file in files:
                if file.endswith(".enc"):
                    encrypted_file_path = os.path.join(root, file)
                    try:
                        # Read and decrypt the file
                        with open(encrypted_file_path, "rb") as f:
                            encrypted_data = f.read()
                        data = fernet.decrypt(encrypted_data)

                        # Write the decrypted data to a new file and delete the encrypted file
                        original_file_path = encrypted_file_path.replace(".enc", "")
                        with open(original_file_path, "wb") as f:
                            f.write(data)
                        os.remove(encrypted_file_path)
                        print(f"Decrypted and replaced: {encrypted_file_path}")
                    except Exception as e:
                        print(f"Failed to decrypt {encrypted_file_path}: {e}")

    def generate_key(self, password):
        """
        Generate a Fernet key using the given password.
        """
        key = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), b"salt", 100000, dklen=32
        )
        return base64.urlsafe_b64encode(key)


if __name__ == "__main__":
    app = QApplication([])
    usb_app = USBEncryptionApp()
    app.exec_()

import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QClipboard
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class RSAApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RSA message Encryptor/Decryptor")
        self.setGeometry(100, 100, 800, 400)

        # Main container widget
        container = QWidget()
        self.setCentralWidget(container)
        layout = QHBoxLayout(container)

        # Apply global styles
        self.setStyleSheet("""
            QWidget {
                background-color: #2e2e2e;  
                color: white;              
            }
            QPushButton {
                background-color: #3e3e3e; 
                color: white;              
                border: 1px solid white;   
                padding: 5px;
            }
            QTextEdit, QLabel {
                background-color: #3e3e3e; 
                color: white;              
            }
            QPushButton:hover {
                background-color: #5e5e5e; 
            }
        """)

        # Left segment: Decryption
        self.decryption_widget = self.create_decryption_segment()
        layout.addWidget(self.decryption_widget)

        # Right segment: Encryption
        self.encryption_widget = self.create_encryption_segment()
        layout.addWidget(self.encryption_widget)

    def create_decryption_segment(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Title
        title = QLabel("<b>Decryption</b>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(title)

        # Private key file loader
        self.private_key_path_label = QLabel("No private key file selected")
        layout.addWidget(self.private_key_path_label)
        select_private_key_btn = QPushButton("Load Private Key from File")
        select_private_key_btn.clicked.connect(self.load_private_key)
        layout.addWidget(select_private_key_btn)

        # Cipher text input
        layout.addWidget(QLabel("Cipher Text (hex):"))
        self.cipher_text_box = QTextEdit()
        layout.addWidget(self.cipher_text_box)

        # Decryption result
        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.clicked.connect(self.decrypt_message)
        layout.addWidget(decrypt_btn)
        self.decrypted_message_label = QLabel("Decrypted Message (hex): ")
        layout.addWidget(self.decrypted_message_label)

        return widget

    def create_encryption_segment(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Title
        title = QLabel("<b>Encryption</b>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(title)

        # Public key file loader or manual entry
        self.public_key_path_label = QLabel("No public key file selected")
        layout.addWidget(self.public_key_path_label)
        select_public_key_btn = QPushButton("Load Public Key from File")
        select_public_key_btn.clicked.connect(self.load_public_key)
        layout.addWidget(select_public_key_btn)
        layout.addWidget(QLabel("Or enter public key manually:"))
        self.public_key_box = QTextEdit()
        layout.addWidget(self.public_key_box)

        # Message to encrypt
        layout.addWidget(QLabel("Message to encrypt:"))
        self.message_box = QTextEdit()
        layout.addWidget(self.message_box)

        # Encryption result
        encrypt_btn = QPushButton("Encrypt")
        encrypt_btn.clicked.connect(self.encrypt_message)
        layout.addWidget(encrypt_btn)

        self.encrypted_message_label = QTextEdit("Encrypted Cipher Text (hex): ")
        self.encrypted_message_label.setReadOnly(True)
        layout.addWidget(self.encrypted_message_label)

        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_to_clipboard)
        layout.addWidget(copy_btn)

        return widget

    def load_private_key(self):
        initial_dir = os.getcwd()  # Get the current working directory
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Private Key File", initial_dir)
        if file_path:
            self.private_key_path_label.setText(f"Loaded Private Key: {file_path}")
            self.private_key_path = file_path

    def load_public_key(self):
        initial_dir = os.getcwd()  # Get the current working directory
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Public Key File", initial_dir)
        if file_path:
            self.public_key_path_label.setText(f"Loaded Public Key: {file_path}")
            with open(file_path, "r") as f:
                self.public_key_box.setText(f.read())

    def decrypt_message(self):
        try:
            with open(self.private_key_path, "r") as f:
                private_key = RSA.import_key(f.read())
            cipher = PKCS1_OAEP.new(private_key)
            cipher_text = self.cipher_text_box.toPlainText()
            cipher_bytes = bytes.fromhex(cipher_text)
            decrypted_message = cipher.decrypt(cipher_bytes).decode()
            wrapped_decrypted_message = '\n'.join(
            decrypted_message[i:i + 64] for i in range(0, len(decrypted_message), 64)
        )
            self.decrypted_message_label.setText(f"Decrypted Message: {wrapped_decrypted_message}")
        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", str(e))

    def encrypt_message(self):
        try:
            public_key_data = self.public_key_box.toPlainText()
            public_key = RSA.import_key(public_key_data)
            cipher = PKCS1_OAEP.new(public_key)
            message = self.message_box.toPlainText()
            cipher_text = cipher.encrypt(message.encode())
            wrapped_cipher_text = '\n'.join(
                cipher_text.hex()[i:i + 64] for i in range(0, len(cipher_text.hex()), 64)
            )
            self.encrypted_message_label.setText(wrapped_cipher_text)
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", str(e))

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.encrypted_message_label.toPlainText())
        QMessageBox.information(self, "Copied to Clipboard", "Encrypted cipher text has been copied!")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RSAApp()
    window.show()
    sys.exit(app.exec())

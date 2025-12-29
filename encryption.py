import sys
import string
import random
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLineEdit, 
                             QPushButton, QTextEdit, QLabel, QMessageBox, QInputDialog)
from PyQt5.QtCore import Qt

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
       
        self.chars = " " + string.ascii_letters + string.digits + string.punctuation
        self.chars = list(self.chars)
        self.key = self.chars.copy()
        random.shuffle(self.key)
        
        self.saved_password = "" 
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Secure Text Encryptor")
        self.setGeometry(600, 300, 500, 500)
        self.setStyleSheet("background-color: #121212; color: white;")

        vbox = QVBoxLayout()

        # Input Area
        vbox.addWidget(QLabel("Enter Message to Encrypt/Decrypt:"))
        self.text_input = QTextEdit()
        self.text_input.setStyleSheet("background-color: #1e1e1e; color: white; border: 1px solid #444; font-size: 16px;")
        vbox.addWidget(self.text_input)

        # Encrypt Button (Sets the initial password)
        self.encrypt_btn = QPushButton("ENCRYPT MESSAGE")
        self.encrypt_btn.setFixedHeight(50)
        self.encrypt_btn.setStyleSheet("background-color: #27ae60; font-weight: bold; border-radius: 5px;")
        self.encrypt_btn.clicked.connect(self.encrypt_logic)
        vbox.addWidget(self.encrypt_btn)

        # Decrypt Button (Triggers the password prompt loop)
        self.decrypt_btn = QPushButton("DECRYPT MESSAGE")
        self.decrypt_btn.setFixedHeight(50)
        self.decrypt_btn.setStyleSheet("background-color: #2980b9; font-weight: bold; border-radius: 5px;")
        self.decrypt_btn.clicked.connect(self.decrypt_logic)
        vbox.addWidget(self.decrypt_btn)

        # Result Display
        vbox.addWidget(QLabel("Result:"))
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        self.result_output.setStyleSheet("background-color: #111; color: #00FF00; font-size: 16px;")
        vbox.addWidget(self.result_output)

        self.setLayout(vbox)

    def encrypt_logic(self):
        # Step 1: Ask for the password to set it
        text, ok = QInputDialog.getText(self, 'Set Password', 
                                        'Enter the password that is going to be used for decryption:', 
                                        QLineEdit.Password)
        
        if ok and text:
            self.saved_password = text
            plaintext = self.text_input.toPlainText()
            ciphertext = ""
            for letter in plaintext:
                if letter in self.chars:
                    index = self.chars.index(letter)
                    ciphertext += self.key[index]
                else:
                    ciphertext += letter
            self.result_output.setText(ciphertext)
            QMessageBox.information(self, "Success", "Encrypted! Use the set password to decrypt later.")
        else:
            QMessageBox.warning(self, "Cancelled", "Encryption cancelled. Password is required.")

    def decrypt_logic(self):
        if not self.saved_password:
            QMessageBox.warning(self, "Error", "No password set. Encrypt something first.")
            return

        # Step 2: Persistent Loop (Like your 'while True' logic)
        while True:
            password_check, ok = QInputDialog.getText(self, 'Password Required', 
                                                      'Enter the password for decryption:', 
                                                      QLineEdit.Password)
            
            # If user clicks cancel
            if not ok:
                break 
            
            # If password is correct
            if password_check == self.saved_password:
                ciphertext = self.text_input.toPlainText()
                plaintext = ""
                for letter in ciphertext:
                    if letter in self.key:
                        index = self.key.index(letter)
                        plaintext += self.chars[index]
                    else:
                        plaintext += letter
                self.result_output.setText(plaintext)
                QMessageBox.information(self, "Success", "Decryption Successful!")
                break
            
            # If password is wrong
            else:
                retry = QMessageBox.question(self, "Incorrect Password", 
                                             "Incorrect password! Do you want to try again?",
                                             QMessageBox.Yes | QMessageBox.No)
                if retry == QMessageBox.No:
                    print("Exiting decryption...")
                    break

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptionApp()
    ex.show()
    sys.exit(app.exec_())

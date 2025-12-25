import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QPushButton, QLabel, QLineEdit, QMessageBox, 
                             QGridLayout, QStackedWidget, QFrame)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QFontDatabase

class BankApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.balance = 1250.50  # Starting balance
        self.user_id = ""
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Global Bank ATM")
        self.setFixedSize(500, 650)
        self.setStyleSheet("background-color: #1a1a1a; color: #ecf0f1;")

        # The StackedWidget allows us to switch screens
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        # Create Screens
        self.setup_id_screen()      # Screen 0
        self.setup_pin_screen()     # Screen 1
        self.setup_menu_screen()    # Screen 2
        self.setup_transfer_screen() # Screen 3

    # --- SCREEN 0: IDENTIFICATION ---
    def setup_id_screen(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        lbl = QLabel("WELCOME TO GLOBAL BANK\n\nPlease enter Account, Card, \nor Phone Number:")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("font-size: 18px; margin-top: 50px;")
        
        self.id_input = QLineEdit()
        self.id_input.setPlaceholderText("Enter Identification")
        self.id_input.setStyleSheet(self.get_input_style())
        self.id_input.setFixedHeight(50)

        next_btn = self.create_nav_btn("CONTINUE")
        next_btn.clicked.connect(self.go_to_pin)

        layout.addWidget(lbl)
        layout.addWidget(self.id_input)
        layout.addStretch()
        layout.addWidget(next_btn)
        self.stack.addWidget(page)

    # --- SCREEN 1: PIN ENTRY ---
    def setup_pin_screen(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        lbl = QLabel("ENTER ATM PIN")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("font-size: 24px; font-weight: bold; margin-top: 50px;")
        
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_input.setPlaceholderText("****")
        self.pin_input.setMaxLength(4)
        self.pin_input.setStyleSheet(self.get_input_style())
        self.pin_input.setFixedHeight(60)

        next_btn = self.create_nav_btn("LOGIN")
        next_btn.clicked.connect(self.go_to_menu)

        layout.addWidget(lbl)
        layout.addWidget(self.pin_input)
        layout.addStretch()
        layout.addWidget(next_btn)
        self.stack.addWidget(page)

    # --- SCREEN 2: MAIN MENU (ATM STYLE) ---
    def setup_menu_screen(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        # Screen Header
        self.welcome_lbl = QLabel("HELLO, USER")
        self.welcome_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.welcome_lbl)

        # Visual Screen
        screen_frame = QFrame()
        screen_frame.setStyleSheet("background-color: #002b36; border: 3px solid #073642; border-radius: 10px;")
        screen_layout = QVBoxLayout(screen_frame)
        
        self.balance_display = QLabel(f"BALANCE\n${self.balance:.2f}")
        self.balance_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.balance_display.setStyleSheet("font-size: 35px; color: #268bd2; font-family: 'Courier New';")
        screen_layout.addWidget(self.balance_display)
        layout.addWidget(screen_frame)

        # Function Grid
        grid = QGridLayout()
        btns = [
            ("DEPOSIT", self.handle_deposit),
            ("WITHDRAW", self.handle_withdraw),
            ("TRANSFER", lambda: self.stack.setCurrentIndex(3)),
            ("EXIT", lambda: self.stack.setCurrentIndex(0))
        ]

        for i, (text, func) in enumerate(btns):
            btn = QPushButton(text)
            btn.setFixedSize(200, 60)
            btn.setStyleSheet(self.get_btn_style())
            btn.clicked.connect(func)
            grid.addWidget(btn, i // 2, i % 2)

        layout.addLayout(grid)
        
        # Generic Amount Input for Deposit/Withdraw
        self.main_amount_input = QLineEdit()
        self.main_amount_input.setPlaceholderText("Enter Amount for Deposit/Withdraw")
        self.main_amount_input.setStyleSheet(self.get_input_style())
        layout.addWidget(self.main_amount_input)

        self.stack.addWidget(page)

    # --- SCREEN 3: TRANSFER SCREEN ---
    def setup_transfer_screen(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        lbl = QLabel("TRANSFER FUNDS")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet("font-size: 20px; font-weight: bold;")

        self.target_acc = QLineEdit()
        self.target_acc.setPlaceholderText("Target Account Number")
        self.target_acc.setStyleSheet(self.get_input_style())

        self.transfer_amt = QLineEdit()
        self.transfer_amt.setPlaceholderText("Amount to Send")
        self.transfer_amt.setStyleSheet(self.get_input_style())

        send_btn = self.create_nav_btn("CONFIRM TRANSFER")
        send_btn.clicked.connect(self.process_transfer)

        back_btn = QPushButton("CANCEL")
        back_btn.clicked.connect(lambda: self.stack.setCurrentIndex(2))

        layout.addWidget(lbl)
        layout.addWidget(self.target_acc)
        layout.addWidget(self.transfer_amt)
        layout.addWidget(send_btn)
        layout.addWidget(back_btn)
        self.stack.addWidget(page)

    # --- LOGIC METHODS ---
    def go_to_pin(self):
        if self.id_input.text():
            self.user_id = self.id_input.text()
            self.welcome_lbl.setText(f"ACCOUNT: {self.user_id}")
            self.stack.setCurrentIndex(1)
        else:
            QMessageBox.warning(self, "Error", "Please identify yourself")

    def go_to_menu(self):
        if self.pin_input.text() == "1234": # Hardcoded PIN for demo
            self.stack.setCurrentIndex(2)
        else:
            QMessageBox.critical(self, "Error", "Invalid PIN")

    def handle_deposit(self):
        try:
            amt = float(self.main_amount_input.text())
            self.balance += amt
            self.update_ui()
        except: QMessageBox.warning(self, "Error", "Enter valid amount")

    def handle_withdraw(self):
        try:
            amt = float(self.main_amount_input.text())
            if amt <= self.balance:
                self.balance -= amt
                self.update_ui()
            else: QMessageBox.critical(self, "Error", "Insufficient Funds")
        except: QMessageBox.warning(self, "Error", "Enter valid amount")

    def process_transfer(self):
        try:
            amt = float(self.transfer_amt.text())
            acc = self.target_acc.text()
            if acc and amt <= self.balance:
                self.balance -= amt
                QMessageBox.information(self, "Success", f"Sent ${amt} to {acc}")
                self.update_ui()
                self.stack.setCurrentIndex(2)
            else: QMessageBox.warning(self, "Error", "Check details")
        except: pass

    def update_ui(self):
        self.balance_display.setText(f"BALANCE\n${self.balance:.2f}")
        self.main_amount_input.clear()
        self.transfer_amt.clear()
        self.target_acc.clear()

    # --- STYLING HELPERS ---
    def get_input_style(self):
        return "background-color: #333; color: white; border: 1px solid #555; padding: 5px; font-size: 18px;"

    def get_btn_style(self):
        return "QPushButton { background-color: #2c3e50; color: white; font-weight: bold; border-radius: 5px; } QPushButton:hover { background-color: #34495e; }"

    def create_nav_btn(self, text):
        btn = QPushButton(text)
        btn.setFixedHeight(50)
        btn.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold; font-size: 16px;")
        return btn

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = BankApp()
    ex.show()
    sys.exit(app.exec())
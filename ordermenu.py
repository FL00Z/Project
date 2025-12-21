import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QListWidget, QPushButton, QLineEdit, QFrame)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QFontDatabase

class FoodOrderApp(QWidget):
    def __init__(self):
        super().__init__()
        self.menu = {
            "pizza": 10.00, "burger": 20.00, "pasta": 30.00,
            "sandwich": 40.00, "fries": 50.00, "coke": 60.00, "popcorn": 70.00
        }
        self.cart = []
        self.total = 0.0
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Digital Food Ordering System")
        self.setGeometry(600, 300, 500, 650)
        self.setStyleSheet("background-color: black; color: white;")

        vbox = QVBoxLayout()

        #  Menu Header
        header = QLabel("--- DIGITAL MENU ---")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 24px; color: #00FF00; font-weight: bold; margin-bottom: 10px;")
        vbox.addWidget(header)

        #  Horizontal Layout for Menu and Cart
        hbox = QHBoxLayout()
        
        # Menu List
        self.menu_list = QListWidget()
        for item, price in self.menu.items():
            self.menu_list.addItem(f"{item.capitalize()}: ${price:.2f}")
        self.menu_list.setStyleSheet("background-color: #111; color: white; font-size: 16px; border: 1px solid #444; padding: 5px;")
        hbox.addWidget(self.menu_list)

        vbox.addLayout(hbox)

        #  Action Buttons
        self.add_btn = QPushButton("ADD TO CART")
        self.add_btn.setFixedHeight(50)
        self.add_btn.setCursor(Qt.PointingHandCursor) # Changes cursor to hand
        self.add_btn.setStyleSheet("background-color: #27ae60; font-weight: bold; border-radius: 5px;")
        self.add_btn.clicked.connect(self.add_to_cart)
        vbox.addWidget(self.add_btn)

        
        vbox.addWidget(QLabel("TOTAL BILL:"))
        self.total_display = QLineEdit("Total: $0.00")
        self.total_display.setReadOnly(True)
        self.total_display.setAlignment(Qt.AlignCenter)
        
        
        self.total_display.setFixedHeight(100) 
        self.total_display.setStyleSheet("""
            QLineEdit {
                background-color: #111;
                color: #00FF00;
                border: 2px solid #444;
                font-size: 40px; 
                border-radius: 10px;
                padding-top: 20px; 
            }
        """)
        vbox.addWidget(self.total_display)

        #  Reset Button
        self.reset_btn = QPushButton("CLEAR ORDER")
        self.reset_btn.setFixedHeight(40)
        self.reset_btn.setStyleSheet("background-color: #c0392b; font-weight: bold; border-radius: 5px;")
        self.reset_btn.clicked.connect(self.clear_order)
        vbox.addWidget(self.reset_btn)

        self.setLayout(vbox)

        # Load Digital Font for the Total Display
        try:
            font_path = "C:\\Users\\parih\\OneDrive\\Desktop\\Python\\digital_clock\\DS-DIGI.TTF"
            font_id = QFontDatabase.addApplicationFont(font_path)
            if font_id != -1:
                font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
                self.total_display.setFont(QFont(font_family, 40))
        except:
            pass

    def add_to_cart(self):
        selected = self.menu_list.currentItem()
        if selected:
            item_text = selected.text().split(":")[0].lower()
            price = self.menu[item_text]
            self.cart.append(item_text)
            self.total += price
            self.total_display.setText(f"Total: ${self.total:.2f}")

    def clear_order(self):
        self.cart = []
        self.total = 0.0
        self.total_display.setText("Total: $0.00")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = FoodOrderApp()
    ex.show()
    sys.exit(app.exec_())
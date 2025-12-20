import re
import sys
from PyQt5.QtWidgets import QApplication,QWidget,QLabel,QLineEdit,QPushButton,QVBoxLayout,QCheckBox,QProgressBar
from PyQt5.QtCore import Qt


class  PasswordAnalz(QWidget):
    def __init__(self):
        super().__init__()
        self.password_analyzer = QLabel("Enter the password ")
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.strength_meter = QProgressBar(self)
        self.strength_meter.setRange(0,100)
        self.strength_meter.setValue(0)
        self.strength_meter.setValue(False)
        self.show_password_checkbox = QCheckBox("Show password",self)
        self.check_password_button = QPushButton("Check the password",self)
        self.description_label = QLabel(self)
        self.initUI()

    def initUI(self) :
     self.setWindowTitle("Password Analyzer")
     vbox = QVBoxLayout()

     vbox.addWidget(self.password_analyzer)
     vbox.addWidget(self.password_input)
     vbox.addWidget(self.show_password_checkbox)
     vbox.addWidget(self.strength_meter)
     vbox.addWidget(self.check_password_button)
     vbox.addWidget(self.description_label)

     self.setLayout(vbox)


     self.password_analyzer.setAlignment(Qt.AlignCenter)
     self.password_input.setAlignment(Qt.AlignCenter)
     self.description_label.setAlignment(Qt.AlignCenter)

     self.password_analyzer.setObjectName("password_analyzer")
     self.password_input.setObjectName("password_input")
     self.check_password_button.setObjectName("check_password_button")
     self.description_label.setObjectName("description_label")
     self.show_password_checkbox.setObjectName("show_password_checkbox")

     self.setStyleSheet("""
                  QLabel,QPushButton,QCheckBox{
                        font-family: calibri;
                    }
                  QLabel#password_analyzer{
                        font-size: 40px;
                        font-style: italic;
                    }
                  QPushButton#check_password_button{
                        font-size: 30px;
                        font-weight: bold;
                        }
                  QLineEdit#password_input{
                        font-size: 40px;
                        } 
                  QLabel#description_label{
                        font-size:50px;
                    }    """)
     self.password_input.textChanged.connect(self.update_meter)
     self.check_password_button.clicked.connect(self.display_result)
     self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)


    def update_meter(self,text) :
        length = len(text)
        progress = min(100,(length/8)*100)
        self.strength_meter.setValue(int(progress))

        if progress <40 :
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: red; }")
        elif progress < 75:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: orange; }")
        else:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: green; }")



    def  toggle_password_visibility(self,state):
        if state == Qt.Checked:
            self.password_input.setEchoMode(QLineEdit.Normal)

        else:
            self.password_input.setEchoMode(QLineEdit.Password)
        

    def check_password_strength(self,password):
        banned = ["password123", "12345678", "qwertyuiop"]
        if password.lower()  in banned:
            return f"password Do't use common password"
    
        if len(password) < 8 :
            return f"password is weak must have 8 char"
    
        if not any (char.isdigit() for char in password):
            return f"password must have digit"
    
        if not any (char.isupper() for char in password):
            return f"password must have upper char"
    
        if not any (char.islower() for char in password):
            return f"password must have a lower letter"
    
        if not re.search(r'[!@#$%^&*(){}<>?.,]',password):
            return f"password must have special char"
 
        return f"password is strong "

    
    def display_result(self):
        password = self.password_input.text()

        if not password:
            self.description_label.setText("Please enter a password first !")
            return

        result = self.check_password_strength(password)
        self.description_label.setText(result)



if __name__ == "__main__" :
    app = QApplication(sys.argv)
    password_analyzer = PasswordAnalz()
    password_analyzer.show()
    sys.exit(app.exec())
    
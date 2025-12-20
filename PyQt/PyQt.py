import sys
from PyQt5.QtWidgets import QApplication,QMainWindow,QLabel
from PyQt5.QtGui import QIcon
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GUI Application")
        self.setGeometry(0,0,400,250)
        self.setWindowIcon(QIcon("C:\\Users\\parih\\OneDrive\\Desktop\\Python\\Gemini_Generated_Image_k2kypxk2kypxk2ky.png"))
        

        label = QLabel("Hello",self)
        label.setFont(QFont("Arial",30))
        label.setGeometry(135,50,500,100)
        label.setStyleSheet("Color: teal;"
                            "background-color:black;"
                            "font-weight:bold;"
                            "font-style:italic;" 
                            "text-decoration:underline;")
        
     #  label.setAlignment(Qt.Alignment(Qt.AlignTop)) #vertically top
     #  label.setAlignment(Qt.Alignment(Qt.AlignBottom)) #vertically bottom    
     #  label.setAlignment(Qt.Alignment(Qt.AlignVCenter)) #vertically center

     #  label.setAlignment(Qt.Alignment(Qt.AlignRight)) #Horizontally right
     #  label.setAlignment(Qt.Alignment(Qt.AlignHCenter)) #Horizontally center
     #  label.setAlignment(Qt.Alignment(Qt.AlignLeft)) #Horizontally left

     #  label.setAlignment(Qt.Alignment(Qt.AlignHCenter | Qt.AlignTop)) #center & top
     #  label.setAlignment(Qt.Alignment(Qt.AlignHCenter | Qt.AlignBottom)) #center & bottom
     #  label.setAlignment(Qt.Alignment(Qt.AlignCenter) #center & center

def main():
    app=QApplication(sys.argv)
    window=MainWindow() 
    window.show()
    sys.exit(app.exec_())



if __name__=="__main__":
    main()
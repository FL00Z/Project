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
        label.setGeometry(0,0,500,100)
        label.setStyleSheet("Color: teal;"
                            "background-color:black;"
                            "font-weight:bold;"
                            "font-style:italic;" 
                            "text-decoration:underline;")
        
        #label.setAlignment(Qt.AlignTop) #vertically top
        #label.setAlignment(Qt.AlignBottom) #vertically bottom
        #label.setAlignment(Qt.AlignVCenter) #vertically center
         
        #label.setAlignment(Qt.AlignRight) #Horizontally right
        #label.setAlignment(Qt.AlingnLeft) #Horizontally left
        #label.setAlignment(Qt.AlignHCenter) #Horizontally center
        
        #label.setAlignment(Qt.AlignHCenter|Qt.alignTop) #center &Top
        #label.setAlignment(Qt.AlignHCenter|Qt.AlignBottom) #center & bottom
        #label.setAlignment(Qt.AlignLeft|Qt.AlignVCenter) #left & center         

        label.setAlignment(Qt.AlignCenter)



def main():
    app=QApplication(sys.argv)
    window=MainWindow() 
    window.show()
    sys.exit(app.exec_())



if __name__=="__main__":
    main()
import sys
from PyQt5.QtWidgets import (QApplication,
                             QMainWindow,
                             QLabel,
                             QWidget,
                             QVBoxLayout,
                             QHBoxLayout,
                             QGridLayout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setGeometry(700,300,500,500)
        self.initUI()
    
    def initUI(self):
        center_widget=QWidget()
        self.setCentralWidget(center_widget)

        label1=QLabel("Label 1")
        label2=QLabel("Label 2")
        label3=QLabel("Label 3")
        label4=QLabel("Label 4")
        label5=QLabel("Label 5")

        label1.setStyleSheet("background-color:red;")
        label2.setStyleSheet("background-color:yellow;")
        label3.setStyleSheet("background-color:blue;")
        label4.setStyleSheet("background-color:purple;")
        label5.setStyleSheet("background-color:green;")

       
        #vbox = QVBoxLayout()
        #hbox = QHBoxLayout()
        #grid= QGridLayout()
        
        # vbox or hbox.layout.addWidget(label1)   #|
        # vbox or hbox.layout.addWidget(label2)   #|
        # vbox or hbox.layout.addWidget(label3)   #|----only for vbox and hbox
        # vbox or hbox.layout.addWidget(label4)   #|
        # vbox or hbox.layout.addWidget(label5)   #|
        
        #grid.addWidget(label1,0,0)               #|
        #grid.addWidget(label2,0,1)               #|
        #grid.addWidget(label3,1,0)               #|-----only for grid 
        #grid.addWidget(label4,1,1)               #|
        #grid.addWidget(label5,1,2)               #|
        
        #center_widget.setLayout(grid)           |  for grid only
        #center_widget.setLayout(vbox or hbox)   |  for vbox or hbox only


def main():
    app=QApplication(sys.argv)
    window=MainWindow() 
    window.show()
    sys.exit(app.exec_())



if __name__=="__main__":
    main()
class student:
    
    count=0
    total_marks=0
    
    def __init__(self,name,marks):
        self.name=name
        self.marks=marks
        student.count+=1
        student.total_marks+=marks
    
    def get_info(self):
        return f"{self.name} - {self.marks}"
    @classmethod
    def get_count(cls):
        return f"totals students : {cls.count}"
    @classmethod
    def get_average_marks(cls):
        if cls.count == 0:
            return "No students available to calculate average."
        average = cls.total_marks / cls.count
        return f"Average marks : {average:.2f}"

s1=student("Archit",85)
s2=student("Rohit",90)        
s3=student("Virat",78)

print(s1.get_info())
print(s2.get_info())
print(s3.get_info())
print(student.get_count())
print(student.get_average_marks())
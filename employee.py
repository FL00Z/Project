class Employee:
    def __init__(self, name, age, position):
        self.name = name
        self.age = age
        self.position = position

    def get_info(self):
        return f"{self.name}= {self.position}"
    
    @staticmethod
    def is_valid_position(position):
        valid_positions = ["Manager", "Team Lead", "Developer", "Designer"]
        return position in valid_positions
    
Employee1 = Employee("Alice", 30, "Developer")
Employee2 = Employee("Bob", 25, "Designer")
Employee3 = Employee("Charlie", 28, "Manager")

print(Employee.is_valid_position("Manager"))
print(Employee.is_valid_position("Intern"))
print(Employee1.get_info())
print(Employee2.get_info())
print(Employee3.get_info())

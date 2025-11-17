class Jet:
    
    def __init__(self,manufacturer,model,version,speed):
        self.manufacturer=manufacturer
        self.model=model
        self.version=version
        self.speed=speed

    def __str__(self):
        return f"{self.manufacturer} {self.model} {self.version} {self.speed}"

    def __eq__(self,other):
        return (self.manufacturer==other.manufacturer and
                self.model==other.model and
                self.version==other.version and
                self.speed==other.speed)

    def __lt__(self,other):
        return (self.speed < other.speed) 
    
    def __gt__(self,other):
        return (self.speed > other.speed)
    
    def __add__(self,other):
        return self.speed + other.speed
    
    def __contains__(self,keyword):
        return keyword in self.version or keyword in self.manufacturer


jet1=Jet("Boeing","f22","airforce",1.65)   
jet2=Jet("Airbus","eurofighter","army",1.8)
jet3=Jet("Boeing","f22","army",1.65)

print(jet1)
print(jet2) 
print(jet3)
print(jet1==jet2)
print(jet1>jet3)
print(jet1<jet2)
print(jet1+jet2)
print("airforce" in jet1)
print("boeing" in jet1)

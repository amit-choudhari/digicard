import inspect
import array
from control import Control

#          CLA  INS  P1   P2   Lc  |--------Data------------->
AID =     [0x00,0xA4,0x04,0x00,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x07]
CLA =     [0xB0]
NAME =    [0x04,0x41, 0x6D, 0x69, 0x74]
PRENOM =  [0xB0,0x02,0x00,0x00,0x09,0x43, 0x68, 0x6F, 0x75, 0x64, 0x68, 0x61, 0x72, 0x69]
PIN =     [0xB0,0x03,0x00,0x00,0x06,0x1,0x2,0x3,0x4,0x5,0x6]
MAC =     [0xB0,0x50,0x00,0x00,0x08,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8]
GET_BAL = [0xB0,0x41,0x00,0x00,0x01,0x00]
P1_P2 =   [0x00, 0x00]

# INS
INS_ENROLL_name = 0x00
INS_ENROLL_surname = 0x01
INS_ENROLL_PIN = 0x03
                    
INS_VERIFY_PIN = 0x10
INS_DEBIT = 0x20
INS_CREDIT = 0x30
INS_GET_BAL = 0x41;

class user_apps:
    def __init__ (self):
        self.card = Control()
        self.card.connect()

    def close(self):
        self.card.disconnect()

    def enroll_name(self):
        print(inspect.stack()[0].function)
        name = array.array('b',input("Enter Name:").encode()).tolist()
        print(name)
        ins = [INS_ENROLL_name]
        data = name
        size = [len(name)]
        self.card.send(ins, data, size)
    
    def enroll_surname(self):
        print(inspect.stack()[0].function)
        surname = array.array('b',input("Enter Surname:").encode()).tolist()
        print(surname)
        ins = [INS_ENROLL_surname]
        data = surname
        size = [len(surname)]
        self.card.send(ins, data, size)
    
    def enroll_pin(self):
        print(inspect.stack()[0].function)
        pin = array.array('b',input("Enter New PIN:").encode()).tolist()
        print(pin)
        ins = [INS_ENROLL_PIN]
        data = pin
        size = [len(pin)]
        self.card.send(ins, data, size)
    
    def verify_pin(self):
        print(inspect.stack()[0].function)
        pin = array.array('b',input("Enter PIN:").encode()).tolist()
        print(pin)
        ins = [INS_VERIFY_PIN]
        data = pin
        size = [len(pin)]
        self.card.send(ins, data, size)
    
    def debit(self):
        print(inspect.stack()[0].function)
        amt = [int(input("Enter amount:"))]
        print(amt)
        ins = [INS_DEBIT]
        data = amt
        size = [len(amt)]
        self.card.send(ins, data, size)
    
    def credit(self):
        print(inspect.stack()[0].function)
        amt = [int(input("Enter amount:"))]
        print(amt)
        ins = [INS_CREDIT]
        data = amt
        size = [len(amt)]
        self.card.send(ins, data, size)
    
    def balance(self):
        print(inspect.stack()[0].function)
        amt = []
        print(amt)
        ins = [INS_GET_BAL]
        data = amt
        size = [len(amt)]
        self.card.send(ins, data, size)
        
    def exchange(self):
        print(inspect.stack()[0].function)
        self.card.send(ins, data, size)

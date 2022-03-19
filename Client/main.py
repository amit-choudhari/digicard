import sys
import inspect
from apps import user_apps

HELP = """========================
commands
-----------------------
1. Enroll: name
2. Enroll: surname
3. Enroll: PIN
4. Verify: PIN
5. Debit
6. Credit
7. Balance
8. Exchange
9. Exit
=======================
"""
ENROLL_NAME = 1
ENROLL_SURNAME =2
ENROLL_PIN = 3
VERIFY_PIN = 4
DEBIT = 5
CREDIT = 6
BALANCE = 7
EXCHANGE = 8
EXIT = 9

def enroll_name(session):
    session.enroll_name()

def enroll_surname(session):
    session.enroll_surname()

def enroll_pin(session):
    session.enroll_pin()

def verify_pin(session):
    session.verify_pin()

def debit(session):
    session.debit()

def credit(session):
    session.credit()

def exchange(session):
    session.exchange()

def balance(session):
    session.balance()

options = {
        ENROLL_NAME : enroll_name,
        ENROLL_SURNAME : enroll_surname,
        ENROLL_PIN : enroll_pin,
        VERIFY_PIN : verify_pin,
        DEBIT : debit,
        CREDIT : credit,
        BALANCE : balance,
        EXCHANGE : exchange,
}
def main():
    exit = False
    print(HELP)
    session = user_apps()

    while exit != True:
        cmd = int(input("Select cmd:"))
        if cmd == EXIT:
            session.close()
            exit = True
        else:
            options[cmd](session)
        print()


if __name__ == "__main__":
   main()

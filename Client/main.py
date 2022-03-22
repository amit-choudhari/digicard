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
0. Test
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
TEST = 0


def enroll_name(session):
    session.enroll_name()
    return False

def enroll_surname(session):
    session.enroll_surname()
    return False

def enroll_pin(session):
    session.enroll_pin()
    return False

def verify_pin(session):
    session.verify_pin()
    return False

def debit(session):
    session.debit()
    return False

def credit(session):
    session.credit()
    return False

def exchange(session):
    session.exchange()
    return True

def balance(session):
    session.balance()
    return False

def test(session):
    session.test()
    return False

options = {
        ENROLL_NAME : enroll_name,
        ENROLL_SURNAME : enroll_surname,
        ENROLL_PIN : enroll_pin,
        VERIFY_PIN : verify_pin,
        DEBIT : debit,
        CREDIT : credit,
        BALANCE : balance,
        EXCHANGE : exchange,
        TEST : test,
}
def main():
    print(HELP)
    session = user_apps()
    exit = False

    while exit != True:
        cmd = int(input("Select cmd:"))
        if cmd == EXIT:
            session.close()
            exit = True
        else:
            exit = options[cmd](session)
        print()


if __name__ == "__main__":
   main()

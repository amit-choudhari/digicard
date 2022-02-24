from smartcard.System import readers
r=readers()
connection=r[0].createConnection()
connection.connect()
#Selection AID
data, sw1, sw2 = connection.transmit([0x00,0xA4,0x04,0x00,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x07])

# Start enrolment
print("=====================")
print("Enrolment phase")
#1. send name
print("Set name")
data, sw1, sw2 = connection.transmit([0xB0,0x01,0x00,0x00,0x04,0x41, 0x6D, 0x69, 0x74])
mess1 = ''
for e in data:
    mess1 += chr(e)

print(mess1)

#2. send prenom
#print("Set prename")
data, sw1, sw2 = connection.transmit([0xB0,0x02,0x00,0x00,0x09,0x43, 0x68, 0x6F, 0x75, 0x64, 0x68, 0x61, 0x72, 0x69])
mess1 = ''
for e in data:
    mess1 += chr(e)

print(mess1)

#2. send PIN
print("Set PIN")
data, sw1, sw2 = connection.transmit([0xB0,0x03,0x00,0x00,0x06,0x1,0x2,0x3,0x4,0x5,0x6])
mess1 = ''
for e in data:
    mess1 += chr(e)

print(mess1)

print("Enrolment complete!")
print("=====================")
print ("")

print("=====================")
print ("USE CARD")
# enter correct pin
print("Enter PIN")
data, sw1, sw2 = connection.transmit([0xB0,0x10,0x00,0x00,0x06,0x1,0x2,0x3,0x4,0x5,0x6])
mess1 = ''
for e in data:
    mess1 += chr(e)

print(mess1)

# enter incorrect pin
#data, sw1, sw2 = connection.transmit([0xB0,0x10,0x00,0x00,0x06,0x1,0x2,0x3,0x4,0x5,0x7])
#mess1 = ''
#for e in data:
#    mess1 += chr(e)
#
#print(mess1)

# get balance
print("Get Balance")
data, sw1, sw2 = connection.transmit([0xB0,0x41,0x00,0x00,0x01,0x00])
print(data)

# credit amount
print("Credit 100Euro")
data, sw1, sw2 = connection.transmit([0xB0,0x30,0x00,0x00,0x01,0x64])
mess1 = ''
for e in data:
    mess1 += chr(e)

print(mess1)

print("Get Balance")
data, sw1, sw2 = connection.transmit([0xB0,0x41,0x00,0x00,0x01,0x00])
print(data)

# debit amount
print("Debit 15Euro")
data, sw1, sw2 = connection.transmit([0xB0,0x20,0x00,0x00,0x01,0x0F])
mess1 = ''
for e in data:
    mess1 += chr(e)

print(mess1)

print("Get Balance")
data, sw1, sw2 = connection.transmit([0xB0,0x41,0x00,0x00,0x01,0x00])
print(data)

#Disconnect the reader
connection.disconnect()


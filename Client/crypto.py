import inspect
from secrets import *
import array
from control import Control
from time import sleep

from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString, PACK, toBytes,HexListToBinString, BinStringToHexList
from Crypto.Cipher import DES3
from Crypto.Cipher import DES

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
INS_AUTH_INIT = 0x50
INS_AUTH_FINI = 0x51
INS_GET_BAL = 0x41;
                    
master_key = [0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0x00,0x01]

class Crypto:
    def __init__(self, cipher, key = 0):
        self.key = key
        self.type = cipher
        pass

    def gencipher(self):
        key_ = bytearray(self.key)
        self.zdes = DES.new(key_, DES.MODE_ECB)
        pass

    def encrypt(self, data):
        data_ = bytearray(data)
        cipherText = self.zdes.encrypt(data_)
        return cipherText

    def decrypt():
        pass

    def gen_mac(self):
        pass

class secure_channel:
    def __init__ (self, card):
        self.card = card
        pass

    def open(self):
        # generate host challenge
        chal_h = list(token_bytes(4))
        out = self.card.send([INS_AUTH_INIT], chal_h, [len(chal_h)])
        chal_hc = out[:len(chal_h)*2]
        print(chal_hc)

        # generate session Keys
        self.cipher_des = Crypto('DES', master_key)
        self.cipher_des.gencipher()
        self.sessionKey = self.cipher_des.encrypt(chal_hc)
        print(list(self.sessionKey))
        print(out[len(chal_h)*2:])
        self.cipher_session = Crypto('DES', self.sessionKey)
        pass

    def close(self):
        pass

    def gen_signature(self):
        pass

    def send(self, card):
        print(inspect.stack()[0].function)
        amt = []
        print(amt)
        ins = [INS_GET_BAL]
        data = amt
        size = [len(amt)]
        amt = card.send(ins, data, size)
        print("Balance: ",amt)
        print("-------")
        return amt
        pass

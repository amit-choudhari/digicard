import inspect
from secrets import *
import array
from control import Control
from time import sleep

from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString, PACK, toBytes,HexListToBinString, BinStringToHexList
from Crypto.Cipher import DES3
from Crypto.Cipher import DES
import hashlib
#from des import DesKey

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
INS_VERIFY_PIN = 0x10

hashLen = 24 
master_key = [0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0x00,0x01,
        0xAA,0xAD,0xBE,0xEF,0xCA,0xFE,0x00,0x02,
        0xBB,0xAD,0xBE,0xEF,0xCA,0xFE,0x00,0x03]

class Crypto:
    def __init__(self, cipher, key = 0):
        self.key = key
        self.type = cipher
        pass

    def gencipher(self):
        key_ = bytearray(self.key)
        self.zdes = DES3.new(key_, DES.MODE_ECB)
        pass

    def encrypt(self, data):
        if len(data) < len(self.key):
            pad = [0x0] * (len(self.key) - len(data))
            #print(pad)
            data += pad
        data_ = bytearray(data)
        cipherText = self.zdes.encrypt(data_)
        return cipherText

    def decrypt(self, data):
        data_ = bytearray(data)
        text = self.zdes.decrypt(data_)
        return text
        pass

    def gen_mac(self):
        pass

class secure_channel:
    def __init__ (self, card):
        self.card = card
        pass

    def open(self):
        # generate host challenge
        chal_h = list(token_bytes(12))
        out = self.card.send([INS_AUTH_INIT], chal_h, [len(chal_h)])
        chal_hc = out[:len(chal_h)*2]
        #print("[host|challenge]:",chal_hc)

        # generate session Keys
        self.cipher_des = Crypto('DES', master_key)
        self.cipher_des.gencipher()
        self.sessionKey = self.cipher_des.encrypt(chal_hc)
        #print("S_Key: ",list(self.sessionKey))
        #print(out[len(chal_h)*2:])
        self.cipher_session = Crypto('DES', self.sessionKey)
        self.cipher_session.gencipher()
        pass

    def close(self):
        pass

    def gen_signature(self, data):
        #print(data)
        h = hashlib.sha1(bytearray(data)).digest()
        #print("hash",list(h))
        h = array.array('B',h).tolist()
        return self.cipher_session.encrypt(h)

    def check_signature(self, data):
        h1 = self.cipher_session.decrypt(data[len(data)-hashLen:])
        #h1 = hashlib.sha1(Htxt).digest()
        h2 = hashlib.sha1(bytearray(data[:len(data)-hashLen])).digest()
        #print(list(h1)[:20])
        #print(list(h2))
        if(list(h1)[:20] == list(h2)):
            return True
        else:
            return False

    def send(self, card, ins, data, size):
        #print(inspect.stack()[0].function)
        c = self.cipher_session.encrypt(data)
        #print("Encrypted data:",c)
        #print(c)
        data = array.array('B',c).tolist()
        #tmp = self.cipher_session.decrypt(data)
        #txt = array.array('B',tmp).tolist()
        #print(txt)
        #return
        size = [len(data)]
        payload = data
        sign = self.gen_signature(payload)
        #print("MAC:",sign)
        data = data + array.array('B',sign).tolist()

        #print("Send...")
        resp = card.send(ins, data, size)
        #print(len(resp))
        #print(resp)
        #print("response...")
        #return
        if (self.check_signature(resp)):
            print("Integrity check passed.. decrypting")
        else:
            print("Integrity check failed")
            return False

        txt = self.cipher_session.decrypt(resp[:len(resp)-hashLen])
        txt = array.array('B',txt).tolist()
        while txt[-1] == 0:
            txt.pop(-1)

        return txt

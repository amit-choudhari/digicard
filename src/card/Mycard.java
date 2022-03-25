package card;

import javacard.framework.APDU;
import javacard.framework.*;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.security.DESKey;
import javacard.security.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javacard.security.MessageDigest;

public class Mycard extends Applet {

    /* Constants */
    // CLA
    public static final byte CLA_MONAPPLET = (byte) 0xB0;

    // INS
    public static final byte INS_MASK = 0x70;
    public static final byte INS_ENROLL_MASK = 0x00;
    public static final byte INS_ENROLL_name = 0x01;
    public static final byte INS_ENROLL_surname = 0x02;
    public static final byte INS_ENROLL_PIN = 0x03;
    public static final byte INS_ENROLL_UID = 0x04;

    public static final byte INS_ENTER_PIN = 0x10;
    public static final byte INS_DEBIT = 0x20;
    public static final byte INS_CREDIT = 0x30;

    public static final byte INS_GET_MASK = 0x40;
    public static final byte INS_GET_BAL = 0x41;
    public static final byte INS_GET_INFO = 0x42;
    
    public static final byte INS_AUTH_MASK = 0x50;
    public static final byte INS_AUTH_INIT = 0x50;
    public static final byte INS_AUTH_FINI = 0x51;

    public static final byte INS_RESET = 0x70;
    
    // Valid State
    public static final byte STATE_RESET = 0x00;
    public static final byte STATE_ENROLL = 0x01;
    public static final byte STATE_USE = 0x02;
    public static final byte STATE_INVALID = 0x7F;
    
    // MAX values
    private static final byte MAX_PIN_RETRY = 5;
    private static final byte PIN_SIZE = 6;
    final static short MAC_LENGTH = (short) 8;
    
    // Exceptions
    final static short SW_INVALID_TRANSACTION = 0x6A83;
    final static short SW_CIPHER_DATA_LENGTH_BAD = 0x6710;
    public static final short ERROR_VERIFICATION_FAILED=(short)0x9102;

    // Messages
    private static final byte[] MESS_1 = {'H','e','l','l','o',' ','m','y',' ','n','a','m','e',' ','i','s',' ','A','m','i','t'};
    private static final byte[] PIN_SUCCESS = {'c','o','d','e',' ','b','o','n','!'};
    private static final byte[] PIN_FAIL = {'c','o','d','e',' ','p','a',' ','b','o','n'};
    private static final byte[] CARD_BLOCK = {'B','L','O','C','K','E','D'};
    private static final byte[] key = {'B','L','O','C','K','E','D'};
    
    // Variable declaration
    OwnerPIN pin = null;
    //byte[] name;
    private static byte[] name = {};
    private static byte[] surname = {};
    private static short balance = 0;
    private static byte[] uniqueID = {};
    // state machine for the card
    // RESET->ENROLL->USE{credit<->debit}->RESET
    private static byte state;
    private RandomData random;
    private byte[] cardChallenge;
    private byte[] hostChallenge;
    private Signature signature;
    final static short CHALLENGE_LENGTH = (short) 12;
    final static short UID_LENGTH = (short) 8;
    /**
     * Unique ID
     */
    private byte[] uid = {0x01,0x02,0x03,0x04,0x01,0x02,0x03,0x04};

    private Cipher m_cipher;
    private DESKey staticKey;
    final static short LENGTH_DES_BYTE = (short) (KeyBuilder.LENGTH_DES / 8);
    private byte[] keyDerivationData; // Transient
    private byte[] sessionKeyData; // Transient
    private byte[] m_hash;
    private DESKey sessionKey; // Transient key
    private MessageDigest m_messagedigest;
    byte[] staticKeyData = {(byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF, (byte)0xCA, (byte)0xFE, (byte)0x00, (byte)0x01,
                         (byte)0xAA, (byte)0xAD, (byte)0xBE, (byte)0xEF, (byte)0xCA, (byte)0xFE, (byte)0x00, (byte)0x02, 
                         (byte)0xBB, (byte)0xAD, (byte)0xBE, (byte)0xEF, (byte)0xCA, (byte)0xFE, (byte)0x00, (byte)0x03};



    /* Constructor */
    private Mycard() {
        // Create and initialize the ramdom data generator with the UID (seed)
        random = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        random.setSeed(uid, (short) 0, UID_LENGTH);
        
        // Create challenge transient buffer
        cardChallenge = JCSystem.makeTransientByteArray(CHALLENGE_LENGTH,
                JCSystem.CLEAR_ON_DESELECT);
        hostChallenge = JCSystem.makeTransientByteArray(CHALLENGE_LENGTH,
                JCSystem.CLEAR_ON_DESELECT);
        keyDerivationData = JCSystem.makeTransientByteArray(
                (short) (2 * CHALLENGE_LENGTH), JCSystem.CLEAR_ON_DESELECT);
        sessionKeyData = JCSystem.makeTransientByteArray(
	            (short) (2 * keyDerivationData.length),
	            JCSystem.CLEAR_ON_DESELECT);

        signature = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_M1, false);

        state = STATE_ENROLL;
	    register(); //Mandatory to register 
    }

    private byte[] generateHash(byte[] buffer, short dataLen) {
        m_hash = new byte[20];
        MessageDigest m_sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        m_sha1.reset();
        m_sha1.doFinal(buffer, (short) 0, dataLen, m_hash, (short) 0);
        return m_hash;
    }

    private boolean checkHash(byte[] data, byte[] hash, APDU apdu) {
        byte[] h1;
        byte[] h2 = new byte[20];
        byte[] temp;

        h1 = generateHash(data, (short)data.length);
		byte[] buffer = apdu.getBuffer(); //To parse the apdu

        decrypt(hash);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, h2, (short) 0, (short)20);
        if(Util.arrayCompare(h1, (short) 0, h2, (short) 0, (short) 20) == (byte)0) {
            return true;
        }else {
            return false;
        }
    }

    // Encrypt outgoing data
    private short encrypt(byte[] data) {
        short dataLen = (short)data.length;
        m_ramArray = new byte[100];

        m_cipher.init(sessionKey, Cipher.MODE_ENCRYPT);
        //byte[] data = {'A','M','I','T','4','3','2','1'};
        //if ((dataLen % 8) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        // ENCRYPT INCOMING BUFFER
        return m_cipher.doFinal(data, (short) 0, dataLen, m_ramArray, (short) 0);
    }

    // Decrypt incoming data
    private short decrypt(byte[] data) {
        short dataLen = (short)data.length;
        m_ramArray = new byte[100];

        m_cipher.init(sessionKey, Cipher.MODE_DECRYPT);
        return m_cipher.doFinal(data, (short) 0, dataLen, m_ramArray, (short) 0);
    }

    
    //----------------------
    // Helper Functions
    //----------------------

    //Enrollment Funtions
    private byte[] setname(byte[] buffer, short byteRead) {
		//byte[] buff = apdu.getBuffer(); //To parse the apdu
        name = new byte[byteRead];
        //read name
	    Util.arrayCopy(buffer, (short)0, name, (short)0, byteRead);
        
        return name;
    }

    private byte[] setsurname(byte[] buffer, short byteRead) {
        surname = new byte[byteRead];
        //read name
	    Util.arrayCopy(buffer, (short)0, surname, (short)0, byteRead);
        return surname;
    }

    private byte[] setPIN(byte[] buffer, short byteRead) {
		//byte[] buf = apdu.getBuffer(); //To parse the apdu
        pin = new OwnerPIN(MAX_PIN_RETRY, PIN_SIZE);
        byte[] arr = {(byte)byteRead};

        if (PIN_SIZE != byteRead)
           ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // The installation parameters contain the PIN
        // initialization value
        pin.update(buffer, (short)0, (byte)byteRead);
        return arr;
    }

    private byte[] setUID(byte[] buffer, short byteRead) {
        uniqueID = new byte[byteRead];
	    Util.arrayCopy(buffer, (short)0, uniqueID, (short)0, byteRead);
        return uniqueID;
    }

    private void enroll(APDU apdu) {
        if (state != STATE_ENROLL)
            return;

		byte[] buffer = apdu.getBuffer(); //To parse the apdu
        byte[] data = {};

        byte[] hash= new byte[24];
        short dataLen = 0;
        short hashLen = 0;
        boolean res = false;
        byte byteRead = buffer[ISO7816.OFFSET_LC];
        byte[] msg = {};
        byte[] temp= new byte[byteRead];

        Util.arrayCopyNonAtomic(buffer, (short) ISO7816.OFFSET_CDATA, temp, (short) 0, (short)(byteRead));
        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA+byteRead), hash, (short) 0, (short)24);
        res = checkHash(temp, hash, apdu);

        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA), temp, (short) 0, byteRead);
        dataLen = decrypt(temp);
        while (m_ramArray[(short)(dataLen-1)] == 0) {
            dataLen = (short)(dataLen - (short)1);
        }

        /*byte byteRead =
            (byte)(apdu.setIncomingAndReceive());
        if (numBytes != byteRead)
           ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
         */

		switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_ENROLL_name: 
                data = setname(m_ramArray, dataLen);
                break;
            case INS_ENROLL_surname: 
                data = setsurname(m_ramArray, dataLen);
                break;
            case INS_ENROLL_PIN: 
                data = setPIN(m_ramArray, dataLen);
                break;
            case INS_ENROLL_UID: 
                data = setUID(m_ramArray, dataLen);
                break;
        }
        if (name.length > 0 && surname.length > 0 && pin != null && uniqueID.length > 0)
            state = STATE_USE;
        dataLen = encrypt(data);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, (short) 0, dataLen);
        hash = generateHash(buffer,dataLen);
        hashLen = encrypt(hash);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, dataLen, hashLen);
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+hashLen));
    }

    /* Credit Funtions */
    // Credit INS_CREDIT = 0x30
    private void credit(APDU apdu) {
        //TODO check state
        
		byte[] buffer = apdu.getBuffer(); //To parse the apdu
        byte[] hash= new byte[24];
        short dataLen = 0;
        short hashLen = 0;
        boolean res = false;
        byte byteRead = buffer[ISO7816.OFFSET_LC];
        byte[] msg = {};
        byte[] temp= new byte[byteRead];

        Util.arrayCopyNonAtomic(buffer, (short) ISO7816.OFFSET_CDATA, temp, (short) 0, (short)(byteRead));
        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA+byteRead), hash, (short) 0, (short)24);
        res = checkHash(temp, hash, apdu);

        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA), temp, (short) 0, byteRead);
        dataLen = decrypt(temp);
        while (m_ramArray[(short)(dataLen-1)] == 0) {
            dataLen = (short)(dataLen - (short)1);
        }

        // check pin verified
        if (!pin.isValidated())
            ISOException.throwIt(SW_INVALID_TRANSACTION);

        byte creditamt = m_ramArray[0];
        // TODO add checks on valid credits
        balance = (short)(balance + creditamt);
        byte[] arr = {creditamt};

        dataLen = encrypt(arr);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, (short) 0, dataLen);
        hash = generateHash(buffer,dataLen);
        hashLen = encrypt(hash);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, dataLen, hashLen);
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+hashLen));
    }

    /* Debit Funtions */
    // Debit INS_DEBIT = 0x20
    private void debit(APDU apdu) {
        //TODO check state

		byte[] buffer = apdu.getBuffer(); //To parse the apdu
        byte[] hash= new byte[24];
        short dataLen = 0;
        short hashLen = 0;
        boolean res = false;
        byte byteRead = buffer[ISO7816.OFFSET_LC];
        byte[] msg = {};
        byte[] temp= new byte[byteRead];

        Util.arrayCopyNonAtomic(buffer, (short) ISO7816.OFFSET_CDATA, temp, (short) 0, (short)(byteRead));
        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA+byteRead), hash, (short) 0, (short)24);
        res = checkHash(temp, hash, apdu);

        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA), temp, (short) 0, byteRead);
        dataLen = decrypt(temp);
        while (m_ramArray[(short)(dataLen-1)] == 0) {
            dataLen = (short)(dataLen - (short)1);
        }

        // check pin verified
        if (!pin.isValidated())
            ISOException.throwIt(SW_INVALID_TRANSACTION);

        byte debitamt = m_ramArray[0];
        // TODO add checks on valid credits
        if ((short)(balance&0xff) < (short)(debitamt&0xff))
            ISOException.throwIt(SW_INVALID_TRANSACTION);
        balance = (short)(balance - debitamt);
        byte[] arr = {debitamt};

        dataLen = encrypt(arr);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, (short) 0, dataLen);
        hash = generateHash(buffer,dataLen);
        hashLen = encrypt(hash);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, dataLen, hashLen);
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+hashLen));
    }

    // Validate PIN
    private void enterpin(APDU apdu) {
        byte[] hash= new byte[24];
		byte[] buffer = apdu.getBuffer(); //To parse the apdu
        short dataLen = 0;
        short hashLen = 0;
        boolean res = false;
        byte byteRead = buffer[ISO7816.OFFSET_LC];
        byte[] msg = {};
        byte[] temp= new byte[byteRead];

        Util.arrayCopyNonAtomic(buffer, (short) ISO7816.OFFSET_CDATA, temp, (short) 0, (short)(byteRead));
        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA+byteRead), hash, (short) 0, (short)24);
        res = checkHash(temp, hash, apdu);

        Util.arrayCopyNonAtomic(buffer, (short) (ISO7816.OFFSET_CDATA), temp, (short) 0, byteRead);
        dataLen = decrypt(temp);
        while (m_ramArray[(short)(dataLen-1)] == 0) {
            dataLen = (short)(dataLen - (short)1);
        }
        if (res == true) {
            if ((pin.check(m_ramArray,(short)0, (byte)dataLen) == false)) {
                msg = PIN_FAIL;
            } else {
                msg = PIN_SUCCESS;
	            //Util.arrayCopyNonAtomic(PIN_SUCCESS, (short)0, buffer, (short)0, (short)PIN_SUCCESS.length);
            }
        } else {
                msg = PIN_FAIL;
        }
        dataLen = encrypt(msg);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, (short) 0, dataLen);
        hash = generateHash(buffer,dataLen);
        hashLen = encrypt(hash);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, dataLen, hashLen);
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+hashLen));
    }

    /* Get Information Functions */
    // Get balance INS_GET_BAL = 0x41
    private void getbalance(APDU apdu) {
        //byte[] hash= new byte[20];

        byte[] temp= new byte[2];
		byte[] buffer = apdu.getBuffer(); //To parse the apdu
        byte[] hash= new byte[24];
        short dataLen = 0;
        short hashLen = 0;
        boolean res = false;
        byte byteRead = buffer[ISO7816.OFFSET_LC];
        byte[] msg = {};

        // check pin verified
        if (!pin.isValidated())
            ISOException.throwIt(SW_INVALID_TRANSACTION);

        Util.setShort(temp, (short) 0, balance);

        dataLen = encrypt(temp);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, (short) 0, dataLen);
        hash = generateHash(buffer,dataLen);
        hashLen = encrypt(hash);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, dataLen, hashLen);
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+hashLen));
    }
    
    private void getinfo(APDU apdu) {
		byte[] buffer = apdu.getBuffer(); //To parse the apdu
        short offset = 0;
        byte[] nextline = {0x0A};
        byte[] temp;
        byte[] hash= new byte[24];
        short dataLen = 0;
        short hashLen = 0;
        boolean res = false;
        byte byteRead = buffer[ISO7816.OFFSET_LC];
        byte[] msg = {};

	    Util.arrayCopyNonAtomic(uniqueID, (short)0, buffer, offset, (short)uniqueID.length);
        offset += uniqueID.length;
	    Util.arrayCopyNonAtomic(nextline, (short)0, buffer, offset, (short)nextline.length);
        offset += nextline.length;

	    Util.arrayCopyNonAtomic(name, (short)0, buffer, offset, (short)name.length);
        offset += name.length;
	    Util.arrayCopyNonAtomic(nextline, (short)0, buffer, offset, (short)nextline.length);
        offset += nextline.length;

	    Util.arrayCopyNonAtomic(surname, (short)0, buffer, offset, (short)surname.length);
        offset += surname.length;
	    Util.arrayCopyNonAtomic(nextline, (short)0, buffer, offset, (short)nextline.length);
        offset += nextline.length;

        temp= new byte[offset];
	    Util.arrayCopyNonAtomic(buffer, (short)0, temp, (short)0, offset);
        //apdu.setOutgoingAndSend((short)0, (short)(offset));
        dataLen = encrypt(temp);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, (short) 0, dataLen);
        hash = generateHash(buffer,dataLen);
        hashLen = encrypt(hash);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, buffer, dataLen, hashLen);
        apdu.setOutgoingAndSend((short)0, (short)(dataLen+hashLen));
    }

    private void get(APDU apdu) {
		byte[] buffer = apdu.getBuffer(); //To parse the apdu

		switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_GET_BAL: 
                getbalance(apdu);
                break;
            case INS_GET_INFO: 
                getinfo(apdu);
                break;
        }
    }

    private void generate_symm_key() {
        staticKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
        sessionKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
        // Static key
        staticKey.setKey(staticKeyData, (short)0);
        //encrypt dummy data
        m_cipher = Cipher.getInstance(Cipher.ALG_DES_ECB_ISO9797_M1, false);
    }

    private void generate_sessionKey() {
        m_cipher.init(staticKey, Cipher.MODE_ENCRYPT);
        // CHECK EXPECTED LENGTH (MULTIPLY OF 64 bites)
        //if ((dataLen % 8) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        m_cipher.doFinal(keyDerivationData, (short) 0, (short) keyDerivationData.length,
                sessionKeyData, (short) 0);
        // Generate new session key from encrypted derivation data
        sessionKey.setKey(sessionKeyData, (short) 0);
    }

    private void auth_init(APDU apdu, byte[] buffer, short byteRead) {
		byte[] buf = apdu.getBuffer(); //To parse the apdu
        short signLen = 0;

        //read host challenge
	    Util.arrayCopy(buf, (short)ISO7816.OFFSET_CDATA, hostChallenge, (short)0, byteRead);
        random.generateData(cardChallenge, (short) 0, CHALLENGE_LENGTH);
        
        // copy card challenge and host challenge [host 8bytes | card 8bytes]
	    Util.arrayCopyNonAtomic(hostChallenge, (short)0, keyDerivationData, (short)0, CHALLENGE_LENGTH);
        Util.arrayCopyNonAtomic(cardChallenge, (short) 0, keyDerivationData, CHALLENGE_LENGTH, CHALLENGE_LENGTH);
        Util.arrayCopyNonAtomic(keyDerivationData, (short) 0, buf, (short) 0, (short)(CHALLENGE_LENGTH*2));
        
        // generate static key
        generate_symm_key();

        // generate session keys KDF
        generate_sessionKey();
        //generateHash(apdu, arr);
        //Util.arrayCopyNonAtomic(sessionKeyData, (short) 0, buf, (short)(CHALLENGE_LENGTH*2), (short)(CHALLENGE_LENGTH*2));
        
        // generate MAC
        //signLen = generateMAC(buf,(short)(CHALLENGE_LENGTH*2));
        apdu.setOutgoingAndSend((short)0, (short)(CHALLENGE_LENGTH*2));
    }

    private void auth_fini(APDU apdu, byte[] buffer, short byteRead) {

    }

    private void auth(APDU apdu) {
        //TODO check state

		byte[] buffer = apdu.getBuffer(); //To parse the apdu

        byte numBytes = buffer[ISO7816.OFFSET_LC];

        /*byte byteRead =
            (byte)(apdu.setIncomingAndReceive());
        if (numBytes != byteRead)
           ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
         */

		switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_AUTH_INIT: 
                auth_init(apdu, buffer, numBytes);
                break;
            case INS_AUTH_FINI: 
                auth_fini(apdu, buffer, numBytes);
                break;
        }
        // TODO change state

    }
    
    private void reset(APDU apdu) {

    }

    private void generate_keyderivationdata() {

    }




    private RSAPrivateKey m_privateKey;
    private RSAPublicKey m_publicKey;
    private KeyPair m_keyPair;
    private Signature m_sign;
    private short m_signLen;
        //--RSA Keypair data
    private static final byte[] RSA_PUB_KEY_EXP = {(byte)0x01, (byte)0x00, (byte)0x01};
    private static final byte[] RSA_PUB_PRIV_KEY_MOD = { (byte)0xbe, (byte)0xdf,
        (byte)0xd3, (byte)0x7a, (byte)0x08, (byte)0xe2, (byte)0x9a, (byte)0x58,
        (byte)0x27, (byte)0x54, (byte)0x2a, (byte)0x49, (byte)0x18, (byte)0xce,
        (byte)0xe4, (byte)0x1a, (byte)0x60, (byte)0xdc, (byte)0x62, (byte)0x75,
        (byte)0xbd, (byte)0xb0, (byte)0x8d, (byte)0x15, (byte)0xa3, (byte)0x65,
        (byte)0xe6, (byte)0x7b, (byte)0xa9, (byte)0xdc, (byte)0x09, (byte)0x11,
        (byte)0x5f, (byte)0x9f, (byte)0xbf, (byte)0x29, (byte)0xe6, (byte)0xc2,
        (byte)0x82, (byte)0xc8, (byte)0x35, (byte)0x6b, (byte)0x0f, (byte)0x10,
        (byte)0x9b, (byte)0x19, (byte)0x62, (byte)0xfd, (byte)0xbd, (byte)0x96,
        (byte)0x49, (byte)0x21, (byte)0xe4, (byte)0x22, (byte)0x08, (byte)0x08,
        (byte)0x80, (byte)0x6c, (byte)0xd1, (byte)0xde, (byte)0xa6, (byte)0xd3,
        (byte)0xc3, (byte)0x8f};

    private static final byte[] RSA_PRIV_KEY_EXP = { (byte)0x84, (byte)0x21,
        (byte)0xfe, (byte)0x0b, (byte)0xa4, (byte)0xca, (byte)0xf9, (byte)0x7d,
        (byte)0xbc, (byte)0xfc, (byte)0x0e, (byte)0xa9, (byte)0xbb, (byte)0x7a,
        (byte)0xbd, (byte)0x7d, (byte)0x65, (byte)0x40, (byte)0x2b, (byte)0x08,
        (byte)0xc6, (byte)0xdf, (byte)0xc9, (byte)0x4b, (byte)0x09, (byte)0x6a,
        (byte)0x29, (byte)0x3b, (byte)0xc2, (byte)0x42, (byte)0x88, (byte)0x23,
        (byte)0x44, (byte)0xaf, (byte)0x08, (byte)0x82, (byte)0x4c, (byte)0xff,
        (byte)0x42, (byte)0xa4, (byte)0xb8, (byte)0xd2, (byte)0xda, (byte)0xcc,
        (byte)0xee, (byte)0xc5, (byte)0x34, (byte)0xed, (byte)0x71, (byte)0x01,
        (byte)0xab, (byte)0x3b, (byte)0x76, (byte)0xde, (byte)0x6c, (byte)0xa2,
        (byte)0xcb, (byte)0x7c, (byte)0x38, (byte)0xb6, (byte)0x9a, (byte)0x4b,
        (byte)0x28, (byte)0x01};

    private byte[] m_ramArray;


    private void generate_asymm_key(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        // CREATE RSA KEYS AND PAIR
        try {
            m_publicKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_512,false);
            m_privateKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,KeyBuilder.LENGTH_RSA_512,false);
            m_privateKey.setExponent(RSA_PRIV_KEY_EXP,(short)0,(short)RSA_PRIV_KEY_EXP.length);
            m_privateKey.setModulus(RSA_PUB_PRIV_KEY_MOD,(short)0,(short)RSA_PUB_PRIV_KEY_MOD.length);
            m_publicKey.setExponent(RSA_PUB_KEY_EXP,(short)0,(short)RSA_PUB_KEY_EXP.length);
            m_publicKey.setModulus(RSA_PUB_PRIV_KEY_MOD,(short)0,(short)RSA_PUB_PRIV_KEY_MOD.length);

            //m_keyPair = new KeyPair(KeyPair.ALG_RSA, (short)KeyBuilder.LENGTH_RSA_512);
            //m_keyPair = new KeyPair(m_publicKey, m_privateKey);
            // STARTS ON-CARD KEY GENERATION PROCESS
            //m_keyPair.genKeyPair();
            // CREATE SIGNATURE OBJECT
            m_sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            
        } catch (CryptoException e) {
            short reason = e.getReason();
            byte[] arr = {(byte)reason};
	        Util.arrayCopyNonAtomic(arr,
                                    (short)0,
                                    apdubuf,
                                    (short)0,
                                    (short)1);
         
            apdu.setOutgoingAndSend((short)0, (short)1);
            ISOException.throwIt((short) ((short) 0x6B00 | reason));
         }
    }

    void sign(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
            byte[] data = {'A','M','I','T','4','3','2','1'};
            short dataLen = (short)data.length;
            // INIT WITH PRIVATE KEY
            m_sign.init(m_privateKey, Signature.MODE_SIGN);
            // SIGN INCOMING BUFFER
            m_signLen = m_sign.sign(data, (byte) 0, (byte) dataLen, apdubuf, (byte) 0);
            apdu.setOutgoingAndSend((short)0, m_sign.getLength());

    }

    void verify(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
            byte[] data = {'A','M','I','T','4','3','2','1'};
            short dataLen = (short)data.length;
            m_sign.init(m_publicKey,Signature.MODE_VERIFY);
            boolean verified=false;
            verified = m_sign.verify(data, (short) 0, dataLen, apdubuf,(short)0,m_signLen);
            //In either case m1 is consumed by this applet
            if(!verified){
                ISOException.throwIt(ERROR_VERIFICATION_FAILED);
            }

    }


    private void initialize_session(APDU apdu) {

		//byte[] buf = apdu.getBuffer(); //To parse the apdu

        // Create cipher
        generate_symm_key();
        generate_asymm_key(apdu);
        sign(apdu);

        //staticKey.getKey(buf, (short) 0);
	    //Util.arrayCopyNonAtomic(buffer, (short)0, buf, (short)0, (short)LENGTH_DES_BYTE);
        //encrypt(apdu);
        apdu.setOutgoingAndSend((short)0, LENGTH_DES_BYTE);

        // generate challenge
        
        // generate Keyderivation
        
        // generate session key

        // append card challenge
        
        // append status word
        
        // sign response 
    }

    // ---------------------------------
    // Mandatory functions for Java card
    // ---------------------------------
    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
	    new Mycard();
    }

    public boolean select() {
        // Block the applet.
        //if ( pin.getTriesRemaining() == 0 )
        //   return false;

        return true;

    }

    public void deselect() {
        // reset the pin value
        pin.reset();

    }

    public void process(APDU apdu) throws ISOException {
        //If you are selecting this applet. 
		if (this.selectingApplet()) return; 
    
		byte[] buffer = apdu.getBuffer();
        
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		switch (buffer[ISO7816.OFFSET_INS] & INS_MASK) {
            case INS_AUTH_MASK: 
                auth(apdu);
                break;
            case INS_ENROLL_MASK: 
                enroll(apdu);
            break;
            case INS_DEBIT: 
                debit(apdu);
            break;
            case INS_CREDIT: 
                credit(apdu);
            break;
            case INS_ENTER_PIN:
                enterpin(apdu);
            break;
            case INS_GET_MASK:
                get(apdu);
            break;
            case INS_RESET:
                reset(apdu);
            break;
		    default:
		        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
    }

}

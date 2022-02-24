package card;

import javacard.framework.APDU;
import javacard.framework.*;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.JCSystem;

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

    public static final byte INS_ENTER_PIN = 0x10;
    public static final byte INS_DEBIT = 0x20;
    public static final byte INS_CREDIT = 0x30;

    public static final byte INS_GET_MASK = 0x40;
    public static final byte INS_GET_BAL = 0x41;
    public static final byte INS_RESET = 0x70;
    
    // Valid State
    public static final byte STATE_RESET = 0x00;
    public static final byte STATE_ENROLL = 0x01;
    public static final byte STATE_USE = 0x02;
    public static final byte STATE_INVALID = 0x7F;
    
    // MAX values
    private static final byte MAX_PIN_RETRY = 5;
    private static final byte PIN_SIZE = 6;
    
    // Exceptions
    final static short SW_INVALID_TRANSACTION = 0x6A83;

    // Messages
    private static final byte[] MESS_1 = {'H','e','l','l','o',' ','m','y',' ','n','a','m','e',' ','i','s',' ','L','e','o','n'};
    private static final byte[] PIN_SUCCESS = {'c','o','d','e',' ','b','o','n','!'};
    private static final byte[] PIN_FAIL = {'c','o','d','e',' ','p','a',' ','b','o','n'};
    private static final byte[] CARD_BLOCK = {'B','L','O','C','K','E','D'};
    
    // Variable declaration
    OwnerPIN pin;
    //byte[] name;
    private static byte[] name;
    private static byte[] surname;
    private static short balance = 0;
    private static short uniqueID;
    // state machine for the card
    // RESET->ENROLL->USE{credit<->debit}->RESET
    private static byte state;


    /* Constructor */
    private Mycard() {
	    register(); //Mandatory to register 
    }
    
    //----------------------
    // Helper Functions
    //----------------------

    //Enrollment Funtions
    private void setname(APDU apdu, byte[] buffer, short byteRead) {

        name = new byte[byteRead];
        //read name
	    Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, name, (short)0, byteRead);
        
        apdu.setOutgoing();
        apdu.setOutgoingLength(byteRead);
		byte[] buff = apdu.getBuffer(); //To parse the apdu

        // send the buffer back
	    Util.arrayCopyNonAtomic(name,
                                    (short)0,
                                    buffer,
                                    (short)0,
                                    (short)name.length);

	    apdu.sendBytes((short)0, (short)(name.length));
    }

    private void setsurname(APDU apdu, byte[] buffer, short byteRead) {
        surname = new byte[byteRead];
        //read name
	    Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, surname, (short)0, byteRead);
        
        apdu.setOutgoing();
        apdu.setOutgoingLength(byteRead);
		byte[] buff = apdu.getBuffer(); //To parse the apdu

        // send the buffer back
	    Util.arrayCopyNonAtomic(surname,
                                    (short)0,
                                    buffer,
                                    (short)0,
                                    (short)surname.length);

	    apdu.sendBytes((short)0, (short)(surname.length));
    }

    private void setPIN(APDU apdu, byte[] buffer, short byteRead) {
        pin = new OwnerPIN(MAX_PIN_RETRY, PIN_SIZE);

        if (PIN_SIZE != byteRead)
           ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // The installation parameters contain the PIN
        // initialization value
        pin.update(buffer, (short)(ISO7816.OFFSET_CDATA), (byte)byteRead);

    }

    private void enroll(APDU apdu) {
        //TODO check state

		byte[] buffer = apdu.getBuffer(); //To parse the apdu

        byte numBytes = buffer[ISO7816.OFFSET_LC];

        /*byte byteRead =
            (byte)(apdu.setIncomingAndReceive());
        if (numBytes != byteRead)
           ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
         */

		switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_ENROLL_name: 
                setname(apdu, buffer, numBytes);
                break;
            case INS_ENROLL_surname: 
                setsurname(apdu, buffer, numBytes);
                break;
            case INS_ENROLL_PIN: 
                setPIN(apdu, buffer, numBytes);
                break;
        }
        // TODO change state

    }

    /* Credit Funtions */
    // Credit INS_CREDIT = 0x30
    private void credit(APDU apdu) {
        //TODO check state

		byte[] buffer = apdu.getBuffer(); //To parse the apdu
        byte byteRead = buffer[ISO7816.OFFSET_LC];

        // check pin verified
        if (!pin.isValidated())
            ISOException.throwIt(SW_INVALID_TRANSACTION);

        byte creditamt = buffer[ISO7816.OFFSET_CDATA];
        // TODO add checks on valid credits
        balance = (short)(balance + creditamt);
    }

    /* Debit Funtions */
    // Debit INS_DEBIT = 0x20
    private void debit(APDU apdu) {
        //TODO check state

		byte[] buffer = apdu.getBuffer(); //To parse the apdu
        byte byteRead = buffer[ISO7816.OFFSET_LC];

        // check pin verified
        if (!pin.isValidated())
            ISOException.throwIt(SW_INVALID_TRANSACTION);

        byte debitamt = buffer[ISO7816.OFFSET_CDATA];
        // TODO add checks on valid credits
        balance = (short)(balance - debitamt);

    }

    // Validate PIN
    private void enterpin(APDU apdu) {
		byte[] buffer = apdu.getBuffer(); //To parse the apdu

        byte byteRead = buffer[ISO7816.OFFSET_LC];

        if (pin.check(buffer,(short)(ISO7816.OFFSET_CDATA), byteRead) == false) {
	        Util.arrayCopyNonAtomic(PIN_FAIL,
                                        (short)0,
                                        buffer,
                                        (short)0,
                                        (short)PIN_FAIL.length);
            apdu.setOutgoingAndSend((short)0, (short)PIN_FAIL.length);
        } else {
	        Util.arrayCopyNonAtomic(PIN_SUCCESS,
                                        (short)0,
                                        buffer,
                                        (short)0,
                                        (short)PIN_SUCCESS.length);
            apdu.setOutgoingAndSend((short)0, (short)PIN_SUCCESS.length);
        }
    }

    /* Get Information Functions */
    // Get balance INS_GET_BAL = 0x41
    private void getbalance(APDU apdu) {
        // check state

		byte[] buffer = apdu.getBuffer(); //To parse the apdu
        byte byteRead = buffer[ISO7816.OFFSET_LC];

        // check pin verified
        //if (!pin.isValidated())
        //    ISOException.throwIt(SW_INVALID_TRANSACTION);

        //apdu.setOutgoing();
        //apdu.setOutgoingLength((short)PIN_SUCCESS.length);
        buffer[0] = (byte)(balance >> 8);
        buffer[1] = (byte)(balance & 0xFF);
	    /*Util.arrayCopyNonAtomic(PIN_SUCCESS,
                                    (short)0,
                                    buffer,
                                    (short)0,
                                    (short)PIN_SUCCESS.length);
         */
        apdu.setOutgoingAndSend((short)0, (short)2);


    }
    
    private void reset(APDU apdu) {

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
                getbalance(apdu);
            break;
            case INS_RESET:
                reset(apdu);
            break;
		    default:
		        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
    }

}

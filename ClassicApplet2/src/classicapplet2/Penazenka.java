/*
 * https://www.programcreek.com/java-api-examples/?api=javacard.framework.OwnerPIN
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package classicapplet2;

import javacard.framework.*;

/**
 *
 * @author marti
 */
public class Penazenka extends Applet {
    
    // CLA Byte variables
    public final static byte PENAZENKA_CLA = (byte)0x80;   
    
    // INS Byte variables
    public final static byte RETURN_NAME = (byte)0x00;
    public final static byte ACCEPT = (byte)0x01;   
    public final static byte SEND_BACK = (byte)0x02;
    public final static byte VERIFY = (byte) 0x20;
    
    // ERROR codes
    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    
    // signal the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    
    // OTHER global variables
    protected byte [] arr;
    protected byte length_arr;
    
    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT =(byte)0x03;
  
    // maximum size PIN
    final static byte MAX_PIN_SIZE =(byte)0x08;
    
    /* instance variables declaration */
    OwnerPIN pin;
      
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // Vytvori instanciu Penazenky
        new Penazenka(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected Penazenka(byte[] bArray, short bOffset, byte bLength) {
        arr = new byte [(short) 20];
        length_arr = 0;
        
        // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
   
        // The installation parameters contain the PIN
        // initialization
        pin.update(bArray, bOffset, bLength);
        register();
    }
    
    // caled by JCRE to indicate, that this applet was selected
    public boolean select() {
        // The applet declines to be selected
        // if the pin is blocked.
        if ( pin.getTriesRemaining() == 0 ) return false;
        return true;
    }// end of select method
    
    // clean up method called by JCRE called before applet is deselected
    public void deselect() {
        // reset the pin value
        pin.reset();
    }
    
    private void return_name(APDU apdu){
        byte[] name = { 'M', 'a', 'r', 't', 'i', 'n' };
        
        short bytesLeft = (byte) apdu.setOutgoing();
                
        // osetrit, pokial Le by bol kratsi ako dialka mena 6xx - xx spravna dialka
        if ( name.length != bytesLeft ){
            ISOException.throwIt( (short)(0x6C00 + (short) name.length) );
        } 
                
        apdu.setOutgoingLength((short) name.length);               
        apdu.sendBytesLong(name, (short) 0, (short) name.length); 
    }
    
    private void accept(APDU apdu){
        // returns true if the PIN was successfully checked in this session
        if ( ! pin.isValidated()){
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        
        byte[] buffer = apdu.getBuffer();        
        // Lc tells us the incoming apdu command length
        short bytesLeft1 = (short) (buffer[ISO7816.OFFSET_LC]);              
               
        if (bytesLeft1 > (short)20) {
            ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
        }else {
            length_arr = (byte) apdu.setIncomingAndReceive();
            Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, arr, (short)0, length_arr);
        }
    }
    
    private void send_back(APDU apdu){
        // returns true if the PIN was successfully checked in this session
        if ( ! pin.isValidated()){
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        
        byte length_t = (byte) apdu.setOutgoing();
                
        // Handle wrong expected length
        if (length_t != length_arr){
            ISOException.throwIt( (short)(0x6C00 + (short) length_arr) );          
        } else {
            apdu.setOutgoingLength(length_arr);
        }
               
        apdu.sendBytesLong(arr, (short)0, length_arr);   
    }
    
    private void verify(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        
        // retrieve the PIN data for validation.
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        
        if ( pin.check(buffer, ISO7816.OFFSET_CDATA,byteRead) == false || 
                pin.getTriesRemaining() <= 0 ){
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    public void process(APDU apdu) {
        byte []buffer = apdu.getBuffer();
        byte numBytes = buffer[ISO7816.OFFSET_LC];
        
        // 0X9000 status
        if(selectingApplet()){
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
        
        // Handle incorrect value of CLA
        if(buffer[ISO7816.OFFSET_CLA] != PENAZENKA_CLA){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
              
        switch(buffer[ISO7816.OFFSET_INS]){
            
            // INS=0x00 returns your name encoded in ASCII
            case RETURN_NAME: return_name(apdu);                
                return;
            
            // INS=0x01 accepts data, 20 bytes maximum
            case ACCEPT: accept(apdu);              
                return;
                
            // INS=0x02 sends back data received using 0x01, at most as many bytes, as are expected (Le), and as were received previously
            case SEND_BACK: send_back(apdu);                         
                return;
                
            case VERIFY: verify(apdu);
                return;
            
            // Handle an incorrect value of INS    
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}

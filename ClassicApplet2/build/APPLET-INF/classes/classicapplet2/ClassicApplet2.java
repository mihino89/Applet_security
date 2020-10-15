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
public class ClassicApplet2 extends Applet {
    
    public final static byte APPLET2_CLA = (byte)0x80;
    public final static byte RETURN_NAME_INC = (byte)0x00;
    public final static byte ACCEPT_INC = (byte)0x01;   
    public final static byte SEND_BACK_INC = (byte)0x02;
    byte [] arr;
    byte length_arr;
    
    // maximum balance
    final static short MAX_BALANCE = 0x14;

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
        new ClassicApplet2();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected ClassicApplet2() {
        register();
        arr = new byte [(short) 20];
        length_arr = 0;
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
        if(buffer[ISO7816.OFFSET_CLA] != APPLET2_CLA){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
              
        switch(buffer[ISO7816.OFFSET_INS]){
            
            // INS=0x00 returns your name encoded in ASCII
            case RETURN_NAME_INC:
                byte[] name = { 'M', 'a', 'r', 't', 'i', 'n' };
                short bytesLeft = (byte) apdu.setOutgoing();
                
                // osetrit, pokial Le by bol kratsi ako dialka mena 6xx - xx spravna dialka
                if ( name.length != bytesLeft ){
                    ISOException.throwIt( (short)(0x6C00 + (short) name.length) );
                } 
                
                apdu.setOutgoingLength((short) name.length);               
                apdu.sendBytesLong(name, (short) 0, (short) name.length); 
                
                break;
            
            // INS=0x01 accepts data, 20 bytes maximum
            case ACCEPT_INC:                
                // Lc tells us the incoming apdu command length
                short bytesLeft1 = (short) (buffer[ISO7816.OFFSET_LC]);              
               
                if (bytesLeft1 > (short)20) {
                    ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
                }else {
                    length_arr = (byte) apdu.setIncomingAndReceive();
                    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, arr, (short)0, length_arr);
                }   
                
                break;
                
            // INS=0x02 sends back data received using 0x01, at most as many bytes, as are expected (Le), and as were received previously
            case SEND_BACK_INC:
                byte length_t = (byte) apdu.setOutgoing();
                
                // Handle INS=0x02 with wrong expected length
                if (length_t != length_arr){
                    // osetrit, pokial Le by bol kratsi ako dialka mena 6xx - xx spravna dialka
                    ISOException.throwIt( (short)(0x6C00 + (short) length_arr) );          
                } else {
                    apdu.setOutgoingLength(length_arr);
                }
               
                apdu.sendBytesLong(arr, (short)0, length_arr);                                
                break;
            
            // Handle an incorrect value of INS    
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}

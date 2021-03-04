/*
 * https://www.programcreek.com/java-api-examples/?api=javacard.framework.OwnerPIN
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package classicapplet2;

import javacard.framework.*;
import javacard.security.MessageDigest;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

/**
 *
 * @author marti
 */
public class Penazenka extends Applet {
    
//  **************      Constantes      **************
    // CLA Byte variables
    public final static byte PENAZENKA_CLA = (byte)0x80;    
    // INS Byte variables
    public final static byte RETURN_NAME = (byte)0x00;
    public final static byte ACCEPT = (byte)0x01;   
    public final static byte SEND_BACK = (byte)0x02;
    public final static byte VERIFY_PIN = (byte) 0x20;
    public final static byte HASH_DATA = (byte) 0x30;
    public final static byte RETURN_HASH = (byte) 0x32;
    public final static byte SIGN_DATA = (byte) 0x40;
    private final static byte GEN_RSA = (byte) 0x41;     
    public final static byte VERIFY_SIGN = (byte) 0x42;
    
//  **************      Error Constantes      **************
    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;   
    // signal the PIN validation is required for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    // maximum number of incorrect tries before the
    final static byte PIN_TRY_LIMIT =(byte)0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE =(byte)0x04;
    // Podpis nebyl uspesne overen
    public static final short ERROR_VERIFICATION_FAILED = (short) 0x9102;
    // Chybna delka podpisu
    public static final short ERROR_BAD_SIG_LEN = (short) 0x9101;
    
//  **************      Variables      **************
    protected final static byte[] name = { 'M', 'a', 'r', 't', 'i', 'n' };
    public final static short SIG_LENGTH=64;
    protected byte [] arr;
    protected byte length_arr;
    
    private OwnerPIN pin;
    private MessageDigest md;
    private byte [] hash;
    private byte[] tmpMessage;
    private static KeyPair card_KeyPair;
    private static RSAPublicKey card_PublicKey;
    private static RSAPrivateKey card_PrivateKey;
    private static Signature signature;
    
    // byty verejneho exponentu
    private final byte[] RSA_PUBLIC_KEY_EXPONENT = {(byte) 0x01, (byte) 0x00, (byte) 0x01};
    // byty soukromeho exponentu
    private static final byte[] RSA_PRIVATE_KEY_EXPONENT = {(byte) 0x84, (byte) 0x21,
        (byte) 0xfe, (byte) 0x0b, (byte) 0xa4, (byte) 0xca, (byte) 0xf9, (byte) 0x7d,
        (byte) 0xbc, (byte) 0xfc, (byte) 0x0e, (byte) 0xa9, (byte) 0xbb, (byte) 0x7a,
        (byte) 0xbd, (byte) 0x7d, (byte) 0x65, (byte) 0x40, (byte) 0x2b, (byte) 0x08,
        (byte) 0xc6, (byte) 0xdf, (byte) 0xc9, (byte) 0x4b, (byte) 0x09, (byte) 0x6a,
        (byte) 0x29, (byte) 0x3b, (byte) 0xc2, (byte) 0x42, (byte) 0x88, (byte) 0x23,
        (byte) 0x44, (byte) 0xaf, (byte) 0x08, (byte) 0x82, (byte) 0x4c, (byte) 0xff,
        (byte) 0x42, (byte) 0xa4, (byte) 0xb8, (byte) 0xd2, (byte) 0xda, (byte) 0xcc,
        (byte) 0xee, (byte) 0xc5, (byte) 0x34, (byte) 0xed, (byte) 0x71, (byte) 0x01,
        (byte) 0xab, (byte) 0x3b, (byte) 0x76, (byte) 0xde, (byte) 0x6c, (byte) 0xa2,
        (byte) 0xcb, (byte) 0x7c, (byte) 0x38, (byte) 0xb6, (byte) 0x9a, (byte) 0x4b,
        (byte) 0x28, (byte) 0x01
    };
    //byty modulu
    private final byte[] RSA_KEY_MODULUS = {(byte) 0xbe, (byte) 0xdf,
        (byte) 0xd3, (byte) 0x7a, (byte) 0x08, (byte) 0xe2, (byte) 0x9a, (byte) 0x58,
        (byte) 0x27, (byte) 0x54, (byte) 0x2a, (byte) 0x49, (byte) 0x18, (byte) 0xce,
        (byte) 0xe4, (byte) 0x1a, (byte) 0x60, (byte) 0xdc, (byte) 0x62, (byte) 0x75,
        (byte) 0xbd, (byte) 0xb0, (byte) 0x8d, (byte) 0x15, (byte) 0xa3, (byte) 0x65,
        (byte) 0xe6, (byte) 0x7b, (byte) 0xa9, (byte) 0xdc, (byte) 0x09, (byte) 0x11,
        (byte) 0x5f, (byte) 0x9f, (byte) 0xbf, (byte) 0x29, (byte) 0xe6, (byte) 0xc2,
        (byte) 0x82, (byte) 0xc8, (byte) 0x35, (byte) 0x6b, (byte) 0x0f, (byte) 0x10,
        (byte) 0x9b, (byte) 0x19, (byte) 0x62, (byte) 0xfd, (byte) 0xbd, (byte) 0x96,
        (byte) 0x49, (byte) 0x21, (byte) 0xe4, (byte) 0x22, (byte) 0x08, (byte) 0x08,
        (byte) 0x80, (byte) 0x6c, (byte) 0xd1, (byte) 0xde, (byte) 0xa6, (byte) 0xd3,
        (byte) 0xc3, (byte) 0x8f
    };
    
      
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
    public Penazenka(byte[] bArray, short bOffset, byte bLength) {
        arr = new byte [(short) 20];
        length_arr = 0;       
        
        //  instance AID 
        short ilen = bArray[bOffset];
        bOffset += ilen + 1;
        
        //  control info 
        short clen = bArray[bOffset];
        bOffset += clen + 1;
        
        //  applet data 
        short alen = bArray[bOffset];
        
        if (alen > (short) 4) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
        
        // The installation parameters contain the PIN - initialization
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        pin.update(bArray, (short) (bOffset + 1), (byte) alen);
 
        hash = JCSystem.makeTransientByteArray( MessageDigest.LENGTH_SHA, JCSystem.CLEAR_ON_RESET );
        md = MessageDigest.getInstance( MessageDigest.ALG_SHA, false);
        
        card_PrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        card_PublicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, true);
        
        card_PrivateKey.setExponent(RSA_PRIVATE_KEY_EXPONENT,(short)0,(short)RSA_PRIVATE_KEY_EXPONENT.length);
        card_PrivateKey.setModulus(RSA_KEY_MODULUS,(short)0,(short)RSA_KEY_MODULUS.length);
        
        card_PublicKey.setExponent(RSA_PUBLIC_KEY_EXPONENT,(short)0,(short)RSA_PUBLIC_KEY_EXPONENT.length);
        card_PublicKey.setModulus(RSA_KEY_MODULUS,(short)0,(short)RSA_KEY_MODULUS.length);
        
        card_KeyPair = new KeyPair(KeyPair.ALG_RSA, card_PublicKey.getSize());
        tmpMessage = JCSystem.makeTransientByteArray((short)(128),JCSystem.CLEAR_ON_DESELECT);
        
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1 ,false);
   
        register();
    }
        
    private void return_name(APDU apdu){       
        short bytesLeft = (byte) apdu.setOutgoing();
                
        // osetrit, pokial Le by bol kratsi ako dialka mena 6xx - xx spravna dialka
        if ( name.length != bytesLeft ){
            ISOException.throwIt( (short)(0x6C00 + (short) name.length) );
        } 
                
        apdu.setOutgoingLength((short) name.length);               
        apdu.sendBytesLong(name, (short) 0, (short) name.length); 
    }
    
    private void accept(APDU apdu){        
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
//        if ( ! pin.isValidated()){
//            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
//        }
        
        byte length_t = (byte) apdu.setOutgoing();
                
        // Handle wrong expected length
        if (length_t != length_arr){
            ISOException.throwIt( (short)(0x6C00 + (short) length_arr) );          
        } else {
            apdu.setOutgoingLength(length_arr);
        }
               
        apdu.sendBytesLong(arr, (short)0, length_arr);   
    }
    
    private void verify_pin(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        
        // retrieve the PIN data for validation.
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        
        if ( pin.check(buffer, ISO7816.OFFSET_CDATA,byteRead) == false || 
                pin.getTriesRemaining() <= 0 ){
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    }
    
    private void hash_data(APDU apdu){
        byte []buffer = apdu.getBuffer();
        short tmpMessageLength, dlzka_hashu;
        
        tmpMessageLength = (byte) apdu.setIncomingAndReceive();     
        
        if (tmpMessageLength > (short)128) {
            ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
        }

        md.reset();
        dlzka_hashu = md.doFinal( buffer, ISO7816.OFFSET_CDATA, (short) tmpMessageLength, hash, (short) 0);
        
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) dlzka_hashu);
        apdu.sendBytesLong(hash, (short) 0, (short) dlzka_hashu);
    }
    
    private void return_hash(APDU apdu){        
        byte []buffer = apdu.getBuffer();
        short bytesToSend, dlzka_hashu;
        bytesToSend = (byte) apdu.setOutgoing();

        md.reset();
        dlzka_hashu = md.doFinal( name, (short) 0, (short) name.length, hash, (short) 0);
        
        if( dlzka_hashu != bytesToSend ){
            ISOException.throwIt( (short)(0x6C00 + (short) name.length) );
        }
        
        apdu.setOutgoingLength((short) dlzka_hashu);
        apdu.sendBytesLong(hash, (short) 0, (short) dlzka_hashu);
    }
    
    private void sign_data(APDU apdu){
        if ( ! pin.isValidated()){
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        
        byte[] buffer = apdu.getBuffer();
        short tmpMessageLength, signLen, bytesLeft1;
        tmpMessageLength = (byte) apdu.setIncomingAndReceive();           
               
        if (tmpMessageLength > (short)128) {
            ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
        }
        
        signature.init(card_PrivateKey, Signature.MODE_SIGN);
        signLen = signature.sign(buffer, (short) ISO7816.OFFSET_CDATA, (short) tmpMessageLength, tmpMessage, (short) 0);
        
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) signLen);
        apdu.sendBytesLong(tmpMessage, (short) 0, (short) signLen);
    }
    
    private void verify_signature(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        
        // retrieve the PIN data for validation.
        byte bytesRead = (byte)(apdu.setIncomingAndReceive());
        short dlzka_spravy = buffer[ISO7816.OFFSET_CDATA];
        
        if((bytesRead - dlzka_spravy) - 1 != SIG_LENGTH){
            ISOException.throwIt(ERROR_BAD_SIG_LEN);
        }
                
        signature.init(card_PublicKey, Signature.MODE_VERIFY);
        if(!signature.verify(buffer,(short)(ISO7816.OFFSET_CDATA+1), dlzka_spravy, buffer, (short)(ISO7816.OFFSET_CDATA+1+dlzka_spravy),SIG_LENGTH)){
            ISOException.throwIt(ERROR_VERIFICATION_FAILED);
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
            if ( pin.getTriesRemaining() == 0 ){
                ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
            }
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }
        
        // Handle incorrect value of CLA
        if(buffer[ISO7816.OFFSET_CLA] != PENAZENKA_CLA){
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
              
        switch(buffer[ISO7816.OFFSET_INS]){
            
            case RETURN_NAME: return_name(apdu);                
                return;
            
            case ACCEPT: accept(apdu);              
                return;
                
            case SEND_BACK: send_back(apdu);                         
                return;
                
            case VERIFY_PIN: verify_pin(apdu);
                return;
               
            case HASH_DATA: hash_data(apdu);
                return;
                
            case RETURN_HASH: return_hash(apdu);
                return;
                
            case SIGN_DATA: sign_data(apdu);
                return;
            
            case VERIFY_SIGN: verify_signature(apdu);
                return;
            
            // Handle an incorrect value of INS    
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}

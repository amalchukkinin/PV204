package applets;

import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import simpleapdu.CardMngr;


import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;

;

public class SimpleApplet extends javacard.framework.Applet {

    
    byte[] myG= new byte[255]; 
    private byte[] tempBuffer;
    //byte[] arrayforG;
    private byte[] flags;
    private static final short FLAGS_SIZE = (short)5;
    private byte[] arrayforG = new byte[49];
    private byte[] arrayforA = new byte[24];
    private byte[] arrayforB = new byte[24];
    private short eccKeyLen;
    private Signature ecdsa;
    private KeyPair eccKey;
    ECKey keyforus;
    ECPublicKey pubkeyC;
    ECPrivateKey privKeyC;
    
    //pin
    private byte PIN[] = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};
    private byte dummy[] = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};
    //random number
    private byte x[] =new byte[16];
    // MAIN INSTRUCTION CLASS

    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_ENCRYPT = (byte) 0x50;
    final static byte INS_DECRYPT = (byte) 0x51;
    final static byte INS_SETKEY = (byte) 0x52;
    final static byte INS_HASH = (byte) 0x53;
    final static byte INS_RANDOM = (byte) 0x54;
    final static byte INS_VERIFYPIN = (byte) 0x55;
    final static byte INS_SETPIN = (byte) 0x56;
    final static byte INS_RETURNDATA = (byte) 0x57;
    final static byte INS_SIGNDATA = (byte) 0x58;

    final static short ARRAY_LENGTH = (short) 0xff;
    final static byte AES_BLOCK_LENGTH = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE = (short) 0x6711;
    final static short SW_BAD_PIN = (short) 0x6900;

    final static short SW_Exception = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException = (short) 0xff03;
    final static short SW_ArrayStoreException = (short) 0xff04;
    final static short SW_NullPointerException = (short) 0xff05;
    final static short SW_NegativeArraySizeException = (short) 0xff06;
    final static short SW_CryptoException_prefix = (short) 0xf100;
    final static short SW_SystemException_prefix = (short) 0xf200;
    final static short SW_PINException_prefix = (short) 0xf300;
    final static short SW_TransactionException_prefix = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix = (short) 0xf500;

    private AESKey m_aesKey = null;
    private Cipher m_encryptCipher = null;
    private Cipher m_decryptCipher = null;
    private RandomData m_secureRandom = null;
    private MessageDigest m_hash = null;
    private OwnerPIN m_pin = null;
    private Signature m_sign = null;
    private KeyPair m_keyPair = null;
    private Key m_privateKey = null;
    private Key m_publicKey = null;

    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte m_dataArray[] = null;

    /**
     * SimpleApplet default constructor Only this class's install method should
     * create the applet object.
     */
    protected SimpleApplet(byte[] buffer, short offset, byte length) {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if (length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]
            // shift to privilege offset
            dataOffset += (short) (1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short) (1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

            // CREATE RANDOM DATA GENERATORS
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            // SET KEY VALUE
            m_aesKey.setKey(m_dataArray, (short) 0);

            // INIT CIPHERS WITH NEW KEY
            m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);

            m_pin = new OwnerPIN((byte) 5, (byte) 4); // 5 tries, 4 digits in pin
            m_pin.update(PIN, (byte) 0, (byte) 4); // set  pin
            //printing PIN
            

           

            // CREATE RSA KEYS AND PAIR 
            m_keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
            m_keyPair.genKeyPair(); // Generate fresh key pair on-card
            m_publicKey = m_keyPair.getPublic();
            m_privateKey = m_keyPair.getPrivate();
            // SIGNATURE ENGINE    
            m_sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            // INIT WITH PRIVATE KEY
            m_sign.init(m_privateKey, Signature.MODE_SIGN);

            // INIT HASH ENGINE
            m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

            // update flag
            isOP2 = true;

        } 

        // register this instance
        register();
    }

    /**
     * Method installing the applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // applet  instance creation 
        new SimpleApplet(bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     *
     * @return boolean status of selection.
     */
    public boolean select() {
        clearSessionData();
        
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect() {
        clearSessionData();
    }

    
    
    
     private void GenEccKeyPair(APDU apdu, short len) throws NoSuchAlgorithmException
    {
        byte[] buffer = apdu.getBuffer();
        
        short keyLen = (short)0;
        byte[] apdubuf = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_P1])
        {
        case (byte)0x01: // 192
            //Constructs a KeyPair instance for the specified algorithm and keylength;
            eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
            keyLen = (short)24;
            //System.out.println("Hai i am applet");  
            break;
        case (byte)0x02:
            //Here, the KeyBuilder.LENGTH_EC_FP_256 only be used in JavaCard API 3.0.4
            eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
            keyLen = (short)32;
            break;
        case (byte)0x03: // 384
            //Here, the KeyBuilder.LENGTH_EC_FP_384 only be used in JavaCard API 3.0.4
            eccKey = new KeyPair(KeyPair.ALG_EC_FP,KeyBuilder.LENGTH_EC_FP_384); 
            keyLen = (short)48;
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            break;
        }
        //(Re)Initializes the key objects encapsulated in this 'eccKey' KeyPair instance with new key values.
        /*
        eccKey.genKeyPair();
        keyforus=(ECKey)eccKey.getPublic();
        keyforus.getG(arrayforG, len);
        System.out.println("The G is");
        System.out.println(Arrays.toString(arrayforG));
        eccKeyLen = keyLen;
        */
        //System.out.println("Enterd the ecc function in BOB");
        eccKey.genKeyPair();

        pubkeyC=(ECPublicKey)(ECKey)eccKey.getPublic();
        privKeyC= (ECPrivateKey)eccKey.getPrivate();
        privKeyC.getG(arrayforG,(short) 0);
        privKeyC.getA(arrayforA, (short)0);
        privKeyC.getB(arrayforB, (short)0);
        //TODO
        //BOB TO ALICE- xG + wM;
        
        //CALCULATES SECRET= x(S-wN)
        
        //Generating random number 'x'
        int prime=1500450271;
         //byte[] prime= {(byte) 0x31, (byte) 0x35, (byte) 0x30, (byte) 0x30,(byte) 0x34, (byte) 0x35,(byte) 0x30, (byte) 0x32,(byte) 0x37,
         //(byte) 0x31};
         SecureRandom secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG");
     
        // Get 128 random bytes
        byte[] randomBytes = new byte[10];
        int i=0;
        secureRandomGenerator.nextBytes(randomBytes);
        

        ByteBuffer wrapped = ByteBuffer.wrap(randomBytes); // big-endian by default
        int x = wrapped.getInt();
        while(i<1){
        if(x<prime){
        i=1;    
        }
        else{
        secureRandomGenerator.nextBytes(randomBytes);
        ByteBuffer wrappd = ByteBuffer.wrap(randomBytes); // big-endian by default
        x = wrappd.getShort();
        }
        }
        //System.out.println("\nTHE RANDOM NUMBER GEN IN BOB/APPLET IS " +x);
        
        
        ByteBuffer wrappdG = ByteBuffer.wrap(arrayforG); // big-endian by default
        int G = wrappdG.getInt();

        //System.out.println("\nTHE G IN APPLET/BOB IS " +G);
       
        
        
       //multiplication x * G

        int xG = x*G;

        
        
        //System.out.println("\nTHE VALUE OF xG CALCULATED IN BOB/APPLET IS " +xG);  
        
     
        
        // xG + wM = next step
        //wM calc, M used is in arrayforA and w is the pin 
        
        //System.out.println("\nTHE VALUE OF PIN AS STORED IN  BOB/APPLET IS ");  
         
        
        ByteBuffer wrappdpin = ByteBuffer.wrap(PIN); // big-endian by default
        int w = wrappdpin.getInt();
      
        ByteBuffer wrappdA = ByteBuffer.wrap(arrayforA); // big-endian by default
        int M = wrappdA.getInt();
        
        int wM= w*M;
        
        //System.out.println("checkk1");  

         
        
        //System.out.println("\nTHE VALUE OF wM IN  BOB/APPLET IS " +wM);  
        
     
        //final step T =X +wM
        
        int Tint = xG+wM;
        
        //T IS READY TO BE SENT
        //System.out.println("\nTHE T IS READY TO BE SENT FROM BOB " +Tint);  
        
        byte Tarray[]= ByteBuffer.allocate(4).putInt(Tint).array();
        
        
        //System.out.println("\nTHE LENGTH OF T IS "+Tarray.length);
        
        //System.out.println("\nPRINTING THE T IN BYTE ARRAY :");  
        
        for (byte b : Tarray) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        
        
        short SfromALiceLen = apdubuf[ISO7816.OFFSET_LC];
        byte[] SfromAlice = new byte[SfromALiceLen];
        //copy random number to counter
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, SfromAlice, (short) 0, SfromALiceLen);

        
        
        
        //printing check
        ByteBuffer wrappedSfromAlice = ByteBuffer.wrap(SfromAlice); // big-endian by default
        int S = wrappedSfromAlice.getInt();
      
        //System.out.println("\n PRINTING THE S THAT CAME FROM ALICE IN APDU :" +S);  

 
         // COPY T INTO OUTGOING BUFFER
        //Util.arrayCopyNonAtomic(Tarray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA,(short)5);
        //System.arraycopy(Tarray, (short)0, apdubuf, ISO7816.OFFSET_CDATA,(short)5);
        Util.arrayCopyNonAtomic(Tarray, (short)0,apdubuf,ISO7816.OFFSET_CDATA, SfromALiceLen);

                 
        
        // SEND OUTGOING BUFFER
        
        //System.out.println("\n  CHECK FOR T IN BOb");
       
        for (byte b : Tarray) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, SfromALiceLen);
        
        
        
        //CALCULATING THE SHARED SECRET
        
        //x(S-wN)
        //step1= calculate wN
        
        ByteBuffer wrappdB = ByteBuffer.wrap(arrayforB); // big-endian by default
        int B = wrappdB.getInt();
        int wN= B*w;
        
        //System.out.println("checkk1");  

        
        //System.out.println("\nCALCULATED wN IN THE APPLET/BOB is  :" +wN);  
        
       
        //nextstep = (S-wN)
        int SsubwN= S- wN;       
        //System.out.println("\nCALCULATED S - wN IN THE APPLET/BOB is  :" +SsubwN);  
        
        
       
      
       //NEXT STEP= x(S-wN)
       
        int sharedsec= x *SsubwN;
        
        //System.out.println("checkk1");  

     
        System.out.println("\nSHARED SECRET IN BOB/APPLET is " +sharedsec);  
      
        System.out.println("\n\n\n");
        
        
        
        
        
    }
    
    
    
    
    
    
    
    /**
     * Method processing an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException {
        // get the buffer with incoming APDU
        byte[] apduBuffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        //System.out.println("the length is "+len);
        // ignore the applet select command dispached to the process
        
       
            
       
        try {
            
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
                
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_SETKEY:
                        SetKey(apdu);
                        break;
                    case INS_ENCRYPT:
                        Encrypt(apdu);
                        break;
                    case INS_DECRYPT:
                        Decrypt(apdu);
                        break;
                    case INS_HASH:
                        Hash(apdu);
                        break;
                    case INS_RANDOM:
                        GenEccKeyPair(apdu,len);
                        break;
                    case INS_VERIFYPIN:
                        VerifyPIN(apdu);
                        break;
                    case INS_SETPIN:
                        SetPIN(apdu);
                        break;
                    case INS_RETURNDATA:
                        ReturnData(apdu);
                        break;
                    case INS_SIGNDATA:
                        Sign(apdu);
                        break;
                    default:
                        // The INS code is not supported by the dispatcher
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }

            // Capture all reasonable exceptions and change into readable ones (instead of 0x6f00) 
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
    }

    void clearSessionData() {
        // E.g., fill sesssion data in RAM with zeroes
        Util.arrayFillNonAtomic(m_ramArray, (short) 0, (short) m_ramArray.length, (byte) 0);
        // Or better fill with random data
        m_secureRandom.generateData(m_ramArray, (short) 0, (short) m_ramArray.length);
    }
    
    // SET ENCRYPTION & DECRYPTION KEY
    void SetKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH
        if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_256) {
            ISOException.throwIt(SW_KEY_LENGTH_BAD);
        }

        // SET KEY VALUE
        m_aesKey.setKey(apdubuf, ISO7816.OFFSET_CDATA);

        // INIT CIPHERS WITH NEW KEY
        m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
        m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
    }

    // ENCRYPT INCOMING BUFFER
    void Encrypt(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER
        m_encryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
        // NOTE: In-place encryption directly with apdubuf as output can be performed. m_ramArray used to demonstrate Util.arrayCopyNonAtomic

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    // DECRYPT INCOMING BUFFER
    void Decrypt(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    // HASH INCOMING BUFFER
    void Hash(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (m_hash != null) {
            m_hash.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
        } else {
            ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);
        }

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_hash.getLength());

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, m_hash.getLength());
    }

    // GENERATE RANDOM DATA
    void Random(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        // GENERATE DATA
        short randomDataLen = apdubuf[ISO7816.OFFSET_P1];
        m_secureRandom.generateData(apdubuf, ISO7816.OFFSET_CDATA, randomDataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, randomDataLen);
    }

    // VERIFY PIN
    void VerifyPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // VERIFY PIN
        if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen) == false) {
            ISOException.throwIt(SW_BAD_PIN);
        }
    }

    // SET PIN 
    // Be aware - this method will allow attacker to set own PIN - need to protected. 
    // E.g., by additional Admin PIN or all secret data of previous user needs to be reased 
    void SetPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // SET NEW PIN
        m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
    }

    // RETURN INPU DATA UNCHANGED
    void ReturnData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    void Sign(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        short signLen = 0;

        // SIGN INCOMING BUFFER
        signLen = m_sign.sign(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen, m_ramArray, (byte) 0);

        // COPY SIGNED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, signLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, signLen);
    }
}

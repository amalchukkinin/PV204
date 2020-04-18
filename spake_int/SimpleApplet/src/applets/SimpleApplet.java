package applets;

import java.security.NoSuchAlgorithmException;
import javacard.framework.*;
import javacard.security.*;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyPair;
import opencrypto.jcmathlib.*;


import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;

;

public class SimpleApplet extends javacard.framework.Applet {

 
   
    private byte dataArray1[] = null;
    private byte dataArray2[] = null;

    ECConfig        ecc = null;
    ECCurve         curve = null;
    ECPoint         bigX = null;
    ECPoint         bigT = null;
    ECPoint         bigS = null;
    ECPoint         bobShared = null;
    KeyPair         kp = null;
    ECPrivateKey    privkey = null;
    ECPublicKey     pubkey = null;
    Bignat          smallx = null;
    Bignat          userpin = null;
    
    final static byte[] PIN_TEST = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34};
    final static byte[] N_COMPRESSED = {(byte) 0x03, (byte) 0xD8, (byte) 0xBB, (byte) 0xD6, (byte) 0xC6, (byte) 0x39, (byte) 0xC6, (byte) 0x29, (byte) 0x37, (byte) 0xB0, (byte) 0x4D, (byte) 0x99, (byte) 0x7F, (byte) 0x38, (byte) 0xC3, (byte) 0x77, (byte) 0x07, (byte) 0x19, (byte) 0xC6, (byte) 0x29, (byte) 0xD7, (byte) 0x01, (byte) 0x4D, (byte) 0x49, (byte) 0xA2, (byte) 0x4B, (byte) 0x4F, (byte) 0x98, (byte) 0xBA, (byte) 0xA1, (byte) 0x29, (byte) 0x2B, (byte) 0x49};
    final static byte[] M_COMPRESSED = {(byte) 0x02, (byte) 0x88, (byte) 0x6E, (byte) 0x2F, (byte) 0x97, (byte) 0xAC, (byte) 0xE4, (byte) 0x6E, (byte) 0x55, (byte) 0xBA, (byte) 0x9D, (byte) 0xD7, (byte) 0x24, (byte) 0x25, (byte) 0x79, (byte) 0xF2, (byte) 0x99, (byte) 0x3B, (byte) 0x64, (byte) 0xE1, (byte) 0x6E, (byte) 0xF3, (byte) 0xDC, (byte) 0xAB, (byte) 0x95, (byte) 0xAF, (byte) 0xD4, (byte) 0x97, (byte) 0x33, (byte) 0x3D, (byte) 0x8F, (byte) 0xA1, (byte) 0x2F};

   
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    
    final static byte INS_RANDOM = (byte) 0x54;
    
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

        dataArray1 = new byte[100];
        Util.arrayFillNonAtomic(dataArray1, (short) 0, (short) 100, (byte) 0);
        dataArray2 = new byte[100];
        Util.arrayFillNonAtomic(dataArray2, (short) 0, (short) 100, (byte) 0);
        // Pre-allocate all helper structures
        ecc = new ECConfig((short) 256); 
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        bigX = new ECPoint(curve, ecc.ech);
        bigT = new ECPoint(curve, ecc.ech);
        bigS = new ECPoint(curve, ecc.ech);
        bobShared = new ECPoint(curve, ecc.ech);
        kp = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
        kp.genKeyPair();
        privkey = (ECPrivateKey) kp.getPrivate();
        pubkey = (ECPublicKey) kp.getPublic();
        short smallxlen = privkey.getS(dataArray1, (short) 0);
        byte[] smallxdata = new byte[smallxlen];
        privkey.getS(smallxdata, (short) 0);
        smallx = new Bignat(smallxdata, ecc.bnh);
        userpin = new Bignat(PIN_TEST,ecc.bnh);
        
        
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
        
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect() {
    }

    
    
    
     private void GenEccKeyPair(APDU apdu, short len) throws NoSuchAlgorithmException
    {
        
        byte[] buffer = apdu.getBuffer();

        byte[] apdubuf = apdu.getBuffer();

        //TODO
        //BOB TO ALICE- xG + wM;
        
        //CALCULATES SECRET= x(S-wN)
        short dataLen = apdu.getIncomingLength(); 

        byte test[]=new byte[dataLen];

        System.arraycopy(apdubuf,ISO7816.OFFSET_CDATA,test,(short)0,dataLen);
        System.out.println("\nPRINTING THE S CAME FROM APDU/PC:");  
        
        for (byte b : test) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        
        
  
        bigS.setW(apdubuf,ISO7816.OFFSET_CDATA, dataLen); //S = S
        bobShared.setW(N_COMPRESSED, (short) 0, (short) N_COMPRESSED.length); //Shared = N
        short bobSharedLen = bobShared.multiplication_x(userpin, dataArray1, (short) 0); // wN stored into memory
        bobShared.setW(dataArray1, (short) 0, bobSharedLen); // Shared = wN
        bobShared.negate(); // Shared = -wN
        bobShared.add(bigS); // Shared = S - wN
        bobSharedLen = bobShared.multiplication_x(smallx, dataArray1, (short) 0); // Putting x*(S-wN) into memory
        bobShared.setW(dataArray1, (short) 0, bobSharedLen); // Shared = x*(S-wN) = x*y*G
        
        System.out.println("\nPRINTING THE SHARED SECRET IN CARD:");  
        
        for (byte b : dataArray1) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        System.out.println("\n");

        


        //CALCULATION OF T = wM + X
        bigT.setW(M_COMPRESSED, (short) 0, (short) M_COMPRESSED.length); //T = M

        short tlen = bigT.multiplication_x(userpin, dataArray2, (short)0);//userpin is Bignat Scalar, wM stored in "memory".
        bigT.setW(dataArray2, (short) 0, tlen); // T = wM

        short bigXlen = pubkey.getW(dataArray2, (short) 0); // getting X length and saving it to "memory" as raw bytes
        bigX.setW(dataArray2, (short) 0, bigXlen); // making X point
        bigT.add(bigX); //T = wM + X
        tlen = bigT.getW(dataArray2,(short) 0); //measuring length of T again and saving it to "memory"
        Util.arrayCopyNonAtomic(dataArray2, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, tlen); // copying to APDU
        System.out.println("\nPRINTING THE T IN CARD:");  
        System.out.println("THE tlen is "+tlen);
        byte test1[] =new byte[tlen];
        System.arraycopy(apdubuf, ISO7816.OFFSET_CDATA, test1,(short)0,tlen);
        for (byte b : test1) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        System.out.println("\n");
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, tlen); //sending T = wM + X
        
        
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
                    
                    case INS_RANDOM:
                        GenEccKeyPair(apdu,len);
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

        
}

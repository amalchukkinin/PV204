package applets;

import javacard.framework.*;
import javacard.security.*;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javacardx.crypto.Cipher;


;

public class SimpleApplet extends javacard.framework.Applet {
    private static boolean eccDone = false;
    private static boolean channelEstablished = false;
    private byte secret[] =null;
    
    
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    
    final static byte INS_ECC = (byte) 0x54;
    final static byte INS_DEC = (byte) 0x55;
    final static byte INS_COMMUNICATION  = (byte) 0x56;
    
    final BigInteger pinvalue;
    short pintries = 3;
    byte messeagecounter = (byte) 0x01;
    
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
    private MessageDigest m_hash = null;

    private Cipher m_encryptCipherCBC = null;
    private Cipher m_decryptCipherCBC = null;
    
    private RandomData m_secureRandom = null;
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

        // update flag
            isOP2 = true;

        } 

        // register this instance
        pinvalue = new BigInteger(buffer);
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
        eccDone = false;
        channelEstablished = false;
        m_aesKey = null;
        m_hash = null;
        m_encryptCipherCBC = null;
        m_decryptCipherCBC = null;
        m_secureRandom = null;
        secret = null;
        messeagecounter = (byte) 0x01;
        
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect() {
        eccDone = false;
        channelEstablished = false;
        m_aesKey = null;
        m_hash = null;
        m_encryptCipherCBC = null;
        m_decryptCipherCBC = null;
        m_secureRandom = null;
        messeagecounter = (byte) 0x01;
    }

    
    
    
     private void GenEccKeyPair(APDU apdu, short len) throws NoSuchAlgorithmException
    {
        pintries--;
        if (channelEstablished || pintries < 0)
            throw new SecurityException("Replay or other attack detected");
        byte[] buffer = apdu.getBuffer();

        byte[] apdubuf = apdu.getBuffer();

        //CALCULATES SECRET= x(S-wN)
        short dataLen = apdu.getIncomingLength(); 

        byte test[]=new byte[dataLen];

        System.arraycopy(apdubuf,ISO7816.OFFSET_CDATA,test,(short)0,dataLen);
  
        X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
        ECDomainParameters ecparams = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());
        final SecureRandom random = new SecureRandom();
        final ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(ecparams, random));
        AsymmetricCipherKeyPair alicePair = gen.generateKeyPair();
        ECPublicKeyParameters alicepublic = (ECPublicKeyParameters) alicePair.getPublic();
        ECPrivateKeyParameters aliceprivate = (ECPrivateKeyParameters) alicePair.getPrivate();
        ECPoint bigY = alicepublic.getQ();
        BigInteger smally = aliceprivate.getD();

        ECPoint bigN = ecparams.getCurve().decodePoint(Hex.decode("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"));
        ECPoint bigM = ecparams.getCurve().decodePoint(Hex.decode("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"));
       
        ECPoint bigT = ecparams.getCurve().decodePoint(test);

        ECPoint shared2 = bigT.subtract(bigM.multiply(pinvalue)).multiply(smally);
        
        secret = shared2.getEncoded(true);
        
        ECPoint bigS = bigN.multiply(pinvalue).add(bigY);
        byte[] tosend_S = bigS.getEncoded(true);
        
        System.arraycopy(tosend_S,(short)0,apdubuf,ISO7816.OFFSET_CDATA,tosend_S.length);
       eccDone = true;
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)tosend_S.length); //sending S
        
        
    }
    
    private void symmetric_enc(APDU apdu){
        if (!eccDone || channelEstablished)
            throw new SecurityException("Replay or other attack detected");
        byte[] apdubuf = apdu.getBuffer();
        
        short dataLen = apdu.getIncomingLength(); 

        byte cipher[]=new byte[dataLen];

        System.arraycopy(apdubuf,ISO7816.OFFSET_CDATA,cipher,(short)0,dataLen);
      
        
        //SET THE MD5(SHARED KEY) AS THE KEY FOR SYMMETRIC ENCRYPTION- AES
        m_hash = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
        byte[] digest=new byte[32];

        m_hash.doFinal(secret, (short)0, (short)secret.length, digest, (short) 0);

        m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        m_aesKey.setKey(digest, (short)0);
        
        //GET INSTANCE-DECRYPTION
        m_decryptCipherCBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        m_decryptCipherCBC.init(m_aesKey, Cipher.MODE_DECRYPT);
        
        //DECRYPTION
        byte [] dec_random= new byte[16];
        m_decryptCipherCBC.doFinal(cipher, (short) 0, (short) cipher.length, dec_random,(short)0);
      
        //REVERSE THE PLAINTEXT
        int i = 0;
        int j = dec_random.length - 1;
        byte tmp;
        while (j > i) {
          tmp = dec_random[j];
          dec_random[j] = dec_random[i];
          dec_random[i] = tmp;
          j--;
          i++;
        }
    
       //REVERSE ENCRYPTION
       m_encryptCipherCBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
       m_encryptCipherCBC.init(m_aesKey, Cipher.MODE_ENCRYPT);
        
       //ENCRYPTION
        byte [] reverse_enc= new byte[16];
        m_encryptCipherCBC.doFinal(dec_random, (short) 0, (short)dec_random.length, reverse_enc,(short)0);
     
        //SEND TO PC
        System.arraycopy(reverse_enc,(short)0,apdubuf,ISO7816.OFFSET_CDATA,reverse_enc.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)reverse_enc.length); 
        
    }
    
    private void secureCommunication(APDU apdu) {
      if (!eccDone || pintries < 0)
            throw new SecurityException("Replay or other attack detected");
      channelEstablished = true;
      byte[] apdubuf = apdu.getBuffer();
      short dataLen = apdu.getIncomingLength(); 
      // Decryption of arrived messeage
      byte cipher[]=new byte[dataLen];
      System.arraycopy(apdubuf,ISO7816.OFFSET_CDATA,cipher,(short)0,dataLen);
      byte [] dec_messeage= new byte[dataLen];
      m_decryptCipherCBC.doFinal(cipher, (short) 0, (short) cipher.length, dec_messeage,(short)0);
      //verify integrity by checking if first 32 bytes include MD5 hash of the rest
      byte[] expected_digest=new byte[32];
      m_hash.doFinal(dec_messeage, (short)16, (short) (dec_messeage.length - 16), expected_digest, (short) 0);
      byte hashcompare = Util.arrayCompare(dec_messeage, (short) 0, expected_digest, (short) 0, (short) 16);
      if (hashcompare !=(byte) 0x00)
          throw new SecurityException("Integrity attack detected");
      // Verify freshness by checking if next byte has the correct counter number
      if (dec_messeage[16] != messeagecounter)
          throw new SecurityException("Replay attack detected");
      byte[] sendingrtries = new byte[1];
      sendingrtries[0] = (byte) pintries;
      System.arraycopy(sendingrtries,(short)0,apdubuf,ISO7816.OFFSET_CDATA,sendingrtries.length);
      messeagecounter++;
      pintries = 3;
      apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)sendingrtries.length);
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

       
        try {
            
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
                
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    
                    case INS_ECC:
                        GenEccKeyPair(apdu,len);
                        break;
                    case INS_DEC:
                        symmetric_enc(apdu);
                        break;
                    case INS_COMMUNICATION:
                        secureCommunication(apdu);
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

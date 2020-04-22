package simpleapdu;

import applets.SimpleApplet;

import cardTools.RunConfig;
import cardTools.Util;
import java.util.Scanner;
import javacard.framework.OwnerPIN;


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
import java.security.SecureRandom;
import static javacard.framework.Util.arrayCompare;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;


/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author TEAM
 */
public class SimpleAPDU {
    private static byte[] APPLET_AID = {(byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C,
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};;
    static CardMngr cardManager = new CardMngr();
    //private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);
    
    private AESKey m_aesKey = null;
    private MessageDigest m_hash = null;

    private static Cipher m_encryptCipherCBC = null;
    private static Cipher m_decryptCipherCBC = null;
    
    private RandomData m_secureRandom = null;
    private int tries_remaining = 3;


    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
       
    
        try {
            SimpleAPDU main = new SimpleAPDU();
            //ask user for pin
             // Prepare simulated card 
            byte[] installData = {(byte) 0x04, (byte)0xD2}; // no special install data passed now - can be used to pass initial keys etc.
            //cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
           
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
            main.Shared_secret_cal();
             byte[] toenc = Util.hexStringToByteArray("076933ff9904d1110d896e2c525e39e501000000000000000000000000000000");
             byte[] tosend = new byte[32];
             m_encryptCipherCBC.doFinal(toenc, (short) 0, (short) toenc.length, tosend, (short) 0);
        
        //transmit the S value; S=wN+Y
     
        byte apdu_withdata[] = new byte[CardMngr.HEADER_LENGTH + tosend.length];
        apdu_withdata[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu_withdata[CardMngr.OFFSET_INS] = (byte) 0x56;// 
        apdu_withdata[CardMngr.OFFSET_P1] = (byte) 0x01;
        apdu_withdata[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu_withdata[CardMngr.OFFSET_LC] = (byte) tosend.length;
        
        if(tosend.length!=0){
        System.arraycopy(tosend, 0, apdu_withdata, CardMngr.OFFSET_DATA, tosend.length);
        }
        
        // Transmit single APDU
        //TRANSMIT T TO CARD
        byte[] responsefromBOB = cardManager.sendAPDUSimulator(apdu_withdata);
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public void Shared_secret_cal() throws Exception {
        
        
        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();
          
        //Take pin fro user in PC/Host
        
            System.out.println("WELCOME USER !!!!\nPLEASE ENTER YOUR PIN");
            Scanner scanner = new Scanner(System.in);
            String inputString = scanner.nextLine();
            
            if(tries_remaining==0){
            System.out.println("\nYOU HAVE ENTERD THE MAX LIMIT OF PIN TRY!!");
            System.exit(0);

            }
        tries_remaining--;
        runCfg.setAppletToSimulate(SimpleApplet.class); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator
        
        //ECDH 
       
        X9ECParameters curve = ECNamedCurveTable.getByName("P-256");
        ECDomainParameters ecparams = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());
        final SecureRandom random = new SecureRandom();
        final ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(ecparams, random));
        AsymmetricCipherKeyPair bobPair = gen.generateKeyPair();
        ECPublicKeyParameters bobpublic = (ECPublicKeyParameters) bobPair.getPublic();
        ECPrivateKeyParameters bobprivate = (ECPrivateKeyParameters) bobPair.getPrivate();
        ECPoint bigX = bobpublic.getQ();
        BigInteger smallx = bobprivate.getD();
        BigInteger PIN = BigInteger.valueOf(Integer.parseInt(inputString));
        ECPoint bigN = ecparams.getCurve().decodePoint(Hex.decode("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"));
        ECPoint bigM = ecparams.getCurve().decodePoint(Hex.decode("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"));
        ECPoint bigT = bigM.multiply(PIN).add(bigX);
       
         byte[] tosend_T = bigT.getEncoded(true);
        
        //transmit the S value; S=wN+Y
     
        byte apdu_withS[] = new byte[CardMngr.HEADER_LENGTH + tosend_T.length];
        apdu_withS[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu_withS[CardMngr.OFFSET_INS] = (byte) 0x54;// 
        apdu_withS[CardMngr.OFFSET_P1] = (byte) 0x01;
        apdu_withS[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu_withS[CardMngr.OFFSET_LC] = (byte) tosend_T.length;
        
        if(tosend_T.length!=0){
        System.arraycopy(tosend_T, 0, apdu_withS, CardMngr.OFFSET_DATA, tosend_T.length);
        }
        
        // Transmit single APDU
        //TRANSMIT T TO CARD
        byte[] responsefromBOB = cardManager.sendAPDUSimulator(apdu_withS);
        
      
        //RECIEVE S FROM CARD
        //CALCULATES SECRET= x(S-wN)
        int len =responsefromBOB.length-2;
        byte[] Sfromcard =new byte[len];

        System.arraycopy(responsefromBOB, (short) 0, Sfromcard,(short)0, (short)len); // copying to APDU

        ECPoint bigS = ecparams.getCurve().decodePoint(Sfromcard);
        ECPoint shared1 = bigS.subtract(bigN.multiply(PIN)).multiply(smallx);
        byte[] secret = shared1.getEncoded(true);
        
        /*
        System.out.println("\nPRINTING THE SHARED SECRET IN PC :");  
        
        for (byte b : secret) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        */
        
        
        
        //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        //SET THE MD5(SHARED KEY) AS THE KEY FOR SYMMETRIC ENCRYPTION- AES
        m_hash = MessageDigest.getInstance(MessageDigest.ALG_MD5, false);
        byte[] digest=new byte[32];

        m_hash.doFinal(secret, (short)0, (short)secret.length, digest, (short) 0);

        m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        m_aesKey.setKey(digest, (short)0);
        //Generate random seed
        m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        byte [] random_number= new byte[16];
        m_secureRandom.generateData(random_number, (short) 0, (short)random_number.length);
        //GET INSTANCE
        m_encryptCipherCBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        m_encryptCipherCBC.init(m_aesKey, Cipher.MODE_ENCRYPT);
        
        //ENCRYPTION
        byte [] enc_random= new byte[16];
       
        m_encryptCipherCBC.doFinal(random_number, (short) 0, (short) random_number.length, enc_random,(short)0);
        
        //TRANSMIT THE CIPHER
       
        byte apdu_cipher[] = new byte[CardMngr.HEADER_LENGTH + enc_random.length];
        apdu_cipher[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu_cipher[CardMngr.OFFSET_INS] = (byte) 0x55;// 
        apdu_cipher[CardMngr.OFFSET_P1] = (byte) 0x01;
        apdu_cipher[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu_cipher[CardMngr.OFFSET_LC] = (byte) enc_random.length;
        
        if(enc_random.length!=0){
        System.arraycopy(enc_random, 0, apdu_cipher, CardMngr.OFFSET_DATA, enc_random.length);
        }
        
        byte[] responseforcipher = cardManager.sendAPDUSimulator(apdu_cipher);
      
        //VERIFYING THE CIPHER- MUTUAL AUTHENTICATION
        
        int l =responseforcipher.length-2;
        byte[] reversecipher =new byte[l];
        
        
        System.arraycopy(responseforcipher, (short) 0, reversecipher,(short)0, (short)l);
      
        //DECRYPTION AT PC
        m_decryptCipherCBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        m_decryptCipherCBC.init(m_aesKey, Cipher.MODE_DECRYPT);
        
        //DECRYPTION
        byte [] dec_reverse= new byte[16];
        m_decryptCipherCBC.doFinal(reversecipher, (short) 0, (short)reversecipher.length, dec_reverse,(short)0);
     
        //REVERSE THE PLAINTEXT
        int i = 0;
        int j = dec_reverse.length - 1;
        byte tmp;
        while (j > i) {
          tmp = dec_reverse[j];
          dec_reverse[j] = dec_reverse[i];
          dec_reverse[i] = tmp;
          j--;
          i++;
        }
        
        if(arrayCompare(dec_reverse, (short)0, random_number, (short)0,(short)dec_reverse.length)==0){
            tries_remaining++;
            System.out.println("\nSUCCESS ! WELCOME USER");
        }
        
        else{
            if(tries_remaining !=0)
            {
                System.out.println("\nINCORRECT PIN! PLEASE TRY AGAIN");
                System.out.println("\nYOU HAVE "+(tries_remaining)+" ATTEMPTS LEFT");
                
                Shared_secret_cal();
            }
            
        }
     

        
    }

   
      
}

package simpleapdu;

import applets.SimpleApplet;

import cardTools.RunConfig;
import java.util.Scanner;
import javacard.framework.OwnerPIN;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

import opencrypto.jcmathlib.Bignat;
import opencrypto.jcmathlib.ECConfig;
import opencrypto.jcmathlib.ECCurve;
import opencrypto.jcmathlib.ECPoint;
import opencrypto.jcmathlib.SecP256r1;


/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda (petrs), Dusan Klinec (ph4r05)
 */
public class SimpleAPDU {
    private static byte[] APPLET_AID = {(byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C,
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};;
    static CardMngr cardManager = new CardMngr();
    //private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);
    
    private OwnerPIN m_pin = null;
    
    private static final String STR_APDU_GETRANDOM = "B054010000";
    
    final static byte[] N_COMPRESSED = {(byte) 0x03, (byte) 0xD8, (byte) 0xBB, (byte) 0xD6, (byte) 0xC6, (byte) 0x39, (byte) 0xC6, (byte) 0x29, (byte) 0x37, (byte) 0xB0, (byte) 0x4D, (byte) 0x99, (byte) 0x7F, (byte) 0x38, (byte) 0xC3, (byte) 0x77, (byte) 0x07, (byte) 0x19, (byte) 0xC6, (byte) 0x29, (byte) 0xD7, (byte) 0x01, (byte) 0x4D, (byte) 0x49, (byte) 0xA2, (byte) 0x4B, (byte) 0x4F, (byte) 0x98, (byte) 0xBA, (byte) 0xA1, (byte) 0x29, (byte) 0x2B, (byte) 0x49};
    final static byte[] M_COMPRESSED = {(byte) 0x02, (byte) 0x88, (byte) 0x6E, (byte) 0x2F, (byte) 0x97, (byte) 0xAC, (byte) 0xE4, (byte) 0x6E, (byte) 0x55, (byte) 0xBA, (byte) 0x9D, (byte) 0xD7, (byte) 0x24, (byte) 0x25, (byte) 0x79, (byte) 0xF2, (byte) 0x99, (byte) 0x3B, (byte) 0x64, (byte) 0xE1, (byte) 0x6E, (byte) 0xF3, (byte) 0xDC, (byte) 0xAB, (byte) 0x95, (byte) 0xAF, (byte) 0xD4, (byte) 0x97, (byte) 0x33, (byte) 0x3D, (byte) 0x8F, (byte) 0xA1, (byte) 0x2F};
    private byte dataArray1[] = null;
    private byte dataArray2[] = null;
    ECConfig        ecc = null;
    ECCurve         curve = null;
    ECPoint         bigX = null;
    ECPoint         bigY = null;
    ECPoint         bigT = null;
    ECPoint         bigS = null;
    ECPoint         bobShared = null;
    KeyPair         kp = null;
    ECPrivateKey    privkey = null;
    ECPublicKey     pubkey = null;
    Bignat          smally = null;
    Bignat          userpin = null;
    

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
            byte[] installData = new byte[10]; // no special install data passed now - can be used to pass initial keys etc.
            //cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
           
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
            main.Shared_secret_cal();
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public void Shared_secret_cal() throws Exception {
        
        
        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();
          
        //Take pin fro user in PC/Host
        
            System.out.println("Welcome User \nPlease enter the PIN");
            Scanner scanner = new Scanner(System.in);
            String inputString = scanner.nextLine();
            byte[]user_pin= inputString.getBytes();
            m_pin = new OwnerPIN((byte) 5, (byte) 4); // 5 tries, 4 digits in pin
            m_pin.update(user_pin, (byte) 0, (byte) 4);
            //System.out.println("\nTHE PIN ENTERED BY USER AND STORED IN HOST/PC/ALICE IS");
       
            
            
        
       
        // A) If running on physical card
        // runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

        // B) If running in the simulator 
        runCfg.setAppletToSimulate(SimpleApplet.class); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        
        //GENERATE EC PARAMS
        
        dataArray1 = new byte[100];
        javacard.framework.Util.arrayFillNonAtomic(dataArray1, (short) 0, (short) 100, (byte) 0);
         dataArray2 = new byte[100];
        javacard.framework.Util.arrayFillNonAtomic(dataArray2, (short) 0, (short) 100, (byte) 0);
        // Pre-allocate all helper structures
        ecc = new ECConfig((short) 256); 
        // Pre-allocate standard SecP256r1 curve and two EC points on this curve
        curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        bigX = new ECPoint(curve, ecc.ech);
        bigY = new ECPoint(curve, ecc.ech);
        bigT = new ECPoint(curve, ecc.ech);
        bigS = new ECPoint(curve, ecc.ech);
        bobShared = new ECPoint(curve, ecc.ech);
        kp = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
        kp.genKeyPair();
        privkey = (ECPrivateKey) kp.getPrivate();
        pubkey = (ECPublicKey) kp.getPublic();
        
        
        short smallylen = privkey.getS(dataArray1, (short) 0);
       
        byte[] smallydata = new byte[smallylen];
        privkey.getS(smallydata, (short) 0);
        smally = new Bignat(smallydata, ecc.bnh);
        userpin = new Bignat(user_pin,ecc.bnh);
       
         //TODO
        // ALICE TO BOB- S= yG + wN; 
         //CALCULATES SECRET= y(T-wM)

        //transmit the S value; S=wN+Y
        bigS.setW(N_COMPRESSED, (short) 0, (short) N_COMPRESSED.length); //S = N
        short slen = bigS.multiplication_x(userpin, dataArray1, (short)0);//userpin is Bignat Scalar, wN stored in "memory".
        bigS.setW(dataArray1, (short) 0, slen); // S = wN
        short bigYlen = pubkey.getW(dataArray1, (short) 0); // getting Y length and saving it to "memory" as raw bytes
        bigY.setW(dataArray1, (short) 0, bigYlen); // making Y point
        
  
        bigS.add(bigY); //S = wN + Y
        slen = bigS.getW(dataArray1,(short) 0); //m
        System.out.println("\nslen is "+slen);
        
     
        byte apdu_withS[] = new byte[CardMngr.HEADER_LENGTH + slen];
        apdu_withS[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu_withS[CardMngr.OFFSET_INS] = (byte) 0x54;// 
        apdu_withS[CardMngr.OFFSET_P1] = (byte) 0x01;
        apdu_withS[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu_withS[CardMngr.OFFSET_LC] = (byte) slen;
        
        if(slen!=0){
        System.arraycopy(dataArray1, 0, apdu_withS, CardMngr.OFFSET_DATA, slen);
        }
        
        // Transmit single APDU
        
        byte test[] =new byte[slen];
        System.arraycopy(apdu_withS, CardMngr.OFFSET_DATA, test,(short)0, slen);

        
        System.out.println("\nPRINTING THE S TO SENT:");  
        
        for (byte b : test) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        System.out.println("\n");

        
        byte[] responsefromBOB = cardManager.sendAPDUSimulator(apdu_withS);
        int len =responsefromBOB.length-2;
        byte[] Tfromcard =new byte[(responsefromBOB.length-2)];
        javacard.framework.Util.arrayCopyNonAtomic(responsefromBOB, (short) 0, Tfromcard,(short)0, (short)len); // copying to APDU

        
        System.out.println("\nPRINTING THE T CAME FROM CARD:");  
        
        for (byte b : Tfromcard) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        

        bigT.setW(Tfromcard,(short)0, (short)Tfromcard.length); //T = T
        bobShared.setW(M_COMPRESSED, (short) 0, (short) M_COMPRESSED.length); //Shared = M
        short bobSharedLen = bobShared.multiplication_x(userpin, dataArray2, (short) 0); // wM stored into memory
        bobShared.setW(dataArray2, (short) 0, bobSharedLen); // Shared = wM
        bobShared.negate(); // Shared = -wM
        bobShared.add(bigT); // Shared = T - wN
        bobSharedLen = bobShared.multiplication_x(smally, dataArray2, (short) 0); // Putting y*(T-wM) into memory
        bobShared.setW(dataArray2, (short) 0, bobSharedLen); // Shared = y*(T-wM) = x*y*G
        
        
        System.out.println("\nPRINTING THE SHARED SECRET IN PC :");  
        
        for (byte b : dataArray2) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        
        
    }

   
      
}

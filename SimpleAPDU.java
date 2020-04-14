package simpleapdu;

import applets.SimpleApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;
import javacard.framework.ISO7816;
import javacard.framework.OwnerPIN;
import javacard.framework.PIN;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

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
    private byte[] arrayforB = new byte[24];
    private byte[] arrayforG = new byte[49];
    private byte[] arrayforA = new byte[24];
    private byte[] pin= new byte[4];
    private byte[] PIN = new byte[4];
    private KeyPair eccKey;
    private OwnerPIN m_pin = null;
    private byte y[] =new byte[16];
    private RandomData m_secureRandom = null;
    ECKey keyforus;
    ECPublicKey pubkeyC;
    ECPrivateKey privKeyC;
    private static final String STR_APDU_GETRANDOM = "B054010000";

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
            long startTime = 0;
            //long elapsedTime = 0;
            long endTime = 0;
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleApplet.class);
            
            
            main.demoGetRandomDataCommand();
            main.demoEncryptDecrypt();
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public void demoGetRandomDataCommand() throws Exception {
        // CardManager abstracts from real or simulated card, provide with applet AID
        //final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);          
        
        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();
          
        //Take pin fro user in PC/Host
        
            System.out.println("Welcome User \nPlease enter the PIN");
            Scanner scanner = new Scanner(System.in);
            String inputString = scanner.nextLine();
            byte[]userpin= inputString.getBytes();
            m_pin = new OwnerPIN((byte) 5, (byte) 4); // 5 tries, 4 digits in pin
            m_pin.update(userpin, (byte) 0, (byte) 4);
            //System.out.println("\nTHE PIN ENTERED BY USER AND STORED IN HOST/PC/ALICE IS");
       
        
       
        // A) If running on physical card
        // runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

        // B) If running in the simulator 
        runCfg.setAppletToSimulate(SimpleApplet.class); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        
        eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
        eccKey.genKeyPair();

        pubkeyC=(ECPublicKey)(ECKey)eccKey.getPublic();
        privKeyC= (ECPrivateKey)eccKey.getPrivate();
        privKeyC.getB(arrayforB,(short) 0);
        privKeyC.getG(arrayforG,(short)0);
        privKeyC.getA(arrayforA, (short)0);
        
       

        //TODO
        // ALICE TO BOB- S= yG + wN;
        
        //CALCULATES SECRET= y(T-wM)
        
        //Generating random number 'y'
        
        //i just used a large prime ..it can be increased later
         int prime=1500450271;
         //byte[] prime= {(byte) 0x31, (byte) 0x35, (byte) 0x30, (byte) 0x30,(byte) 0x34, (byte) 0x35,(byte) 0x30, (byte) 0x32,(byte) 0x37,
         //(byte) 0x31};
         SecureRandom secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG");
     
        // Get 10 random bytes
        byte[] randomBytes = new byte[10];
        int i=0;
        secureRandomGenerator.nextBytes(randomBytes);
        
        //This code calcuates a random number less than the prime selected
        ByteBuffer wrapped = ByteBuffer.wrap(randomBytes); // big-endian by default
        int y = wrapped.getInt();
        while(i<1){
        if(y<prime){
        i=1;    
        }
        else{
        secureRandomGenerator.nextBytes(randomBytes);
        ByteBuffer wrappd = ByteBuffer.wrap(randomBytes); // big-endian by default
        y = wrappd.getShort();
        }
        }
         
        //System.out.println("\nTHE RANDOM NUMBER GEN IN HOST/ALICE/PC y is" +y);
       
      
        //System.out.println("checkk1");  

       
     
        ByteBuffer wrappedG = ByteBuffer.wrap(arrayforG); // big-endian by default
        int G = wrappedG.getInt();
        
        
        //System.out.println("\nTHE VALUE OF G IN HOST/PC/ALICE " +G);

       //multiplication y * G 
       
       int yG= y*G;
       
       //System.out.println("\nTHE MULTIPICATION yG INTEGER CALCULATED IN HOST/PC/ALICE IS" +yG);
       

        
        // yG + wN = next step
        //wN calc, N used is in arrayforB and w is the pin
        
        ByteBuffer wrappedN = ByteBuffer.wrap(arrayforB); // big-endian by default
        int N = wrappedN.getInt();
        
        ByteBuffer wrappeduserpin = ByteBuffer.wrap(userpin); // big-endian by default
        int code = wrappeduserpin.getInt();
        
      
       int wN=N*code;
        //System.out.println("\nCALCULATED wN IN HOST/ALCIE/PC  :" +wN);  
        
  
        //final step S =yG +wN
        int Sint = yG + wN;
        
        //S IS READY TO BE SENT
       // System.out.println("\nS IS READY - SENDING FROM ALICE TO BOB -- "+Sint);  
        
        
        byte S[]= ByteBuffer.allocate(4).putInt(Sint).array();
        
        //System.out.println("\nTHE LENGTH OF S IN HOST/ALICE "+S.length);
        
        
       // System.out.println("\nCALCULATED S   :");  
        
      

        

        
     
        
  
        // Connect to first available card
        // NOTE: selects target applet based on AID specified in CardManager constructor
        System.out.print("Connecting to card...");
        /*
        if (!cardManager.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        */
        System.out.println(" Done.");

        
        
        
        short SLength = 4;
        byte apdu_withS[] = new byte[CardMngr.HEADER_LENGTH + SLength];
        apdu_withS[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu_withS[CardMngr.OFFSET_INS] = (byte) 0x54;// 
        apdu_withS[CardMngr.OFFSET_P1] = (byte) 0x01;
        apdu_withS[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu_withS[CardMngr.OFFSET_LC] = (byte) SLength;
        
        if(SLength!=0){
        System.arraycopy(S, 0, apdu_withS, CardMngr.OFFSET_DATA, SLength);
        }
        
        // Transmit single APDU
        byte[] responsefromBOB = cardManager.sendAPDUSimulator(apdu_withS);
           
        //final ResponseAPDU response2 = cardMngr.transmit(new CommandAPDU(0xB0, 0x54, 0x00, 0x00, data)); // Use other constructor for CommandAPDU
        
        
        //Getting T from Bob
        byte[] TfromBob=new byte[4];
        System.arraycopy(responsefromBOB,(short)0,TfromBob ,(short)0, (short)4);
        //byte[] TfromBob = Arrays.copyOfRange(responsefromBOB, 0,SLength);
        
       // System.out.println("\nPRINTING THE T TAHT CAME FROM BOB THROUGH RESPONSEAPDU :");  
        
        for (byte b : TfromBob) {
            String st = String.format("%02X", b);
            System.out.print(st);
        }
        //GETTING T FROM BOB
        ByteBuffer wrappedT = ByteBuffer.wrap(TfromBob); // big-endian by default
        int T = wrappedT.getInt();
        //System.out.println("\nPRINTING THE T TAHT CAME FROM BOB THROUGH RESPONSEAPDU :" +T);  
        
        
        
        
        
        
        
        //HOST/ALICE CALCULATION  THE SHARED SECRET
        //calculate y(T-wM)
        //step1 - calculate wM
        ByteBuffer wrappedM = ByteBuffer.wrap(arrayforA); // big-endian by default
        int M = wrappedM.getInt();
        
        int wM= code*M;
        
      
        //nextstep= T-wM
        
        //System.out.println("\nCALCULATED wM IN HOST/ALICE IS   :" +wM);  
        
        int TsubwM = T -wM;
        
       // System.out.println("\nCALCULATED T - wM IN HOST/ALICE IS   :" +TsubwM);  
        
     
        //last step of shared secret = y(T-wM)
        
        int sharedsec= y*TsubwM;
                
        System.out.println("\nPRINTING THE SHARED SECRET IN  HOST/ALICE/PC is " +sharedsec);  
        
     
        
        
    }

    public void demoEncryptDecrypt() throws Exception {
        //final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card
        runCfg.setAppletToSimulate(SimpleApplet.class); 
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        // Connect to first available card
        System.out.print("\nConnecting to card...");
        /*
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        */
        System.out.println(" Done.");

        
        // Task 1
        // TODO: Prepare and send APDU with 32 bytes of data for encryption, observe output

        // Task 2
        // TODO: Extract the encrypted data from the card's response. Send APDU with this data for decryption
        // TODO: Compare match between data for encryption and decrypted data
        
        // Task 3
        // TODO: What is the value of AES key used inside applet? Use debugger to figure this out

        // Task 4
        // TODO: Prepare and send APDU for setting different AES key, then encrypt and verify (with http://extranet.cryptomathic.com/aescalc/index
    }    
    
      
}
